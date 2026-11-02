"""Import local Wazuh JSON alerts; Docker access stays in this operator worker."""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from netsentinel_api.db.models import Asset, AuditLog
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.host_alerts import import_alert, parse_alert


def ingest(session, lines, *, agent_id=None, asset_id=None, commit_each=False) -> dict:
    stats = {"added": 0, "duplicates": 0, "skipped": 0, "malformed": 0}
    for line in lines:
        if not line.strip():
            continue
        try:
            event = parse_alert(line)
        except (ValueError, KeyError, TypeError):
            stats["malformed"] += 1
            continue
        if event is None or (agent_id is not None and event.details["agent_id"] != agent_id):
            stats["skipped"] += 1
            continue
        alert_id = import_alert(session, event, asset_id=asset_id)
        stats["added" if alert_id is not None else "duplicates"] += 1
        if alert_id is not None:
            session.add(AuditLog(user_id=None, action="alert.imported", entity=f"alert:{alert_id}",
                                 details={"source": "wazuh", "source_event_id": event.event_id}))
        if commit_each:
            session.commit()
    return stats


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--alerts", type=Path)
    source.add_argument("--container")
    parser.add_argument("--docker", default="docker")
    parser.add_argument("--follow", action="store_true")
    parser.add_argument("--agent-id")
    parser.add_argument("--asset-id", type=int)
    args = parser.parse_args(argv)
    if args.asset_id is not None and args.agent_id is None:
        parser.error("--asset-id requires --agent-id to avoid assigning other hosts to this asset")
    if args.follow and not args.container:
        parser.error("--follow requires --container")
    while True:
        process = None
        try:
            with get_sessionmaker()() as session:
                if args.asset_id is not None and session.get(Asset, args.asset_id) is None:
                    parser.error("mapped asset does not exist")
                session.commit()
                if args.container:
                    command = [args.docker, "--context", "desktop-linux", "exec", args.container, "tail", "-n", "1000"]
                    if args.follow:
                        command.append("-F")
                    command.append("/var/ossec/logs/alerts/alerts.json")
                    process = subprocess.Popen(command, stdout=subprocess.PIPE, text=True, encoding="utf-8")
                    lines = process.stdout
                else:
                    lines = args.alerts.open(encoding="utf-8-sig")
                try:
                    stats = ingest(session, lines, agent_id=args.agent_id, asset_id=args.asset_id,
                                   commit_each=args.follow)
                    session.commit()
                finally:
                    lines.close()
                print(f"Wazuh import: {stats}", flush=True)
                if process is not None and process.wait() != 0 and not args.follow:
                    return 2
        except KeyboardInterrupt:
            return 0
        except Exception as exc:
            print(f"Wazuh import unavailable ({type(exc).__name__})", file=sys.stderr, flush=True)
            if not args.follow:
                return 2
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait()
        if not args.follow:
            return 0
        time.sleep(15)


if __name__ == "__main__":
    raise SystemExit(main())
