"""Send allowlisted local alert metadata to one configured HTTPS cloud API."""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from netsentinel_api.db.models import Alert, Detection
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.telemetry import TelemetryBatch, export_alert


def sync_once(session, client, state: dict, save) -> int:
    rows = list(session.scalars(select(Alert).options(joinedload(Alert.detection).load_only(Detection.model_id))
                               .where(Alert.alert_id > state["cursor"])
                               .order_by(Alert.alert_id).limit(100)))
    if not rows:
        return 0
    events = [event for row in rows if (event := export_alert(row)) is not None]
    if events:
        batch = TelemetryBatch(host_id=state["host_id"], alerts=events)
        response = client.post("/api/v1/telemetry/alerts", json=batch.model_dump(mode="json"))
        response.raise_for_status()
        if response.json().get("accepted") != len(events):
            raise ValueError("cloud did not acknowledge the entire batch")
    state["cursor"] = rows[-1].alert_id
    save(state)
    return len(rows)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--follow", action="store_true")
    args = parser.parse_args(argv)
    origin = urlsplit(args.origin)
    if (origin.scheme != "https" or not origin.hostname or origin.username or origin.password
            or origin.path not in {"", "/"} or origin.query or origin.fragment):
        parser.error("--origin must be an HTTPS origin without credentials or a path")
    token = os.environ.get("NETSENTINEL_TELEMETRY_TOKEN", "")
    if len(token) < 32:
        parser.error("NETSENTINEL_TELEMETRY_TOKEN must contain at least 32 characters")
    args.state.parent.mkdir(parents=True, exist_ok=True)

    def save(value):
        temporary = args.state.with_suffix(".tmp")
        temporary.write_text(json.dumps(value), encoding="utf-8")
        temporary.replace(args.state)

    if args.state.exists():
        state = json.loads(args.state.read_text(encoding="utf-8"))
    else:
        state = {"host_id": "host_" + secrets.token_hex(12), "cursor": 0}
        save(state)
    # Never follow redirects with the write credential; default TLS validation stays on.
    with httpx.Client(base_url=args.origin.rstrip("/"), timeout=60,
                      headers={"Authorization": f"Bearer {token}"}, follow_redirects=False) as client:
        while True:
            try:
                with get_sessionmaker()() as session:
                    count = sync_once(session, client, state, save)
                if count:
                    print(f"Telemetry: acknowledged {count} local rows", flush=True)
                    continue
                if not args.follow:
                    return 0
            except KeyboardInterrupt:
                return 0
            except Exception as exc:
                # HTTP exceptions can contain payloads and credentials; log only the class.
                print(f"Telemetry unavailable ({type(exc).__name__}); cursor retained", file=sys.stderr, flush=True)
                if not args.follow:
                    return 2
            time.sleep(15)


if __name__ == "__main__":
    raise SystemExit(main())
