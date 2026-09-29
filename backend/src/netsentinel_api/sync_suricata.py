"""Import Suricata's eve.json alerts into the ``alerts`` table.

    python -m netsentinel_api.sync_suricata --eve eve.json [--eve other/eve.json]

Safe to re-run on the same file: rows already imported are not added again. The
decisions live in ``services.signatures``; this is the file handling, as in the
Greenbone import.

After the import, recent model alerts are compared with the signature alerts around
them (``services.signatures.corroborate``). It runs here, after each pass, rather than
in the writer, because either can arrive first: a rule can match mid-flow, minutes
before the flow ends and its model alert is written.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select

from netsentinel_api.db.models import Alert, AuditLog
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.signatures import (
    CORROBORATION_WINDOW,
    SOURCE,
    corroborate,
    parse_eve,
    raise_corroborated,
    sync,
)

#: How far back each pass looks for model alerts not yet compared. The import runs
#: every five minutes by default; an hour covers a few missed passes.
LOOKBACK = timedelta(hours=1)


def run(session, path: Path) -> dict[str, int]:
    malformed: list[int] = []
    with path.open(encoding="utf-8") as lines:
        found = parse_eve(lines, malformed)
    if malformed:
        print(f"skipped malformed lines in {path}: {malformed}", file=sys.stderr)
    added = sync(session, found, session.scalars(select(Alert).where(Alert.source == SOURCE)))
    skipped = sum(match.context for match in found)
    stats = {"alerts": len(found), "skipped": skipped, "added": added,
             "malformed": len(malformed)}
    session.add(
        AuditLog(
            user_id=None,  # an operator ran the import; nobody is logged in
            action="alerts.imported",
            entity=f"suricata:{path.name}",
            details=stats,
        )
    )
    return stats


def corroborate_recent(session, now: datetime | None = None) -> int:
    """Raise the recent model alerts a signature agrees with; return how many."""
    since = (now or datetime.now(timezone.utc)) - LOOKBACK
    alerts = list(
        session.scalars(
            select(Alert).where(
                Alert.source != SOURCE,
                Alert.detection_id.is_not(None),
                Alert.corroborated_by_alert_id.is_(None),
                Alert.created_at >= since,
            )
        )
    )
    if not alerts:
        return 0
    signatures = session.scalars(
        select(Alert).where(
            Alert.source == SOURCE,
            Alert.created_at >= since - CORROBORATION_WINDOW,
        )
    )
    return raise_corroborated(session, corroborate(alerts, signatures))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import Suricata eve.json alerts into alerts")
    parser.add_argument("--eve", required=True, type=Path, action="append",
                        help="an eve.json written by Suricata; repeat for several")
    args = parser.parse_args(argv)

    with get_sessionmaker()() as session:
        for path in args.eve:
            try:
                stats = run(session, path)
            except OSError as exc:
                print(f"import failed on {path}: {exc}", file=sys.stderr)
                return 2
            # Flushed so the next file's comparison sees this file's rows; sessions
            # are created with autoflush off.
            session.flush()
            print(f"Suricata import {path}: {stats}")
        print(f"model alerts corroborated by a signature: {corroborate_recent(session)}")
        session.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
