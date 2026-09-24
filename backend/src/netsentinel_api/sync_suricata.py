"""Import Suricata's eve.json alerts into the ``alerts`` table.

    python -m netsentinel_api.sync_suricata --eve eve.json [--eve other/eve.json]

Safe to re-run on the same file: rows already imported are not added again. The
decisions live in ``services.signatures``; this is the file handling, as in the
Greenbone import.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select

from netsentinel_api.db.models import Alert, AuditLog
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.signatures import SOURCE, EveError, parse_eve, sync


def run(session, path: Path) -> dict[str, int]:
    with path.open(encoding="utf-8") as lines:
        found = parse_eve(lines)
    added = sync(session, found, session.scalars(select(Alert).where(Alert.source == SOURCE)))
    stats = {"alerts": len(found), "added": added}
    session.add(
        AuditLog(
            user_id=None,  # an operator ran the import; nobody is logged in
            action="alerts.imported",
            entity=f"suricata:{path.name}",
            details=stats,
        )
    )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import Suricata eve.json alerts into alerts")
    parser.add_argument("--eve", required=True, type=Path, action="append",
                        help="an eve.json written by Suricata; repeat for several")
    args = parser.parse_args(argv)

    with get_sessionmaker()() as session:
        for path in args.eve:
            try:
                stats = run(session, path)
            except (OSError, EveError) as exc:
                print(f"import failed on {path}: {exc}", file=sys.stderr)
                return 2
            # Flushed so the next file's comparison sees this file's rows; sessions
            # are created with autoflush off.
            session.flush()
            print(f"Suricata import {path}: {stats}")
        session.commit()
    return 0


if __name__ == "__main__":
    sys.exit(main())
