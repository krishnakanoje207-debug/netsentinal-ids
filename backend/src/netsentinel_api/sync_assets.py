"""Import the asset inventory CSV into the ``assets`` table.

    netsentinel-import-assets --csv inventory.csv

Columns: hostname, ip_address, os, criticality (low, medium or high; medium if blank).
The decisions live in ``services.inventory``; this module only reads the file and
records the import in the audit log.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select

from netsentinel_api.db.models import Asset, AuditLog
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.inventory import (
    InventoryError,
    InventoryStats,
    parse_inventory,
    sync_inventory,
)


def run(session, text: str, source: str) -> InventoryStats:
    stats = sync_inventory(session, parse_inventory(text), list(session.scalars(select(Asset))))
    session.add(
        AuditLog(
            user_id=None,  # an operator ran the import; nobody is logged in
            action="assets.imported",
            entity=f"inventory:{source}",
            details=stats.as_dict(),
        )
    )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import the asset inventory CSV")
    parser.add_argument("--csv", required=True, type=Path, help="hostname,ip_address,os,criticality")
    args = parser.parse_args(argv)

    try:
        text = args.csv.read_text(encoding="utf-8-sig")
    except OSError as exc:
        print(f"cannot read {args.csv}: {exc}", file=sys.stderr)
        return 2

    with get_sessionmaker()() as session:
        try:
            stats = run(session, text, args.csv.name)
        except InventoryError as exc:
            print(f"import refused: {exc}", file=sys.stderr)
            return 2
        session.commit()
    print(f"Inventory import: {stats.as_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
