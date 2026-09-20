"""Import a Greenbone report into the ``vulnerabilities`` table.

    python -m netsentinel_api.sync_vulns --report report.xml

Produce the report with Greenbone's own client, which speaks GMP over the gvmd
socket - there is no HTTP API to call instead:

    gvm-cli socket --socketpath /run/gvmd/gvmd.sock --xml \\
      '<get_reports report_id="REPORT-UUID" details="1"
        filter="apply_overrides=0 min_qod=70 rows=-1"/>' > report.xml

The decisions live in ``services.vulns`` and the file handling lives here, the same
split as the MISP sync: the parser and the upsert are testable against fixture XML,
and this module stays the thin part that needs a scanner to exercise properly.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from sqlalchemy import select

from netsentinel_api.db.models import Asset, AuditLog, Vulnerability
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.vulns import MIN_QOD, ScanError, ScanStats, parse_report, sync

logger = logging.getLogger("netsentinel.vulns")


def run(session, xml: str, min_qod: int = MIN_QOD) -> ScanStats:
    findings = parse_report(xml, min_qod=min_qod)
    stats = sync(
        session,
        findings,
        list(session.scalars(select(Asset))),
        list(session.scalars(select(Vulnerability))),
    )
    session.add(
        AuditLog(
            user_id=None,  # an operator ran a scan; nobody is logged in
            action="vulns.imported",
            entity=f"greenbone:min_qod={min_qod}",
            details=stats.as_dict(),
        )
    )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import a Greenbone get_reports XML into vulnerabilities"
    )
    parser.add_argument("--report", required=True, type=Path,
                        help="the report XML produced by gvm-cli")
    parser.add_argument(
        "--min-qod",
        type=int,
        default=MIN_QOD,
        help=f"drop findings below this quality of detection (default: {MIN_QOD})",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    try:
        xml = args.report.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"cannot read {args.report}: {exc}", file=sys.stderr)
        return 2

    with get_sessionmaker()() as session:
        try:
            stats = run(session, xml, min_qod=args.min_qod)
        except ScanError as exc:
            print(f"import failed: {exc}", file=sys.stderr)
            return 2
        session.commit()
        print(f"Greenbone import: {stats.as_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
