"""Pull MISP attributes into the IoC table.

    python -m netsentinel_api.sync_intel --since 7d

Runs on a schedule rather than per alert. Asking MISP about an address while an
analyst waits puts a third party on the critical path of triage; a table this system
owns does not.

The HTTP lives here and the decisions live in ``services.intel``, so the mapping and
the upsert rules are testable without a MISP instance and this module stays the thin
part that can only be tested against one.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any

from sqlalchemy import select

from netsentinel_api.config import Settings, get_settings
from netsentinel_api.db.models import AuditLog, IoC
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.intel import (
    MISP_TYPE_MAP,
    IntelError,
    SyncStats,
    parse_attributes,
    sync,
)

logger = logging.getLogger("netsentinel.intel")

#: Attributes per request. MISP paginates, and a feed worth having is larger than one
#: response should be.
PAGE_SIZE = 1000

#: A runaway feed must not fill the table. Ten pages is an order of magnitude more
#: indicators than a lab deployment has any use for.
MAX_PAGES = 10

REQUEST_TIMEOUT_SECONDS = 30.0


def fetch_attributes(settings: Settings, since: str, page_size: int = PAGE_SIZE) -> list[dict]:
    """Every actionable attribute MISP has published since ``since``.

    ``to_ids`` and ``enforceWarninglist`` are not optional. The first restricts the
    answer to indicators MISP considers actionable, the second drops the ones its
    warninglists mark as known-good - without them a public feed returns addresses
    like 8.8.8.8 and every DNS lookup in the lab becomes an intelligence-backed alert.
    """
    import httpx

    if not settings.misp_url or not settings.misp_api_key:
        raise IntelError(
            "MISP is not configured; set NETSENTINEL_MISP_URL and "
            "NETSENTINEL_MISP_API_KEY"
        )

    url = settings.misp_url.rstrip("/") + "/attributes/restSearch"
    headers = {
        "Authorization": settings.misp_api_key.get_secret_value(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    attributes: list[dict] = []
    with httpx.Client(
        timeout=REQUEST_TIMEOUT_SECONDS, verify=settings.misp_verify_tls
    ) as client:
        for page in range(1, MAX_PAGES + 1):
            body: dict[str, Any] = {
                "returnFormat": "json",
                "type": sorted(MISP_TYPE_MAP),
                "to_ids": True,
                "enforceWarninglist": True,
                "last": since,
                "limit": page_size,
                "page": page,
            }
            try:
                response = client.post(url, headers=headers, json=body)
                response.raise_for_status()
                payload = response.json()
            except httpx.HTTPError as exc:
                raise IntelError(f"MISP request failed: {exc}") from exc
            except ValueError as exc:
                raise IntelError(f"MISP returned a body that is not JSON: {exc}") from exc

            batch = (payload.get("response") or {}).get("Attribute") or []
            attributes.extend(batch)
            if len(batch) < page_size:
                return attributes

    logger.warning(
        "stopped at %s pages; the feed has more indicators than this sync will take",
        MAX_PAGES,
    )
    return attributes


def run(session, settings: Settings, since: str) -> SyncStats:
    indicators = parse_attributes(
        {"response": {"Attribute": fetch_attributes(settings, since)}}
    )
    existing = list(session.scalars(select(IoC)))
    stats = sync(session, indicators, existing)
    session.add(
        AuditLog(
            user_id=None,  # a scheduled action; nobody is logged in
            action="intel.synced",
            entity=f"misp:{since}",
            details=stats.as_dict(),
        )
    )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sync MISP attributes into iocs")
    parser.add_argument(
        "--since",
        default="7d",
        help="MISP 'last' window, e.g. 7d or 12h (default: 7d)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    settings = get_settings()
    with get_sessionmaker()() as session:
        try:
            stats = run(session, settings, args.since)
        except IntelError as exc:
            print(f"sync failed: {exc}", file=sys.stderr)
            return 2
        session.commit()
        print(f"MISP sync: {stats.as_dict()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
