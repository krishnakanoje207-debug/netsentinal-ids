"""Run the opt-in Gemini summary worker against the configured local database.

Detection continues independently when summaries are disabled or unavailable.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from netsentinel_api.db.repositories import AlertRepository
from netsentinel_api.db.session import get_sessionmaker

from netsentinel_copilot.client import (
    DEFAULT_MODEL,
    CopilotError,
    GeminiClient,
)
from netsentinel_copilot.summarise import as_row, summarise

logger = logging.getLogger("netsentinel.copilot")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise an alert for an analyst")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--alert", type=int, help="the alert id")
    target.add_argument(
        "--latest",
        type=int,
        metavar="N",
        help="summarise the N newest alerts that have no valid summary yet",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("NETSENTINEL_COPILOT_MODEL", DEFAULT_MODEL),
        help=f"Gemini model (default: {DEFAULT_MODEL})",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    try:
        client = GeminiClient(
            os.environ.get("GEMINI_API_KEY", ""), args.model,
            allow_cloud=os.environ.get("NETSENTINEL_COPILOT_ALLOW_CLOUD", "").lower() == "true",
        )
    except CopilotError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    with get_sessionmaker()() as session:
        repository = AlertRepository(session)
        if args.alert is not None:
            alert = repository.get(args.alert)
            if alert is None:
                print(f"alert {args.alert} not found", file=sys.stderr)
                return 2
            return _summarise_one(session, client, alert, show=True)

        # Newest first, skipping any alert that already has a summary worth showing.
        pending = [
            alert
            for alert in repository.list(limit=max(args.latest * 4, args.latest))
            if repository.latest_summary(alert) is None
        ][: args.latest]
        results = [
            _summarise_one(session, client, repository.get(alert.alert_id), show=False)
            for alert in pending
        ]
        print(f"{results.count(0)} of {len(pending)} alerts summarised")
        return 0 if all(code == 0 for code in results) else 1


def _summarise_one(session, client: GeminiClient, alert, show: bool) -> int:
    try:
        payload, summary = summarise(client, alert, alert.iocs)
    except CopilotError as exc:
        # Nothing to store: the model said nothing, rather than saying something
        # wrong. The alert is unaffected either way.
        print(f"alert {alert.alert_id}: summary failed: {exc}", file=sys.stderr)
        return 2

    session.add(as_row(alert, payload, summary, client.model))
    session.commit()

    if summary is None:
        # Recorded, not shown. The row is evidence about the model; it is not an
        # explanation of the alert, and printing it as one is the failure this whole
        # package is arranged to avoid.
        print(f"alert {alert.alert_id}: the model's reply was not a valid summary; "
              "stored for review", file=sys.stderr)
        return 1

    if show:
        print(json.dumps(summary.as_row, indent=2))
    else:
        print(f"alert {alert.alert_id}: {summary.headline}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
