"""Summarise one alert with the local model.

    python -m netsentinel_copilot --alert 100
    python -m netsentinel_copilot --latest 10     # the newest ten without a summary

Runs on the laptop, against the database over the SSH tunnel. It is a separate
process and a separate workspace member for the same reason the writer is: the API
must not be able to import an LLM client, and nothing that serves requests should be
able to start a two-minute generation.

The connection details are flags with environment defaults rather than entries in
``netsentinel_api.config``. Ollama is a laptop concern, and the API's settings object
is loaded by every process in the system - including the ones on the VM, which have
no model and never will.
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
    DEFAULT_URL,
    CopilotError,
    OllamaClient,
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
        "--url",
        default=os.environ.get("NETSENTINEL_OLLAMA_URL", DEFAULT_URL),
        help=f"Ollama base URL (default: {DEFAULT_URL})",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("NETSENTINEL_COPILOT_MODEL", DEFAULT_MODEL),
        help=f"model tag (default: {DEFAULT_MODEL})",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    client = OllamaClient(args.url, args.model)
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


def _summarise_one(session, client: OllamaClient, alert, show: bool) -> int:
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
