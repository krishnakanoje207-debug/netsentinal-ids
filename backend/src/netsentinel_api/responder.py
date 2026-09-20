"""The responder: carries out actions a human approved.

    python -m netsentinel_api.responder --interval 10

Approving does not execute. The API moves an action to ``approved`` and stops there,
and this worker is what turns that into a ban at the edge or a command on a host. The
split is deliberate: a route handler that called CrowdSec would hold a database
transaction open across a network round trip, and an analyst clicking approve would
wait for it.

Two rules shape the loop.

**The gate is passed before the network is touched.** ``mark_executed`` is called
first, in memory and uncommitted. It refuses an action that no one approved, so an
unapproved action never reaches an enforcement point. Only once it has consented does
the request go out; only once the request is accepted is the transaction committed.
If the enforcement point refuses, the transaction is rolled back and the action is
recorded as ``failed`` instead - the execution row and the fact of execution stay in
agreement.

**A crash retries rather than forgets.** A process that dies between the accepted
request and the commit leaves the action ``approved``, and the next pass applies it
again. Banning an address twice is the same address banned; recording a ban that was
never applied, or never retrying one that was, is not recoverable from the database.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field

from netsentinel_api.config import get_settings
from netsentinel_api.db.models import ActionType, ResponseAction
from netsentinel_api.db.repositories import ActionRepository
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.enforcement import EnforcementError, enforcers_from
from netsentinel_api.services.response import mark_executed, mark_failed

logger = logging.getLogger("netsentinel.responder")

#: Actions per pass. The queue is human-sized - every entry was approved by somebody
#: - so this is a guard against a runaway, not a throughput setting.
BATCH_SIZE = 25

DEFAULT_INTERVAL_SECONDS = 10.0


@dataclass
class Stats:
    executed: int = 0
    failed: int = 0
    #: Approved, but no enforcement point is configured for its type. Left alone.
    waiting: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"executed": self.executed, "failed": self.failed,
                "waiting": len(self.waiting)}


def execute_action(session, action: ResponseAction, point) -> bool:
    """Apply one approved action. Returns whether the network changed.

    Each action is its own transaction. It has to be: the rollback that undoes the
    optimistic transition when an enforcement point refuses would otherwise discard
    the actions executed earlier in the same pass.
    """
    # Raises without a valid approval, before anything leaves this process.
    mark_executed(session, action)

    try:
        receipt = point.apply(action)
    except EnforcementError as exc:
        session.rollback()
        mark_failed(session, action, str(exc))
        session.commit()
        logger.error("action %s failed: %s", action.action_id, exc)
        return False

    session.commit()
    logger.info("action %s executed: %s", action.action_id, receipt)
    return True


def run_once(session, points: dict[ActionType, object], limit: int = BATCH_SIZE) -> Stats:
    """Drain the approved queue once."""
    stats = Stats()
    for action in ActionRepository(session).approved(limit=limit):
        point = points.get(action.action_type)
        if point is None:
            # Not a failure: an unconfigured backend is a gap in the deployment, not
            # a refusal by the network. Failing the action here would cost the
            # analyst a second approval once the backend arrives.
            stats.waiting.append(action.action_type.value)
            continue
        if execute_action(session, action, point):
            stats.executed += 1
        else:
            stats.failed += 1

    if stats.waiting:
        logger.warning(
            "%s approved action(s) have no enforcement point configured: %s",
            len(stats.waiting),
            ", ".join(sorted(set(stats.waiting))),
        )
    return stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute approved response actions at the enforcement points"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL_SECONDS,
        help=f"seconds between passes (default: {DEFAULT_INTERVAL_SECONDS})",
    )
    parser.add_argument(
        "--once", action="store_true", help="drain the queue once and exit"
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    settings = get_settings()
    points = enforcers_from(settings)
    if not points:
        # Refused rather than started: a worker that polls a queue it can never act
        # on looks healthy in the logs while approved blocks pile up unapplied.
        print(
            "no enforcement point configured; set NETSENTINEL_CROWDSEC_URL "
            "(with machine id and password) or NETSENTINEL_WAZUH_URL",
            file=sys.stderr,
        )
        return 2

    logger.info(
        "responder ready for %s", ", ".join(sorted(t.value for t in points))
    )
    sessionmaker = get_sessionmaker()
    try:
        while True:
            with sessionmaker() as session:
                stats = run_once(session, points)
            if args.once:
                print(f"responder: {stats.as_dict()}")
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("stopping")
        return 0


if __name__ == "__main__":
    sys.exit(main())
