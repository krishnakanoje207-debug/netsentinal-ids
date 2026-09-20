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

The same two rules run the undo queue, with one asymmetry: a refused execution is
recorded as ``failed`` and left, while a refused undo is retried indefinitely. The
difference is what the database would otherwise claim. A failed execution means
nothing is blocked, which is true; a failed undo would mean the same thing while the
address is still blocked, which is not.

Once the transaction is committed, and only then, a change to the estate is narrated
onto the timeline of the DFIR-IRIS case the alert is being worked in. That order is
the third rule: a round trip to another system does not belong inside a transaction,
and an investigator reading the case should see what happened rather than what was
attempted.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from dataclasses import dataclass, field

from netsentinel_api.config import get_settings
from netsentinel_api.db.models import ActionStatus, ActionType, ResponseAction
from netsentinel_api.db.repositories import ActionRepository
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.cases import CaseError, response_event
from netsentinel_api.services.cases import client_from as case_client_from
from netsentinel_api.services.enforcement import EnforcementError, enforcers_from
from netsentinel_api.services.response import (
    mark_executed,
    mark_failed,
    mark_rolled_back,
)

logger = logging.getLogger("netsentinel.responder")

#: Actions per pass. The queue is human-sized - every entry was approved by somebody
#: - so this is a guard against a runaway, not a throughput setting.
BATCH_SIZE = 25

DEFAULT_INTERVAL_SECONDS = 10.0


@dataclass
class Stats:
    executed: int = 0
    failed: int = 0
    rolled_back: int = 0
    #: Undos the enforcement point refused. The action stays in the queue and the
    #: next pass tries again, so this is counted rather than logged and forgotten:
    #: a number that never falls is a ban nobody is managing to lift.
    retrying: int = 0
    #: Queued, but no enforcement point is configured for the type. Left alone.
    waiting: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"executed": self.executed, "failed": self.failed,
                "rolled_back": self.rolled_back, "retrying": self.retrying,
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


def roll_back_action(session, action: ResponseAction, point) -> bool:
    """Undo one action a human asked to have lifted. Returns whether it was lifted.

    This mirrors ``execute_action`` and differs from it in one place that matters.
    When the enforcement point refuses, the action is left in
    ``rollback_requested`` for the next pass instead of being marked ``failed``.
    The ban is still in force, so a row reading ``failed`` would tell an analyst
    that nothing is blocked while the address still is - the more dangerous of the
    two lies. Retrying is safe: deleting a decision that has already expired is a
    success at CrowdSec, and re-running an unisolate is the host already reachable.
    """
    # The gate check: refuses an action nobody asked to roll back, before anything
    # leaves this process.
    mark_rolled_back(session, action)

    try:
        receipt = point.undo(action)
    except EnforcementError as exc:
        session.rollback()
        # Where execute_action writes 'failed' after its rollback, the equivalent
        # here is putting the row back where it was, so this process keeps seeing
        # the action in the undo queue.
        action.status = ActionStatus.rollback_requested
        logger.error("rollback of action %s refused, will retry: %s",
                     action.action_id, exc)
        return False

    session.commit()
    logger.info("action %s rolled back: %s", action.action_id, receipt)
    return True


def record_in_case(session, action: ResponseAction, cases) -> None:
    """Put a change to the estate on the timeline of the case it belongs to.

    Called after the transaction has committed, never inside it: this is a round
    trip to another system, and holding a row lock across it is how a worker turns
    a slow IRIS into a stuck queue. The same reason the writer forwards to Keep
    after its commit rather than before.

    Best effort, and quietly skipped when there is nothing to write to. Most alerts
    are never escalated, so an action with no case behind it is the normal case and
    not a condition worth logging every pass.
    """
    if cases is None:
        return

    case_id = ActionRepository(session).iris_case_for(action)
    if case_id is None:
        return

    try:
        cases.add_timeline_event(case_id, response_event(action))
    except CaseError as exc:
        # Logged, never raised. The action reached the network and the database
        # says so; the timeline entry is how a human reads about it afterwards,
        # and losing it must not undo or repeat the action itself.
        logger.error("could not add action %s to case %s: %s",
                     action.action_id, case_id, exc)


def run_once(session, points: dict[ActionType, object], limit: int = BATCH_SIZE,
             cases=None) -> Stats:
    """Drain the approved queue, then the rollback queue.

    Approvals first. A block that has not been applied is an attacker still
    reaching the network; an undo that waits one interval is a ban that lasts ten
    seconds longer.
    """
    stats = Stats()
    actions = ActionRepository(session)

    for action in actions.approved(limit=limit):
        point = points.get(action.action_type)
        if point is None:
            # Not a failure: an unconfigured backend is a gap in the deployment, not
            # a refusal by the network. Failing the action here would cost the
            # analyst a second approval once the backend arrives.
            stats.waiting.append(action.action_type.value)
            continue
        if execute_action(session, action, point):
            stats.executed += 1
            record_in_case(session, action, cases)
        else:
            stats.failed += 1

    for action in actions.rollback_requested(limit=limit):
        point = points.get(action.action_type)
        if point is None:
            # Same reasoning, and it bites harder here: the request stays queued, so
            # configuring the backend lifts the ban rather than asking the analyst
            # to notice it is still in place.
            stats.waiting.append(action.action_type.value)
            continue
        if roll_back_action(session, action, point):
            stats.rolled_back += 1
            record_in_case(session, action, cases)
        else:
            stats.retrying += 1

    if stats.waiting:
        logger.warning(
            "%s queued action(s) have no enforcement point configured: %s",
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

    # Optional, and unlike the enforcement points its absence is not worth
    # refusing to start over: with no IRIS the blocks still land, they are just not
    # narrated into a case.
    cases = case_client_from(settings)

    logger.info(
        "responder ready for %s%s",
        ", ".join(sorted(t.value for t in points)),
        "" if cases is None else "; writing to IRIS case timelines",
    )
    sessionmaker = get_sessionmaker()
    try:
        while True:
            with sessionmaker() as session:
                stats = run_once(session, points, cases=cases)
            if args.once:
                print(f"responder: {stats.as_dict()}")
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logger.info("stopping")
        return 0


if __name__ == "__main__":
    sys.exit(main())
