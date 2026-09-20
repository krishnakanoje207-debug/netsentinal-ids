"""The responder worker.

One property matters more than the rest and the first test states it: the
enforcement point is never reached without an approval. The others are about what
the database says afterwards - an action recorded as executed when nothing was
applied, or left approved when a ban is in place, is worse than either outcome on
its own.
"""

from __future__ import annotations

import pytest

from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    Approval,
    ApprovalDecision,
    AuditLog,
    ResponseAction,
)
from netsentinel_api.responder import execute_action, run_once
from netsentinel_api.services.enforcement import EnforcementError
from netsentinel_api.services.response import ApprovalRequired


class StubSession:
    """Collects writes and counts transactions. No database, no network."""

    def __init__(self, actions: list[ResponseAction] | None = None) -> None:
        self.added: list[object] = []
        self.commits = 0
        self.rollbacks = 0
        self._actions = actions or []

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def scalars(self, *_args, **_kwargs):
        return list(self._actions)

    def audit_actions(self) -> list[str]:
        return [o.action for o in self.added if isinstance(o, AuditLog)]


class StubEnforcer:
    """Records what it was asked to apply, or refuses."""

    def __init__(self, error: str | None = None) -> None:
        self.applied: list[ResponseAction] = []
        self._error = error

    def apply(self, action: ResponseAction) -> dict:
        self.applied.append(action)
        if self._error:
            raise EnforcementError(self._error)
        return {"backend": "stub"}


def _action(status: ActionStatus = ActionStatus.approved,
            decision: ApprovalDecision | None = ApprovalDecision.approved,
            action_type: ActionType = ActionType.block_ip) -> ResponseAction:
    action = ResponseAction(
        action_id=500,
        alert_id=100,
        action_type=action_type,
        target="203.0.113.9",
        status=status,
    )
    if decision is not None:
        action.approval = Approval(
            approval_id=1, action_id=500, approver_id=7, decision=decision
        )
    return action


# --- the gate holds --------------------------------------------------------

@pytest.mark.parametrize(
    "action",
    [
        _action(status=ActionStatus.pending_approval, decision=None),
        _action(status=ActionStatus.rejected, decision=ApprovalDecision.rejected),
    ],
    ids=["unapproved", "rejected"],
)
def test_an_action_without_an_approval_never_reaches_the_network(action):
    session, enforcer = StubSession(), StubEnforcer()

    with pytest.raises(ApprovalRequired):
        execute_action(session, action, enforcer)

    assert enforcer.applied == []
    assert session.commits == 0


# --- the happy path --------------------------------------------------------

def test_an_approved_action_is_applied_and_recorded():
    action = _action()
    session, enforcer = StubSession(), StubEnforcer()

    assert execute_action(session, action, enforcer) is True
    assert enforcer.applied == [action]
    assert action.status is ActionStatus.executed
    assert action.executed_at is not None
    assert session.commits == 1
    assert "response.executed" in session.audit_actions()


# --- the network refused ---------------------------------------------------

def test_a_refused_action_is_recorded_as_failed():
    action = _action()
    session = StubSession()
    enforcer = StubEnforcer(error="CrowdSec refused the decision: 403")

    assert execute_action(session, action, enforcer) is False
    assert action.status is ActionStatus.failed
    # The optimistic transition is rolled back before the failure is written, so
    # nothing claims an execution that did not happen.
    assert session.rollbacks == 1
    assert "response.failed" in session.audit_actions()


def test_the_failure_reason_is_kept():
    action = _action()
    session = StubSession()
    execute_action(session, action, StubEnforcer(error="host unreachable"))

    failure = next(
        o for o in session.added
        if isinstance(o, AuditLog) and o.action == "response.failed"
    )
    assert "host unreachable" in failure.details["error"]


# --- the pass --------------------------------------------------------------

def test_each_action_is_its_own_transaction():
    """One refusal must not roll back the ones already applied."""
    good, bad = _action(), _action()
    bad.action_id = 501
    session = StubSession([good, bad])
    points = {ActionType.block_ip: StubEnforcer()}

    # The second call fails; the first is already committed.
    assert execute_action(session, good, points[ActionType.block_ip]) is True
    assert execute_action(session, bad, StubEnforcer(error="refused")) is False
    assert session.commits == 2


def test_an_action_with_no_enforcement_point_is_left_approved():
    """An unconfigured backend is a deployment gap, not a decision to undo."""
    action = _action(action_type=ActionType.isolate_host)
    action.target = "001"
    session = StubSession([action])

    stats = run_once(session, {})

    assert stats.executed == 0 and stats.failed == 0
    assert stats.waiting == ["isolate_host"]
    assert action.status is ActionStatus.approved
    assert session.commits == 0


def test_a_pass_executes_what_it_can():
    action = _action()
    session = StubSession([action])
    enforcer = StubEnforcer()

    stats = run_once(session, {ActionType.block_ip: enforcer})

    assert stats.as_dict() == {"executed": 1, "failed": 0, "waiting": 0}
    assert enforcer.applied == [action]
