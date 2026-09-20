"""The responder worker.

One property matters more than the rest and the first test states it: the
enforcement point is never reached without an approval. The others are about what
the database says afterwards - an action recorded as executed when nothing was
applied, or left approved when a ban is in place, is worse than either outcome on
its own.

The undo queue is held to the same standard with one deliberate asymmetry: a refused
undo must leave the action queued rather than mark it failed, because the ban it
failed to lift is still in force.
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
from netsentinel_api.responder import execute_action, roll_back_action, run_once
from netsentinel_api.services.enforcement import EnforcementError
from netsentinel_api.services.response import ApprovalRequired, NotExecutable


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

    def scalars(self, statement, *_args, **_kwargs):
        # The repository's two queues differ only in the status they select, so the
        # stub honours that rather than returning everything: a pass that saw every
        # action in both queues would hide exactly the bug this module is for.
        wanted = statement.whereclause.right.value
        return [a for a in self._actions if a.status == wanted]

    def audit_actions(self) -> list[str]:
        return [o.action for o in self.added if isinstance(o, AuditLog)]


class StubEnforcer:
    """Records what it was asked to apply or undo, or refuses."""

    def __init__(self, error: str | None = None, undo_error: str | None = None) -> None:
        self.applied: list[ResponseAction] = []
        self.undone: list[ResponseAction] = []
        self._error = error
        self._undo_error = undo_error

    def apply(self, action: ResponseAction) -> dict:
        self.applied.append(action)
        if self._error:
            raise EnforcementError(self._error)
        return {"backend": "stub"}

    def undo(self, action: ResponseAction) -> dict:
        self.undone.append(action)
        if self._undo_error:
            raise EnforcementError(self._undo_error)
        return {"backend": "stub", "deleted": []}


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

    assert stats.as_dict() == {"executed": 1, "failed": 0, "rolled_back": 0,
                               "retrying": 0, "waiting": 0}
    assert enforcer.applied == [action]


# --- the undo --------------------------------------------------------------

def test_an_undo_nobody_requested_never_reaches_the_network():
    action = _action(status=ActionStatus.executed)
    session, enforcer = StubSession(), StubEnforcer()

    with pytest.raises(NotExecutable):
        roll_back_action(session, action, enforcer)

    assert enforcer.undone == []
    assert session.commits == 0


def test_a_lifted_ban_is_recorded_as_rolled_back():
    action = _action(status=ActionStatus.rollback_requested)
    session, enforcer = StubSession(), StubEnforcer()

    assert roll_back_action(session, action, enforcer) is True
    assert enforcer.undone == [action]
    assert action.status is ActionStatus.rolled_back
    assert session.commits == 1
    assert "response.rolled_back" in session.audit_actions()


def test_a_refused_undo_leaves_the_action_queued_for_the_next_pass():
    """The ban is still in force, so the row must keep saying so."""
    action = _action(status=ActionStatus.rollback_requested)
    session = StubSession()
    enforcer = StubEnforcer(undo_error="CrowdSec refused to lift the ban: 502")

    assert roll_back_action(session, action, enforcer) is False
    assert action.status is ActionStatus.rollback_requested
    assert session.rollbacks == 1
    assert session.commits == 0
    # Nothing is claimed either way: not rolled back, because it was not, and not
    # failed, because 'failed' would read as nothing being blocked.
    assert "response.failed" not in session.audit_actions()


def test_a_pass_drains_both_queues():
    approved = _action()
    requested = _action(status=ActionStatus.rollback_requested)
    requested.action_id = 501
    session = StubSession([approved, requested])
    enforcer = StubEnforcer()

    stats = run_once(session, {ActionType.block_ip: enforcer})

    assert stats.as_dict() == {"executed": 1, "failed": 0, "rolled_back": 1,
                               "retrying": 0, "waiting": 0}
    assert enforcer.applied == [approved]
    assert enforcer.undone == [requested]


def test_an_undo_with_no_enforcement_point_is_left_requested():
    action = _action(status=ActionStatus.rollback_requested,
                     action_type=ActionType.isolate_host)
    action.target = "001"
    session = StubSession([action])

    stats = run_once(session, {})

    assert stats.rolled_back == 0 and stats.retrying == 0
    assert stats.waiting == ["isolate_host"]
    assert action.status is ActionStatus.rollback_requested
    assert session.commits == 0
