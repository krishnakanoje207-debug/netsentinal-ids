"""The human-in-the-loop gate: the rule the whole design rests on.

These run without a database. The service takes objects and never queries, so a
stub session that only collects what was added is enough - and that shape is
deliberate, because it means no code path can reach execution without passing the
check.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    Alert,
    Approval,
    ApprovalDecision,
    AuditLog,
    ResponseAction,
    Severity,
    User,
)
from netsentinel_api.services.response import (
    AlreadyDecided,
    AlreadyProposed,
    ApprovalRequired,
    InvalidTarget,
    NotExecutable,
    ProtectedTarget,
    SelfApproval,
    mark_executed,
    mark_failed,
    mark_rolled_back,
    propose,
    record_decision,
    request_rollback,
)


class StubSession:
    """Collects added objects. Stands in for a Session's add()."""

    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def audit_entries(self) -> list[AuditLog]:
        return [o for o in self.added if isinstance(o, AuditLog)]


@pytest.fixture
def session() -> StubSession:
    return StubSession()


@pytest.fixture
def analyst() -> User:
    return User(user_id=7, username="analyst", email="a@example.test",
                password_hash="x", role_id=1, is_active=True)


@pytest.fixture
def action() -> ResponseAction:
    return ResponseAction(
        action_id=42,
        alert_id=1,
        action_type=ActionType.block_ip,
        target="203.0.113.9",
        status=ActionStatus.pending_approval,
    )


# --- the refusals ----------------------------------------------------------

def test_execution_without_approval_is_refused(session, action):
    """The single most important assertion in the backend."""
    with pytest.raises(ApprovalRequired, match="no approval"):
        mark_executed(session, action)
    assert action.status is ActionStatus.pending_approval
    assert action.executed_at is None


def test_execution_after_rejection_is_refused(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.rejected, "false positive")
    with pytest.raises(ApprovalRequired, match="rejected"):
        mark_executed(session, action)
    assert action.status is ActionStatus.rejected
    assert action.executed_at is None


def test_a_deactivated_user_cannot_approve(session, action, analyst):
    analyst.is_active = False
    with pytest.raises(ApprovalRequired, match="deactivated"):
        record_decision(session, action, analyst, ApprovalDecision.approved)
    assert action.approval is None


def test_the_proposer_cannot_approve_their_own_action(session, analyst):
    """Two people, whatever the roles say. An account edited in the database to hold
    both permissions still cannot open the gate on both sides."""
    action = propose(session, _alert(), ActionType.block_ip, None, analyst)
    action.action_id = 42

    with pytest.raises(SelfApproval, match="proposed"):
        record_decision(session, action, analyst, ApprovalDecision.approved)

    assert action.approval is None
    assert action.status is ActionStatus.pending_approval
    refused = session.audit_entries()[-1]
    assert refused.action == "response.self_approval_refused"
    assert refused.user_id == analyst.user_id
    assert refused.entity == "response_action:42"


def test_somebody_else_can_approve_the_proposal(session, analyst):
    action = propose(session, _alert(), ActionType.block_ip, None, analyst)
    other = User(user_id=8, username="approver", email="b@example.test",
                 password_hash="x", role_id=1, is_active=True)
    record_decision(session, action, other, ApprovalDecision.approved)
    assert action.status is ActionStatus.approved


def test_an_action_cannot_be_decided_twice(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.rejected)
    with pytest.raises(AlreadyDecided, match="already rejected"):
        record_decision(session, action, analyst, ApprovalDecision.approved)


def test_a_forged_approval_object_still_needs_to_say_yes(session, action, analyst):
    """Attaching an Approval is not enough; the decision is what is checked."""
    action.approval = Approval(
        action_id=action.action_id,
        approver_id=analyst.user_id,
        decision=ApprovalDecision.rejected,
    )
    action.status = ActionStatus.approved  # inconsistent state, as a bug would leave it
    with pytest.raises(ApprovalRequired):
        mark_executed(session, action)


def test_double_execution_is_refused(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_executed(session, action)
    with pytest.raises(NotExecutable, match="expected approved"):
        mark_executed(session, action)


# --- the happy path -------------------------------------------------------

def test_approved_action_executes(session, action, analyst):
    approval = record_decision(session, action, analyst, ApprovalDecision.approved, "confirmed")
    assert action.status is ActionStatus.approved
    assert approval.approver_id == analyst.user_id

    at = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)
    mark_executed(session, action, at=at)
    assert action.status is ActionStatus.executed
    assert action.executed_at == at


def test_executed_action_can_be_rolled_back(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_executed(session, action)

    request_rollback(session, action, analyst, reason="blocked a partner IP")
    # The ban is still in force here; only the request has been recorded.
    assert action.status is ActionStatus.rollback_requested

    mark_rolled_back(session, action)
    assert action.status is ActionStatus.rolled_back


def test_a_rollback_cannot_be_requested_for_an_action_that_never_executed(
    session, action, analyst
):
    with pytest.raises(NotExecutable, match="nothing to roll back"):
        request_rollback(session, action, analyst, reason="premature")
    assert action.status is ActionStatus.pending_approval


def test_an_unrequested_rollback_is_refused(session, action, analyst):
    """The worker cannot lift a ban nobody asked it to lift."""
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_executed(session, action)

    with pytest.raises(NotExecutable, match="no rollback was requested"):
        mark_rolled_back(session, action)
    assert action.status is ActionStatus.executed


def test_failed_execution_is_recorded(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_failed(session, action, error="nftables rule rejected")
    assert action.status is ActionStatus.failed
    assert "nftables" in session.audit_entries()[-1].details["error"]


# --- the audit trail ------------------------------------------------------

def test_every_transition_writes_an_audit_row(session, action, analyst):
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_executed(session, action)
    request_rollback(session, action, analyst, reason="undo")
    mark_rolled_back(session, action)

    actions = [entry.action for entry in session.audit_entries()]
    assert actions == [
        "response.approved",
        "response.executed",
        "response.rollback_requested",
        "response.rolled_back",
    ]
    for entry in session.audit_entries():
        assert entry.entity == "response_action:42"


def test_the_rollback_is_attributed_to_the_human_and_the_lift_to_nobody(
    session, action, analyst
):
    """Two questions, two rows: who asked, and when it was actually lifted."""
    record_decision(session, action, analyst, ApprovalDecision.approved)
    mark_executed(session, action)
    request_rollback(session, action, analyst, reason="blocked a partner IP")
    mark_rolled_back(session, action)

    requested, lifted = session.audit_entries()[-2:]
    assert requested.user_id == analyst.user_id
    assert requested.details["reason"] == "blocked a partner IP"
    # No user id: a worker lifted the ban, and saying otherwise would read as the
    # analyst having gone to the firewall themselves.
    assert lifted.user_id is None


def test_a_refused_execution_leaves_no_audit_row(session, action):
    """Nothing happened on the network, so nothing is claimed in the log."""
    with pytest.raises(ApprovalRequired):
        mark_executed(session, action)
    assert session.audit_entries() == []


# --- the other end of the gate: proposing -----------------------------------

def _alert(**overrides) -> Alert:
    fields = {
        "alert_id": 100,
        "source": "early_flow",
        "severity": Severity.high,
        "src_ip": "203.0.113.9",
        "dst_ip": "10.0.0.9",
    }
    fields.update(overrides)
    return Alert(**fields)


def test_a_proposal_arrives_awaiting_a_decision(session, analyst):
    action = propose(session, _alert(), ActionType.block_ip, None, analyst)

    assert action.status is ActionStatus.pending_approval
    assert action.approval is None
    assert action.proposed_by == analyst.user_id
    assert "response.proposed" in [e.action for e in session.audit_entries()]


def test_blocking_defaults_to_the_address_the_traffic_came_from(session, analyst):
    action = propose(session, _alert(), ActionType.block_ip, None, analyst)
    assert action.target == "203.0.113.9"


def test_an_alert_with_no_source_address_cannot_default_to_one(session, analyst):
    with pytest.raises(InvalidTarget, match="does not supply one"):
        propose(session, _alert(src_ip=None), ActionType.block_ip, None, analyst)


def test_a_host_action_has_no_default_target(session, analyst):
    """Guessing which machine to isolate is not a default worth having."""
    with pytest.raises(InvalidTarget):
        propose(session, _alert(), ActionType.isolate_host, None, analyst)


def test_a_block_on_something_that_is_not_an_address_is_refused(session, analyst):
    with pytest.raises(InvalidTarget, match="not an IP address"):
        propose(session, _alert(), ActionType.block_ip, "attacker.test", analyst)


def test_the_estate_cannot_be_blocked_at_its_own_edge(session, analyst):
    """A response that blackholes your own DNS server is the outage it prevented."""
    with pytest.raises(ProtectedTarget, match="Isolate the host instead"):
        propose(session, _alert(), ActionType.block_ip, "10.0.0.9", analyst,
                protected=["10.0.0.9", "10.0.0.10"])


def test_an_internal_host_can_still_be_isolated(session, analyst):
    """The protection is about blast radius, not about the address."""
    action = propose(session, _alert(), ActionType.isolate_host, "001", analyst,
                     protected=["10.0.0.9"])
    assert action.target == "001"


def test_the_same_proposal_twice_is_refused(session, analyst, action):
    """Approving both bans the address twice and tells two analysts they decided."""
    with pytest.raises(AlreadyProposed, match="already proposes"):
        propose(session, _alert(), ActionType.block_ip, "203.0.113.9", analyst,
                existing=[action])


def test_a_rejected_proposal_can_be_made_again(session, analyst, action):
    """A rejection is a judgement about that moment, not a permanent veto."""
    action.status = ActionStatus.rejected
    again = propose(session, _alert(), ActionType.block_ip, "203.0.113.9", analyst,
                    existing=[action])
    assert again.status is ActionStatus.pending_approval


def test_a_different_action_on_the_same_alert_is_not_a_duplicate(session, analyst, action):
    other = propose(session, _alert(), ActionType.isolate_host, "001", analyst,
                    existing=[action])
    assert other.action_type is ActionType.isolate_host
