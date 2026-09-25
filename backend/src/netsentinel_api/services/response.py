"""The human-in-the-loop gate.

Every automated response passes through here. The functions take the action
object rather than an id and never query, so the rule is testable without a
database and cannot be bypassed by a code path that forgot to load a relationship.

The schema enforces what a schema can - an action has at most one approval, and an
executed action has an execution time. What it cannot express is "do not execute
without a yes", because that spans two tables; that rule lives here, and every
transition writes an audit row.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Iterable, Protocol

from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    Alert,
    Approval,
    ApprovalDecision,
    AuditLog,
    ResponseAction,
    User,
)

#: Statuses in which an action is still somebody's business: awaiting a decision,
#: waiting to be carried out, or in force. A second proposal for the same thing is
#: a duplicate only against these - a rejected or failed one is worth proposing
#: again.
OPEN_STATUSES = frozenset(
    {
        ActionStatus.pending_approval,
        ActionStatus.approved,
        ActionStatus.executed,
        ActionStatus.rollback_requested,
    }
)


class SupportsAdd(Protocol):
    """The slice of a SQLAlchemy Session this module needs."""

    def add(self, instance: object, /) -> None: ...


class ResponseError(Exception):
    """Base for refusals from the gate."""


class AlreadyDecided(ResponseError):
    """An action carries at most one decision, and it already has one."""


class ApprovalRequired(ResponseError):
    """Refused: no human has approved this action."""


class SelfApproval(ResponseError):
    """Refused: the person who proposed an action cannot also approve it."""


class NotExecutable(ResponseError):
    """Refused: the action is not in a state from which it could execute."""


class AlreadyProposed(ResponseError):
    """Refused: this alert already carries an open proposal for the same thing."""


class InvalidTarget(ResponseError):
    """Refused: the action names nothing this system could act on."""


class ProtectedTarget(ResponseError):
    """Refused: the target is part of the estate this system defends."""


def _audit(session: SupportsAdd, user_id: int | None, action_name: str,
           entity_id: int, details: dict) -> None:
    session.add(
        AuditLog(
            user_id=user_id,
            action=action_name,
            entity=f"response_action:{entity_id}",
            details=details,
        )
    )


def propose(
    session: SupportsAdd,
    alert: Alert,
    action_type: ActionType,
    target: str | None,
    actor: User,
    existing: Iterable[ResponseAction] = (),
    protected: Iterable[str] = (),
) -> ResponseAction:
    """Put a containment action in front of a human. Nothing is executed here.

    This is the other end of the gate: the proposal. The role that proposes is
    never the role that approves - ``rbac`` asserts that - so this function creates
    something somebody else has to agree with.

    ``protected`` is the estate's own addresses. Proposing to blackhole one of them
    is how a response causes the outage it was meant to prevent, and an analyst
    approving a plausible-looking block at three in the morning is not a reliable
    last line of defence. An internal host that needs containing is isolated, which
    is a different action with a different blast radius.
    """
    if action_type is ActionType.block_ip and not target:
        # The obvious default, and the only one worth having: the address the alert
        # says the traffic came from.
        target = str(alert.src_ip) if alert.src_ip else None
    if not target:
        raise InvalidTarget(
            f"a {action_type.value} action needs a target, and alert "
            f"{alert.alert_id} does not supply one"
        )
    target = target.strip()

    if action_type is ActionType.block_ip:
        # Checked again at the enforcement point, deliberately: that check asks
        # whether it is safe to send, this one asks whether it is a sane thing to
        # ask a human to approve.
        try:
            ipaddress.ip_address(target)
        except ValueError as exc:
            raise InvalidTarget(f"{target!r} is not an IP address") from exc

        if target in {str(address) for address in protected}:
            raise ProtectedTarget(
                f"{target} is an asset of this estate; blocking it at the edge "
                "would take it off the network. Isolate the host instead"
            )

    duplicate = next(
        (
            action
            for action in existing
            if action.action_type is action_type
            and action.target == target
            and action.status in OPEN_STATUSES
        ),
        None,
    )
    if duplicate is not None:
        # A second identical proposal would sit in the queue next to the first, and
        # approving both bans the same address twice while telling two analysts
        # they each decided something.
        raise AlreadyProposed(
            f"action {duplicate.action_id} already proposes {action_type.value} on "
            f"{target} for alert {alert.alert_id} and is {duplicate.status.value}"
        )

    action = ResponseAction(
        alert_id=alert.alert_id,
        action_type=action_type,
        target=target,
        status=ActionStatus.pending_approval,
        proposed_by=actor.user_id,
    )
    action.alert = alert
    session.add(action)
    # Not ``_audit``: that names a response_action, and this row has no id until it
    # is flushed. The alert is what identifies the proposal until then.
    session.add(
        AuditLog(
            user_id=actor.user_id,
            action="response.proposed",
            entity=f"alert:{alert.alert_id}",
            details={"action_type": action_type.value, "target": target},
        )
    )
    return action


def record_decision(
    session: SupportsAdd,
    action: ResponseAction,
    approver: User,
    decision: ApprovalDecision,
    comment: str | None = None,
) -> Approval:
    """Attach a human decision to an action and move its status accordingly."""
    if action.approval is not None:
        raise AlreadyDecided(
            f"action {action.action_id} was already "
            f"{action.approval.decision.value} by user {action.approval.approver_id}"
        )
    if action.status is not ActionStatus.pending_approval:
        raise NotExecutable(
            f"action {action.action_id} is {action.status.value}, "
            "so it is not awaiting a decision"
        )
    if not approver.is_active:
        raise ApprovalRequired(
            f"user {approver.user_id} is deactivated and cannot approve actions"
        )
    if (
        decision is ApprovalDecision.approved
        and action.proposed_by is not None
        and action.proposed_by == approver.user_id
    ):
        # Roles keep proposing and approving apart, but a role can be edited. This
        # checks the person, so the two-person rule survives an account that holds
        # both permissions. Audited here; the caller commits it past the refusal.
        _audit(session, approver.user_id, "response.self_approval_refused",
               action.action_id,
               {"action_type": action.action_type.value, "target": action.target})
        raise SelfApproval(
            f"user {approver.user_id} proposed action {action.action_id} and "
            "cannot also approve it"
        )

    approval = Approval(
        action_id=action.action_id,
        approver_id=approver.user_id,
        decision=decision,
        comment=comment,
    )
    approval.action = action
    action.approval = approval
    action.status = (
        ActionStatus.approved
        if decision is ApprovalDecision.approved
        else ActionStatus.rejected
    )

    session.add(approval)
    _audit(
        session,
        approver.user_id,
        f"response.{decision.value}",
        action.action_id,
        {
            "action_type": action.action_type.value,
            "target": action.target,
            "comment": comment,
        },
    )
    return approval


def mark_executed(
    session: SupportsAdd,
    action: ResponseAction,
    at: datetime | None = None,
) -> None:
    """Record that an action was carried out. Refuses without an approval.

    This is the single choke point in front of CrowdSec and Wazuh Active
    Response. If it raises, nothing on the network changed.
    """
    if action.approval is None:
        raise ApprovalRequired(
            f"action {action.action_id} has no approval; refusing to execute"
        )
    if action.approval.decision is not ApprovalDecision.approved:
        raise ApprovalRequired(
            f"action {action.action_id} was rejected; refusing to execute"
        )
    if action.status is not ActionStatus.approved:
        raise NotExecutable(
            f"action {action.action_id} is {action.status.value}, expected approved"
        )

    action.status = ActionStatus.executed
    action.executed_at = at or datetime.now(timezone.utc)
    _audit(
        session,
        action.approval.approver_id,
        "response.executed",
        action.action_id,
        {"action_type": action.action_type.value, "target": action.target},
    )


def request_rollback(session: SupportsAdd, action: ResponseAction,
                     actor: User, reason: str) -> None:
    """Ask for an executed action to be undone. The human half of the rollback.

    Nothing on the network changes here: when this returns the ban is still in
    force and the action is queued for the responder, which lifts it and calls
    ``mark_rolled_back``. The split exists because "who asked for the ban to be
    lifted" and "when was it actually lifted" are different questions, and one
    audit row cannot answer both honestly - the second fact is not yet known when
    the first is recorded.
    """
    if action.status is not ActionStatus.executed:
        raise NotExecutable(
            f"action {action.action_id} is {action.status.value}, so there is "
            "nothing to roll back"
        )
    action.status = ActionStatus.rollback_requested
    _audit(session, actor.user_id, "response.rollback_requested", action.action_id,
           {"action_type": action.action_type.value, "target": action.target,
            "reason": reason})


def mark_rolled_back(session: SupportsAdd, action: ResponseAction) -> None:
    """Record that the undo reached the enforcement point.

    Refuses an action nobody asked to roll back, which is what makes this the gate
    check in front of the undo rather than a bookkeeping call after it.

    The audit row carries no user id: a worker completed this, and the human who
    asked for it is on the ``response.rollback_requested`` row. Attributing this
    one to them as well would read as though they had lifted the ban by hand.
    """
    if action.status is not ActionStatus.rollback_requested:
        raise NotExecutable(
            f"action {action.action_id} is {action.status.value}, so no rollback "
            "was requested for it"
        )
    action.status = ActionStatus.rolled_back
    _audit(session, None, "response.rolled_back", action.action_id,
           {"action_type": action.action_type.value, "target": action.target})


def mark_failed(session: SupportsAdd, action: ResponseAction, error: str) -> None:
    """Execution was attempted and the enforcement point rejected it."""
    action.status = ActionStatus.failed
    approver_id = action.approval.approver_id if action.approval else None
    _audit(session, approver_id, "response.failed", action.action_id, {"error": error})
