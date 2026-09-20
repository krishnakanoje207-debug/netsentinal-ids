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

from datetime import datetime, timezone
from typing import Protocol

from netsentinel_api.db.models import (
    ActionStatus,
    Approval,
    ApprovalDecision,
    AuditLog,
    ResponseAction,
    User,
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


class NotExecutable(ResponseError):
    """Refused: the action is not in a state from which it could execute."""


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


def mark_rolled_back(session: SupportsAdd, action: ResponseAction,
                     actor: User, reason: str) -> None:
    """Undo an executed action. The one-click rollback from the risk register."""
    if action.status is not ActionStatus.executed:
        raise NotExecutable(
            f"action {action.action_id} is {action.status.value}, so there is "
            "nothing to roll back"
        )
    action.status = ActionStatus.rolled_back
    _audit(session, actor.user_id, "response.rolled_back", action.action_id,
           {"target": action.target, "reason": reason})


def mark_failed(session: SupportsAdd, action: ResponseAction, error: str) -> None:
    """Execution was attempted and the enforcement point rejected it."""
    action.status = ActionStatus.failed
    approver_id = action.approval.approver_id if action.approval else None
    _audit(session, approver_id, "response.failed", action.action_id, {"error": error})
