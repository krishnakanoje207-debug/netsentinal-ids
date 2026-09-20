"""The approval queue and the decision endpoint.

This is the HTTP face of the human gate. The route validates and records; the rule
itself stays in ``services.response``, so the only way to reach execution is still
through ``mark_executed``.

Execution is not performed here. Approving an action moves it to ``approved``; the
CrowdSec and Wazuh executors (D12) pick it up and call ``mark_executed``. Reporting
a block as done before anything touched nftables would be a lie the dashboard then
shows to an analyst.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.db.models import ApprovalDecision, ResponseAction
from netsentinel_api.deps import ActionRepoDep, SessionDep, require
from netsentinel_api.rbac import APPROVALS_DECIDE, ALERTS_READ
from netsentinel_api.schemas import ActionOut, DecisionIn
from netsentinel_api.services.response import (
    AlreadyDecided,
    ApprovalRequired,
    NotExecutable,
    record_decision,
)

router = APIRouter(prefix="/actions", tags=["response"])


@router.get("/pending", response_model=list[ActionOut])
def pending_actions(
    actions: ActionRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[ResponseAction]:
    return actions.pending(limit=limit)


@router.post("/{action_id}/decision", response_model=ActionOut)
def decide(
    action_id: int,
    payload: DecisionIn,
    actions: ActionRepoDep,
    session: SessionDep,
    user: Annotated[object, Depends(require(APPROVALS_DECIDE))],
) -> ResponseAction:
    action = actions.get(action_id)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="action not found")

    if payload.decision is ApprovalDecision.rejected and not payload.comment:
        # An approval can stand on the evidence in the alert; a rejection is a
        # judgement that the evidence was wrong, and that reasoning is what the
        # next analyst needs.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="a rejection requires a comment explaining it",
        )

    try:
        record_decision(
            session, action, user, payload.decision, payload.comment  # type: ignore[arg-type]
        )
    except AlreadyDecided as exc:
        # 409: the request was well formed, the resource is just past this point.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except (ApprovalRequired, NotExecutable) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    return action
