"""Alert feed, detail and triage."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.db.models import Alert, AlertStatus, AuditLog, Detection, Severity
from netsentinel_api.deps import AlertRepoDep, SessionDep, require
from netsentinel_api.rbac import ALERTS_READ, ALERTS_TRIAGE
from netsentinel_api.schemas import (
    AlertDetailOut,
    AlertOut,
    AlertStatusUpdate,
    ExplanationOut,
)

router = APIRouter(prefix="/alerts", tags=["alerts"])

#: How many contributing features the detail view highlights.
TOP_FEATURE_COUNT = 10


def _explanation(detection: Detection | None) -> ExplanationOut | None:
    if detection is None:
        return None
    contributions = {k: float(v) for k, v in (detection.shap_values or {}).items()}
    ranked = sorted(contributions, key=lambda k: abs(contributions[k]), reverse=True)
    return ExplanationOut(
        risk_score=detection.risk_score,
        model_scores={k: float(v) for k, v in (detection.model_scores or {}).items()},
        feature_contributions=contributions,
        top_features=ranked[:TOP_FEATURE_COUNT],
        shadow=detection.shadow,
    )


@router.get("", response_model=list[AlertOut])
def list_alerts(
    alerts: AlertRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Annotated[Severity | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Alert]:
    return alerts.list(status=status_filter, severity=severity, limit=limit, offset=offset)


@router.get("/{alert_id}", response_model=AlertDetailOut)
def get_alert(
    alert_id: int,
    alerts: AlertRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
) -> AlertDetailOut:
    alert = alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    detail = AlertDetailOut.model_validate(alert)
    detail.explanation = _explanation(alert.detection)
    detail.ioc_values = [ioc.value for ioc in alert.iocs]
    return detail


@router.patch("/{alert_id}/status", response_model=AlertOut)
def update_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    alerts: AlertRepoDep,
    session: SessionDep,
    user: Annotated[object, Depends(require(ALERTS_TRIAGE))],
) -> Alert:
    alert = alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    previous = alert.status
    alerts.set_status(alert, payload.status)
    # Who closed an alert as a false positive, and when, is exactly the question
    # asked after an incident is missed.
    session.add(
        AuditLog(
            user_id=user.user_id,  # type: ignore[attr-defined]
            action="alert.status_changed",
            entity=f"alert:{alert_id}",
            details={"from": previous.value, "to": payload.status.value},
        )
    )
    return alert
