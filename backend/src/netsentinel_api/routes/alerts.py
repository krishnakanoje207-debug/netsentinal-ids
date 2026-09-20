"""Alert feed, detail and triage."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.db.models import (
    Alert,
    AlertStatus,
    AuditLog,
    Detection,
    Incident,
    IncidentStatus,
    Severity,
)
from netsentinel_api.deps import AlertRepoDep, SessionDep, SettingsDep, require
from netsentinel_api.rbac import ALERTS_READ, ALERTS_TRIAGE
from netsentinel_api.schemas import (
    AlertDetailOut,
    AlertOut,
    AlertStatusUpdate,
    EscalateIn,
    ExplanationOut,
    IncidentOut,
)
from netsentinel_api.services.cases import (
    CaseError,
    IrisClient,
    case_description,
    case_title,
    client_from,
)

logger = logging.getLogger("netsentinel.alerts")

router = APIRouter(prefix="/alerts", tags=["alerts"])

#: How many contributing features the detail view highlights.
TOP_FEATURE_COUNT = 10


def case_client(settings: SettingsDep) -> IrisClient | None:
    """The IRIS client this deployment has, if any.

    A dependency rather than a direct call in the handler, so the escalation path
    can be exercised against a client that fails. That is its only purpose.
    """
    return client_from(settings)


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


@router.post(
    "/{alert_id}/escalate",
    response_model=IncidentOut,
    status_code=status.HTTP_201_CREATED,
)
def escalate(
    alert_id: int,
    payload: EscalateIn,
    alerts: AlertRepoDep,
    session: SessionDep,
    iris: Annotated[IrisClient | None, Depends(case_client)],
    user: Annotated[object, Depends(require(ALERTS_TRIAGE))],
) -> Incident:
    """Open an incident for this alert, and a DFIR-IRIS case to work it in.

    The incident is written first and IRIS is called afterwards, because the two
    are not equally important. This system's database is the evidence: it records
    that a named analyst escalated a specific alert at a specific time, and that
    record has to survive IRIS being down, unconfigured or slow. IRIS is where
    humans then work the case. So a failure to open the case is logged and the
    request still succeeds, with ``iris_case_id`` left null - the escalation
    happened, and the case can be opened by hand or on a later attempt.
    """
    alert = alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    if alert.incident_id is not None:
        # 409 rather than a second incident: two incidents for one alert split the
        # investigation in half, and neither half knows about the other.
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"alert {alert_id} already belongs to incident {alert.incident_id}",
        )

    title = payload.title or case_title(alert)
    incident = Incident(title=title, status=IncidentStatus.open,
                        owner_id=user.user_id)  # type: ignore[attr-defined]
    session.add(incident)
    # Sessions are created with autoflush off, and alerts.incident_id is a foreign
    # key to a row that does not have an id until it has been written.
    session.flush()

    alert.incident_id = incident.incident_id
    alerts.set_status(alert, AlertStatus.escalated)

    if iris is not None:
        try:
            incident.iris_case_id = iris.create_case(
                alert, title, case_description(alert, alert.iocs, payload.summary)
            )
        except CaseError as exc:
            # Logged, never raised. See the docstring: the incident is the record.
            logger.error("could not open an IRIS case for alert %s: %s", alert_id, exc)

    # Written after the attempt so one row says both what the analyst did and
    # whether a case came of it.
    session.add(
        AuditLog(
            user_id=user.user_id,  # type: ignore[attr-defined]
            action="alert.escalated",
            entity=f"alert:{alert_id}",
            details={"title": title, "iris_case_id": incident.iris_case_id},
        )
    )
    return incident
