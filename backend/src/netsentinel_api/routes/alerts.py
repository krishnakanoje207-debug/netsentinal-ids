"""Alert feed, detail and triage."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from netsentinel_api.db.models import (
    Alert,
    AlertStatus,
    AuditLog,
    Detection,
    Incident,
    IncidentStatus,
    ResponseAction,
    Severity,
)
from netsentinel_api.db.repositories import MAX_EXPORT_ROWS
from netsentinel_api.deps import (
    AlertRepoDep,
    AssetRepoDep,
    SessionDep,
    SettingsDep,
    require,
)
from netsentinel_api.rbac import ALERTS_READ, ALERTS_TRIAGE, RESPONSE_PROPOSE
from netsentinel_api.schemas import (
    ActionOut,
    AlertDetailOut,
    AlertOut,
    AlertStatusUpdate,
    AlertSummaryOut,
    CopilotSummaryOut,
    EscalateIn,
    ExplanationOut,
    IncidentOut,
    ProposeActionIn,
)
from netsentinel_api.services.cases import (
    CaseError,
    IrisClient,
    case_description,
    case_title,
    client_from,
)
from netsentinel_api.services.export import alerts_csv, filename
from netsentinel_api.services.search import (
    AddressQuery,
    TechniqueQuery,
    Unsearchable,
    parse as parse_search,
)
from netsentinel_api.services.response import (
    AlreadyProposed,
    InvalidTarget,
    ProtectedTarget,
    propose,
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


#: What the search box accepts, in the words the refusal uses.
SEARCH_HELP = "an address (203.0.113.9), a network (203.0.113.0/24) or a technique (T1046)"


def _searched(query: str | None) -> AddressQuery | TechniqueQuery | None:
    """Read the search box, or refuse with a sentence saying what it accepts.

    An empty box is not a refusal - it is the unfiltered feed, which is what the
    dashboard sends when the analyst clears the field.
    """
    if query is None or not query.strip():
        return None
    try:
        return parse_search(query)
    except Unsearchable as exc:
        # 422 rather than an empty list: a search box that silently returns nothing
        # teaches an analyst that there is nothing there.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc


@router.get("", response_model=list[AlertOut])
def list_alerts(
    alerts: AlertRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Annotated[Severity | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=60, description=SEARCH_HELP)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[Alert]:
    return alerts.list(
        status=status_filter,
        severity=severity,
        search=_searched(q),
        limit=limit,
        offset=offset,
    )


# Declared before "/{alert_id}" for the same reason as the export below.
@router.get("/summary", response_model=AlertSummaryOut)
def summarise_alerts(
    alerts: AlertRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
) -> dict:
    """Totals by severity and status, and the addresses raising the most alerts."""
    return alerts.summary()


# Declared before "/{alert_id}", because a path parameter would otherwise match
# "export" first and answer this request by failing to parse it as an integer.
@router.get("/export", response_class=Response)
def export_alerts(
    alerts: AlertRepoDep,
    session: SessionDep,
    user: Annotated[object, Depends(require(ALERTS_READ))],
    status_filter: Annotated[AlertStatus | None, Query(alias="status")] = None,
    severity: Annotated[Severity | None, Query()] = None,
    q: Annotated[str | None, Query(max_length=60, description=SEARCH_HELP)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_EXPORT_ROWS)] = MAX_EXPORT_ROWS,
) -> Response:
    """The feed as a CSV file, with the risk score and the model beside each row.

    The filters are the feed's filters, so what comes out is what the analyst was
    looking at. An export that silently differs from the screen it was taken from is
    evidence nobody can reproduce.

    ``alerts:read`` and nothing more. A separate export permission would be theatre:
    anyone who may page through the feed can already collect it a page at a time,
    and the only thing a second permission would add is the belief that they cannot.

    The read is recorded. Every alert in the estate leaving in one file is worth a
    row in the audit log for the same reason closing one as a false positive is -
    both are questions asked afterwards. An audit entry is a record that a read
    happened rather than a change to what was read, so this stays a GET.
    """
    search = _searched(q)
    rows = alerts.for_export(
        status=status_filter, severity=severity, search=search, limit=limit
    )

    # The repository fetches one more than the cap precisely so this can tell a
    # truncated export from one that filled the cap exactly.
    truncated = len(rows) > limit
    rows = rows[:limit]

    session.add(
        AuditLog(
            user_id=user.user_id,  # type: ignore[attr-defined]
            action="alerts.exported",
            entity="alerts",
            details={
                "rows": len(rows),
                "truncated": truncated,
                "status": status_filter.value if status_filter else None,
                "severity": severity.value if severity else None,
                # Recorded so the audit row says which alerts left, not just how
                # many. "1,412 rows" answers nothing on its own.
                "search": str(search) if search is not None else None,
            },
        )
    )

    name = filename(datetime.now(timezone.utc), truncated)
    return Response(
        content=alerts_csv(rows),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="{name}"',
            # For the dashboard, which warns before the file is even opened. The
            # name carries it too, for whoever opens the file next week.
            "X-Export-Truncated": "true" if truncated else "false",
        },
    )


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


@router.get("/{alert_id}/summary", response_model=CopilotSummaryOut)
def copilot_summary(
    alert_id: int,
    alerts: AlertRepoDep,
    _: Annotated[object, Depends(require(ALERTS_READ))],
) -> dict:
    """The local model's summary of this alert, if one was written and passed its schema.

    Read-only by design. Summaries are generated by the Copilot process on the laptop
    (``netsentinel-copilot``), never by this API: nothing that serves requests may start
    a generation, or hold an LLM client an attacker's traffic could talk to.
    """
    alert = alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")
    row = alerts.latest_summary(alert)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="no summary yet; run netsentinel-copilot --alert "
            f"{alert_id} on the machine with the local model",
        )
    return {**row.summary_json, "llm_model": row.llm_model}


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


@router.post(
    "/{alert_id}/actions",
    response_model=ActionOut,
    status_code=status.HTTP_201_CREATED,
)
def propose_action(
    alert_id: int,
    payload: ProposeActionIn,
    alerts: AlertRepoDep,
    assets: AssetRepoDep,
    session: SessionDep,
    user: Annotated[object, Depends(require(RESPONSE_PROPOSE))],
) -> ResponseAction:
    """Propose containment for this alert. It executes when somebody else agrees.

    The permission is deliberately not the analyst's. No role holds both
    ``response:propose`` and ``approvals:decide`` - ``rbac`` asserts it and the
    tests enforce it - because a gate one account can open on both sides is not a
    gate. A 201 here means the action is in the approval queue and nothing has
    touched the network.
    """
    alert = alerts.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="alert not found")

    try:
        action = propose(
            session,
            alert,
            payload.action_type,
            payload.target,
            user,  # type: ignore[arg-type]
            existing=alert.actions,
            # The estate's own addresses, so a block aimed at one is refused before
            # an analyst is asked to approve it at three in the morning.
            protected=[asset.ip_address for asset in assets.list(limit=200)],
        )
    except AlreadyProposed as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except (InvalidTarget, ProtectedTarget) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    # The id is what the approver will decide on, so it has to be in the reply;
    # sessions are created with autoflush off, so it has to be asked for.
    session.flush()
    return action
