"""Data access, kept out of the route handlers.

Two reasons, in order of importance:

1. A route that builds its own queries cannot be tested without a database. These
   classes are injected, so the API tests run against fakes and the suite needs no
   PostgreSQL.
2. Query shapes stay in one place, which is where the indexes from M2 section 3.2
   can be honoured deliberately rather than by accident.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import cast, func, literal, literal_column, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql import Select

from netsentinel_api.db.models import (
    Alert,
    AlertStatus,
    Asset,
    AuditLog,
    CopilotSummary,
    Detection,
    MLModel,
    ModelMode,
    ModelTier,
    ResponseAction,
    Role,
    Sensor,
    Severity,
    User,
    Vulnerability,
)
from netsentinel_api.services.search import AddressQuery, TechniqueQuery, TimeRange
from netsentinel_api.services.shadow import LABELS, Scored


def _matching(
    statement: Select,
    search: AddressQuery | TechniqueQuery | None,
) -> Select:
    """Narrow a query by what the analyst typed.

    Shared by the feed and the export on purpose. The export claims to be the screen
    it was taken from, and two copies of this clause would eventually make that claim
    false.

    An address is matched with ``<<=`` - contained within or equal to - against the
    INET columns, so 203.0.113.0/24 finds every host on that network and a bare
    address finds itself. Matching addresses as text would make the network case
    impossible and the host case quietly wrong.
    """
    if search is None:
        return statement
    if isinstance(search, TechniqueQuery):
        return statement.where(Alert.mitre_technique == search.technique)

    network = cast(literal(str(search.network)), INET)
    # Either end: an analyst chasing a host wants what it sent and what was sent to
    # it, and which column it landed in is an accident of who opened the connection.
    return statement.where(
        or_(Alert.src_ip.op("<<=")(network), Alert.dst_ip.op("<<=")(network))
    )


def _within(statement: Select, window: TimeRange | None) -> Select:
    """Narrow a query to a time range, for the feed and the export alike.

    On ``created_at`` itself, so ix_alerts_created_at serves it.
    """
    if window is None:
        return statement
    if window.start is not None:
        statement = statement.where(Alert.created_at >= window.start)
    if window.end is not None:
        statement = statement.where(Alert.created_at <= window.end)
    return statement

#: Cap on a page of alerts. A SOC feed is unbounded; a response must not be.
MAX_PAGE_SIZE = 200

#: Cap on an export. Far above a page, because a report built from two hundred rows
#: is not a report, and still bounded: an unbounded export is a request that can be
#: made to read the whole table into memory by anyone who may read one alert.
MAX_EXPORT_ROWS = 10_000


class UserRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def by_username(self, username: str) -> User | None:
        return self._session.scalar(
            select(User).options(joinedload(User.role)).where(User.username == username)
        )


class AlertRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list(
        self,
        *,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        search: AddressQuery | TechniqueQuery | None = None,
        window: TimeRange | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        statement = select(Alert)
        if status is not None:
            statement = statement.where(Alert.status == status)
        if severity is not None:
            statement = statement.where(Alert.severity == severity)
        statement = _matching(statement, search)
        statement = _within(statement, window)
        # Newest first, which is what ix_alerts_created_at is ordered for.
        statement = (
            statement.order_by(Alert.created_at.desc())
            .limit(min(limit, MAX_PAGE_SIZE))
            .offset(offset)
        )
        return list(self._session.scalars(statement))

    def for_export(
        self,
        *,
        status: AlertStatus | None = None,
        severity: Severity | None = None,
        search: AddressQuery | TechniqueQuery | None = None,
        window: TimeRange | None = None,
        limit: int = MAX_EXPORT_ROWS,
    ) -> list[dict]:
        """The same feed, flattened for a file, with the score and the model that
        produced it.

        The score is joined in rather than left to the detail view, because a table
        of alerts with no risk score beside them is the one thing this system exists
        to add. Outer joins throughout: an alert from Suricata or Wazuh has no
        detection and no model, and dropping those rows would produce an export
        that disagrees with the feed it was taken from.

        One row more than asked for is fetched, so the caller can tell a truncated
        export from one that happened to fill the cap exactly.
        """
        statement = (
            select(
                Alert,
                Detection.risk_score,
                MLModel.name,
                MLModel.version,
            )
            .outerjoin(Detection, Detection.detection_id == Alert.detection_id)
            .outerjoin(MLModel, MLModel.model_id == Detection.model_id)
        )
        if status is not None:
            statement = statement.where(Alert.status == status)
        if severity is not None:
            statement = statement.where(Alert.severity == severity)
        statement = _matching(statement, search)
        statement = _within(statement, window)
        statement = statement.order_by(Alert.created_at.desc()).limit(
            min(limit, MAX_EXPORT_ROWS) + 1
        )

        return [
            {
                "alert_id": alert.alert_id,
                "created_at": alert.created_at,
                "severity": alert.severity.value,
                "status": alert.status.value,
                "source": alert.source,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "mitre_technique": alert.mitre_technique,
                "risk_score": risk_score,
                "model": f"{name} {version}" if name else None,
                "incident_id": alert.incident_id,
            }
            for alert, risk_score, name, version in self._session.execute(statement)
        ]

    def summary(self, top: int = 5) -> dict:
        """Counts over every alert, for a page that has to say how things stand.

        Aggregated here rather than by paging the feed: the overview must be right
        about the whole estate, not about the newest fifty rows.
        """
        def counted(column) -> dict:
            return dict(
                self._session.execute(select(column, func.count()).group_by(column)).all()
            )

        by_severity = counted(Alert.severity)
        by_status = counted(Alert.status)
        sources = self._session.execute(
            select(Alert.src_ip, func.count().label("n"))
            .where(Alert.src_ip.is_not(None))
            .group_by(Alert.src_ip)
            .order_by(func.count().desc(), Alert.src_ip)
            .limit(top)
        ).all()
        return {
            "total": sum(by_severity.values()),
            "by_severity": {s.value: n for s, n in by_severity.items()},
            "by_status": {s.value: n for s, n in by_status.items()},
            "top_sources": [{"address": str(ip), "alerts": n} for ip, n in sources],
        }

    def per_minute(self, since: datetime) -> dict[datetime, int]:
        """Alerts raised in each minute from ``since`` on, keyed by the minute.

        Minutes with none are absent; the caller knows which minutes it asked about.
        The range is on ``created_at`` itself, so ix_alerts_created_at serves it.
        """
        # 'minute' as a literal rather than a bound parameter, so the SELECT and the
        # GROUP BY are the same text however the driver numbers parameters. Two
        # different placeholders would be two expressions, and PostgreSQL would
        # refuse the query.
        minute = func.date_trunc(literal_column("'minute'"), Alert.created_at)
        return dict(
            self._session.execute(
                select(minute, func.count())
                .where(Alert.created_at >= since)
                .group_by(minute)
            ).all()
        )

    def get(self, alert_id: int) -> Alert | None:
        return self._session.scalar(
            select(Alert)
            .options(joinedload(Alert.detection), joinedload(Alert.iocs))
            .where(Alert.alert_id == alert_id)
        )

    def detection_for(self, alert: Alert) -> Detection | None:
        return alert.detection

    def latest_summary(self, alert: Alert) -> CopilotSummary | None:
        """The newest summary that passed its schema. A rejected one is evidence about
        the model, kept for review and never served as an explanation."""
        return self._session.scalar(
            select(CopilotSummary)
            .where(CopilotSummary.alert_id == alert.alert_id, CopilotSummary.schema_valid)
            .order_by(CopilotSummary.summary_id.desc())
            .limit(1)
        )

    def set_status(self, alert: Alert, status: AlertStatus) -> Alert:
        alert.status = status
        return alert


class AssetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def list(self, limit: int = 50, offset: int = 0) -> list[Asset]:
        return list(
            self._session.scalars(
                select(Asset)
                .order_by(Asset.hostname)
                .limit(min(limit, MAX_PAGE_SIZE))
                .offset(offset)
            )
        )

    def get(self, asset_id: int) -> Asset | None:
        return self._session.get(Asset, asset_id)

    def vulnerabilities(self, asset: Asset) -> list[Vulnerability]:
        """What a scan found on this host, worst first.

        Ordered by score rather than by date because the question asked of this
        list is which host to patch first, and NULLS LAST keeps a finding with no
        score from sitting above a critical one.
        """
        return list(
            self._session.scalars(
                select(Vulnerability)
                .where(Vulnerability.asset_id == asset.asset_id)
                .order_by(Vulnerability.cvss.desc().nullslast(),
                          Vulnerability.cve_id)
            )
        )


class ActionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, action_id: int) -> ResponseAction | None:
        return self._session.scalar(
            select(ResponseAction)
            .options(joinedload(ResponseAction.approval))
            .where(ResponseAction.action_id == action_id)
        )

    def iris_case_for(self, action: ResponseAction) -> int | None:
        """The IRIS case this action's alert is being worked in, if there is one.

        None is the ordinary answer, not an error: most alerts are never escalated,
        and an alert whose incident has no case has one because IRIS was
        unreachable when it was escalated. Both mean the same thing here - there is
        no timeline to write to.
        """
        from netsentinel_api.db.models import Incident

        return self._session.scalar(
            select(Incident.iris_case_id)
            .join(Alert, Alert.incident_id == Incident.incident_id)
            .where(Alert.alert_id == action.alert_id)
        )

    def pending(self, limit: int = 50) -> list[ResponseAction]:
        """The approval queue the analyst works through."""
        from netsentinel_api.db.models import ActionStatus

        return list(
            self._session.scalars(
                select(ResponseAction)
                .options(joinedload(ResponseAction.approval))
                .where(ResponseAction.status == ActionStatus.pending_approval)
                .order_by(ResponseAction.action_id)
                .limit(min(limit, MAX_PAGE_SIZE))
            )
        )

    def approved(self, limit: int = 50) -> list[ResponseAction]:
        """The execution queue the responder drains.

        The approval is loaded with the action, not left to lazy loading: the gate
        refuses an action whose approval it cannot see, and an execution that fails
        because a relationship was not populated would look exactly like one a human
        never authorised.
        """
        from netsentinel_api.db.models import ActionStatus

        return list(
            self._session.scalars(
                select(ResponseAction)
                .options(joinedload(ResponseAction.approval))
                .where(ResponseAction.status == ActionStatus.approved)
                # Oldest first: the queue is worked in the order it was approved.
                .order_by(ResponseAction.action_id)
                .limit(min(limit, MAX_PAGE_SIZE))
            )
        )

    def rollback_requested(self, limit: int = 50) -> list[ResponseAction]:
        """The undo queue the responder drains.

        A second queue rather than a status argument on ``approved``: the two are
        worked by different code paths, because an undo that fails is retried
        where an execution that fails is not.
        """
        from netsentinel_api.db.models import ActionStatus

        return list(
            self._session.scalars(
                select(ResponseAction)
                .options(joinedload(ResponseAction.approval))
                .where(ResponseAction.status == ActionStatus.rollback_requested)
                .order_by(ResponseAction.action_id)
                .limit(min(limit, MAX_PAGE_SIZE))
            )
        )


class ModelRepository:
    """The registry, and the evidence a promotion is decided on.

    The shadow queries live here rather than beside the report they were first
    written for. The dashboard now asks the same questions the CLI does, and two
    copies of this join would be two definitions of what a label is - which is the
    one thing a promotion argument cannot afford.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    def list(self) -> list[MLModel]:
        # By id, which is registration order: the tiers read down the page in the
        # order somebody added them, and a model does not move when it is promoted.
        return list(self._session.scalars(select(MLModel).order_by(MLModel.model_id)))

    def get(self, model_id: int) -> MLModel | None:
        return self._session.get(MLModel, model_id)

    def active_for(self, tier: ModelTier) -> MLModel | None:
        """The model currently deciding for this tier, if one is."""
        return self._session.scalar(
            select(MLModel).where(MLModel.tier == tier, MLModel.mode == ModelMode.active)
        )

    def labels_by_flow(self, start: datetime) -> dict[str, bool]:
        """The analyst's conclusion per flow, from the alerts they closed.

        A flow with two alerts closed differently is counted as a true positive: an
        analyst concluding that something was there outranks another concluding it
        was not, and the alternative is dropping the flow that generated the
        disagreement - which is the most informative one in the set.
        """
        rows = self._session.execute(
            select(Detection.flow_id, Alert.status)
            .join(Alert, Alert.detection_id == Detection.detection_id)
            .where(Alert.status.in_(list(LABELS)), Detection.created_at >= start)
        )

        labels: dict[str, bool] = {}
        for flow_id, status in rows:
            label = LABELS[status]
            labels[flow_id] = labels.get(flow_id, False) or label
        return labels

    def scored_since(self, start: datetime) -> list[Scored]:
        """Every verdict recorded in the window, carrying its label if it has one.

        Labels are joined on ``flow_id``, not on the model: a shadow model raises no
        alert of its own, so what it has is a score on a flow some other model
        alerted on, and the analyst's verdict on that alert applies to every model
        that scored it.
        """
        labels = self.labels_by_flow(start)
        return [
            Scored(
                model_id=model_id,
                risk_score=risk_score,
                created_at=created_at,
                label=labels.get(flow_id),
            )
            for model_id, risk_score, created_at, flow_id in self._session.execute(
                select(
                    Detection.model_id,
                    Detection.risk_score,
                    Detection.created_at,
                    Detection.flow_id,
                ).where(Detection.created_at >= start)
            )
        ]


class AdminRepository:
    """Accounts, sensors and the audit trail, for the administrator's page."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def users(self) -> list[User]:
        return list(
            self._session.scalars(
                select(User).options(joinedload(User.role)).order_by(User.username)
            )
        )

    def user(self, user_id: int) -> User | None:
        return self._session.scalar(
            select(User).options(joinedload(User.role)).where(User.user_id == user_id)
        )

    def taken(self, username: str, email: str) -> bool:
        """Whether either is already in use; both columns are UNIQUE."""
        return (
            self._session.scalar(
                select(User.user_id).where(or_(User.username == username, User.email == email))
            )
            is not None
        )

    def roles(self) -> list[Role]:
        return list(self._session.scalars(select(Role).order_by(Role.name)))

    def role(self, name: str) -> Role | None:
        return self._session.scalar(select(Role).where(Role.name == name))

    def sensors(self) -> list[tuple[Sensor, str]]:
        """Every sensor with the hostname it runs on."""
        return [
            (sensor, hostname)
            for sensor, hostname in self._session.execute(
                select(Sensor, Asset.hostname)
                .join(Asset, Asset.asset_id == Sensor.host_asset_id)
                .order_by(Sensor.sensor_id)
            )
        ]

    def sensor(self, sensor_id: int) -> tuple[Sensor, str] | None:
        row = self._session.execute(
            select(Sensor, Asset.hostname)
            .join(Asset, Asset.asset_id == Sensor.host_asset_id)
            .where(Sensor.sensor_id == sensor_id)
        ).first()
        return (row[0], row[1]) if row is not None else None

    def audit(
        self,
        *,
        actor: str | None = None,
        action: str | None = None,
        window: TimeRange | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[tuple[AuditLog, str | None]]:
        """Newest first, with the actor's username; None for a system action.

        ``action`` matches as a prefix, so ``user.`` finds every account change.
        On ``ts`` itself, so ix_audit_log_ts serves the range and the order.
        """
        statement = select(AuditLog, User.username).outerjoin(
            User, User.user_id == AuditLog.user_id
        )
        if actor:
            statement = statement.where(User.username == actor)
        if action:
            statement = statement.where(AuditLog.action.startswith(action, autoescape=True))
        if window is not None and window.start is not None:
            statement = statement.where(AuditLog.ts >= window.start)
        if window is not None and window.end is not None:
            statement = statement.where(AuditLog.ts <= window.end)
        statement = (
            statement.order_by(AuditLog.ts.desc(), AuditLog.log_id.desc())
            .limit(min(limit, MAX_PAGE_SIZE))
            .offset(offset)
        )
        return [(entry, username) for entry, username in self._session.execute(statement)]
