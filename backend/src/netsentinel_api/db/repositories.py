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

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from netsentinel_api.db.models import (
    Alert,
    AlertStatus,
    Asset,
    Detection,
    MLModel,
    ModelMode,
    ModelTier,
    ResponseAction,
    Severity,
    User,
    Vulnerability,
)
from netsentinel_api.services.shadow import LABELS, Scored

#: Cap on a page of alerts. A SOC feed is unbounded; a response must not be.
MAX_PAGE_SIZE = 200


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
        limit: int = 50,
        offset: int = 0,
    ) -> list[Alert]:
        statement = select(Alert)
        if status is not None:
            statement = statement.where(Alert.status == status)
        if severity is not None:
            statement = statement.where(Alert.severity == severity)
        # Newest first, which is what ix_alerts_created_at is ordered for.
        statement = (
            statement.order_by(Alert.created_at.desc())
            .limit(min(limit, MAX_PAGE_SIZE))
            .offset(offset)
        )
        return list(self._session.scalars(statement))

    def get(self, alert_id: int) -> Alert | None:
        return self._session.scalar(
            select(Alert)
            .options(joinedload(Alert.detection), joinedload(Alert.iocs))
            .where(Alert.alert_id == alert_id)
        )

    def detection_for(self, alert: Alert) -> Detection | None:
        return alert.detection

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
