"""Data access, kept out of the route handlers.

Two reasons, in order of importance:

1. A route that builds its own queries cannot be tested without a database. These
   classes are injected, so the API tests run against fakes and the suite needs no
   PostgreSQL.
2. Query shapes stay in one place, which is where the indexes from M2 section 3.2
   can be honoured deliberately rather than by accident.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from netsentinel_api.db.models import (
    Alert,
    AlertStatus,
    Detection,
    ResponseAction,
    Severity,
    User,
)

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


class ActionRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def get(self, action_id: int) -> ResponseAction | None:
        return self._session.scalar(
            select(ResponseAction)
            .options(joinedload(ResponseAction.approval))
            .where(ResponseAction.action_id == action_id)
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
