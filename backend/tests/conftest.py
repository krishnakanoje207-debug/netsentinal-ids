"""API test fixtures.

The suite runs with no PostgreSQL. Routes take repositories as dependencies, so
those are overridden with in-memory fakes, and the one direct session use -
``current_user`` loading the caller - is served by a fake whose ``scalar`` returns
the configured user.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterator

import pytest
from fastapi.testclient import TestClient

from netsentinel_api.app import create_app
from netsentinel_api.config import Settings, get_settings
from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    Alert,
    AlertStatus,
    AuditLog,
    Detection,
    IoC,
    IoCType,
    ResponseAction,
    Role,
    Severity,
    User,
)
from netsentinel_api.db.session import get_session
from netsentinel_api.deps import get_action_repo, get_alert_repo, get_user_repo
from netsentinel_api.rbac import DEFAULT_ROLE_PERMISSIONS, ML_ENGINEER, SOC_ANALYST, as_column
from netsentinel_api.security import create_access_token, hash_password

TEST_SECRET = "K7vQp2xR9mLt4wZn6bYc3sEdJf8hGa1uNqXrVoWiTyBk5Pz0"
ANALYST_PASSWORD = "an-analyst-password"
ENGINEER_PASSWORD = "a-modeller-password"

# Hashed once per session. bcrypt is deliberately slow, and re-hashing inside every
# fixture made the API suite take 24s instead of 3s.
ANALYST_HASH = hash_password(ANALYST_PASSWORD)
ENGINEER_HASH = hash_password(ENGINEER_PASSWORD)

NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def analyst_password() -> str:
    """Exposed as a fixture so no test imports this module by name."""
    return ANALYST_PASSWORD


@pytest.fixture
def settings() -> Settings:
    return Settings(jwt_secret=TEST_SECRET)


class FakeSession:
    """Collects writes; answers the single read current_user performs."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.user: User | None = None
        self.committed = False

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def scalar(self, *_args, **_kwargs) -> User | None:
        return self.user

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:  # pragma: no cover - only on an unexpected error
        pass

    def close(self) -> None:
        pass

    def audit_entries(self) -> list[AuditLog]:
        return [o for o in self.added if isinstance(o, AuditLog)]


class FakeUserRepo:
    def __init__(self, users: dict[str, User]) -> None:
        self._users = users

    def by_username(self, username: str) -> User | None:
        return self._users.get(username)


class FakeAlertRepo:
    def __init__(self, alerts: list[Alert]) -> None:
        self.alerts = alerts

    def list(self, *, status=None, severity=None, limit=50, offset=0):
        rows = self.alerts
        if status is not None:
            rows = [a for a in rows if a.status == status]
        if severity is not None:
            rows = [a for a in rows if a.severity == severity]
        return rows[offset : offset + limit]

    def get(self, alert_id: int) -> Alert | None:
        return next((a for a in self.alerts if a.alert_id == alert_id), None)

    def set_status(self, alert: Alert, status: AlertStatus) -> Alert:
        alert.status = status
        return alert


class FakeActionRepo:
    def __init__(self, actions: list[ResponseAction]) -> None:
        self.actions = actions

    def get(self, action_id: int) -> ResponseAction | None:
        return next((a for a in self.actions if a.action_id == action_id), None)

    def pending(self, limit: int = 50) -> list[ResponseAction]:
        return [a for a in self.actions
                if a.status == ActionStatus.pending_approval][:limit]


def _role(name: str) -> Role:
    return Role(role_id=1, name=name, permissions=as_column(DEFAULT_ROLE_PERMISSIONS[name]))


@pytest.fixture
def analyst() -> User:
    return User(
        user_id=1,
        username="analyst",
        email="analyst@example.test",
        password_hash=ANALYST_HASH,
        role_id=1,
        is_active=True,
        role=_role(SOC_ANALYST),
    )


@pytest.fixture
def ml_engineer() -> User:
    return User(
        user_id=2,
        username="modeller",
        email="modeller@example.test",
        password_hash=ENGINEER_HASH,
        role_id=2,
        is_active=True,
        role=_role(ML_ENGINEER),
    )


@pytest.fixture
def detection() -> Detection:
    return Detection(
        detection_id=10,
        flow_id="10.0.0.5:44321-10.0.0.9:80-6",
        sensor_id=1,
        model_id=1,
        risk_score=0.93,
        model_scores={"tier_a": 0.93, "tier_d": 0.71},
        # Deliberately unordered, and mixing signs, so the detail view has to rank
        # by absolute contribution.
        shap_values={"duration_ms": -0.11, "pkt_rate": 0.42, "in_bytes": 0.05},
        shadow=False,
    )


@pytest.fixture
def alert(detection: Detection) -> Alert:
    return Alert(
        alert_id=100,
        detection_id=detection.detection_id,
        asset_id=None,
        incident_id=None,
        source="early_flow",
        severity=Severity.high,
        status=AlertStatus.new,
        src_ip="203.0.113.9",
        dst_ip="10.0.0.9",
        mitre_technique="T1046",
        created_at=NOW,
        detection=detection,
        iocs=[IoC(ioc_id=1, value="203.0.113.9", type=IoCType.ip)],
    )


@pytest.fixture
def action() -> ResponseAction:
    return ResponseAction(
        action_id=500,
        alert_id=100,
        action_type=ActionType.block_ip,
        target="203.0.113.9",
        status=ActionStatus.pending_approval,
    )


@pytest.fixture
def session(analyst: User) -> FakeSession:
    fake = FakeSession()
    fake.user = analyst
    return fake


@pytest.fixture
def client(
    settings: Settings,
    session: FakeSession,
    analyst: User,
    ml_engineer: User,
    alert: Alert,
    action: ResponseAction,
) -> Iterator[TestClient]:
    app = create_app()

    def _session() -> Iterator[FakeSession]:
        yield session

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_user_repo] = lambda: FakeUserRepo(
        {analyst.username: analyst, ml_engineer.username: ml_engineer}
    )
    app.dependency_overrides[get_alert_repo] = lambda: FakeAlertRepo([alert])
    app.dependency_overrides[get_action_repo] = lambda: FakeActionRepo([action])

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_header(settings: Settings, analyst: User) -> dict[str, str]:
    token = create_access_token(settings, analyst.user_id, SOC_ANALYST)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def engineer_header(settings: Settings, ml_engineer: User, session: FakeSession) -> dict[str, str]:
    """Authenticates as the ML engineer, who cannot triage or approve."""
    session.user = ml_engineer
    token = create_access_token(settings, ml_engineer.user_id, ML_ENGINEER)
    return {"Authorization": f"Bearer {token}"}
