"""API test fixtures.

The suite runs with no PostgreSQL. Routes take repositories as dependencies, so
those are overridden with in-memory fakes, and the one direct session use -
``current_user`` loading the caller - is served by a fake whose ``scalar`` returns
the configured user.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
    Asset,
    AuditLog,
    Criticality,
    Detection,
    Incident,
    IoC,
    IoCType,
    MLModel,
    ModelMode,
    ModelTier,
    ResponseAction,
    Role,
    Severity,
    User,
    Vulnerability,
)
from netsentinel_api.db.session import get_session
from netsentinel_api.deps import (
    get_action_repo,
    get_alert_repo,
    get_asset_repo,
    get_model_repo,
    get_user_repo,
)
from netsentinel_api.rbac import (
    ADMINISTRATOR,
    DEFAULT_ROLE_PERMISSIONS,
    ML_ENGINEER,
    SOC_ANALYST,
    as_column,
)
from netsentinel_api.security import create_access_token, hash_password
from netsentinel_api.services.shadow import Scored

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
        self._last_id = 900

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def flush(self) -> None:
        """Hand out the primary keys a real flush would.

        Escalation needs the incident's id before it can point the alert at it, and
        a proposal needs the action's before it can be returned to whoever will
        approve it. A flush that changed nothing would hide the bug it exists to
        prevent.
        """
        for instance in self.added:
            if isinstance(instance, Incident) and instance.incident_id is None:
                self._last_id += 1
                instance.incident_id = self._last_id
            elif isinstance(instance, ResponseAction) and instance.action_id is None:
                self._last_id += 1
                instance.action_id = self._last_id

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

    def _filtered(self, status, severity) -> list[Alert]:
        rows = self.alerts
        if status is not None:
            rows = [a for a in rows if a.status == status]
        if severity is not None:
            rows = [a for a in rows if a.severity == severity]
        return rows

    def list(self, *, status=None, severity=None, limit=50, offset=0):
        return self._filtered(status, severity)[offset : offset + limit]

    def for_export(self, *, status=None, severity=None, limit=10_000) -> list[dict]:
        """Flattened the way the real join flattens it, including the extra row.

        The cap is applied as ``limit + 1`` here too, because the route reads the
        length of what comes back to decide whether the export was truncated. A fake
        that quietly returned exactly ``limit`` rows would make that branch
        untestable and the truncation notice permanently false.
        """
        rows = []
        for alert in self._filtered(status, severity)[: limit + 1]:
            detection = alert.detection
            rows.append(
                {
                    "alert_id": alert.alert_id,
                    "created_at": alert.created_at,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "source": alert.source,
                    "src_ip": alert.src_ip,
                    "dst_ip": alert.dst_ip,
                    "mitre_technique": alert.mitre_technique,
                    "risk_score": detection.risk_score if detection else None,
                    "model": "tier-a-lgbm 1.0.0" if detection else None,
                    "incident_id": alert.incident_id,
                }
            )
        return rows

    def get(self, alert_id: int) -> Alert | None:
        return next((a for a in self.alerts if a.alert_id == alert_id), None)

    def set_status(self, alert: Alert, status: AlertStatus) -> Alert:
        alert.status = status
        return alert


class FakeAssetRepo:
    def __init__(self, assets: list[Asset], vulns: list[Vulnerability]) -> None:
        self.assets = assets
        self.vulns = vulns

    def list(self, limit: int = 50, offset: int = 0) -> list[Asset]:
        return self.assets[offset : offset + limit]

    def get(self, asset_id: int) -> Asset | None:
        return next((a for a in self.assets if a.asset_id == asset_id), None)

    def vulnerabilities(self, asset: Asset) -> list[Vulnerability]:
        rows = [v for v in self.vulns if v.asset_id == asset.asset_id]
        # Worst first, as the repository's ORDER BY does.
        return sorted(rows, key=lambda v: (v.cvss is None, -(v.cvss or 0), v.cve_id))


class FakeActionRepo:
    def __init__(self, actions: list[ResponseAction]) -> None:
        self.actions = actions

    def get(self, action_id: int) -> ResponseAction | None:
        return next((a for a in self.actions if a.action_id == action_id), None)

    def pending(self, limit: int = 50) -> list[ResponseAction]:
        return [a for a in self.actions
                if a.status == ActionStatus.pending_approval][:limit]


class FakeModelRepo:
    """The registry plus the verdicts it would be judged on.

    ``scored_since`` filters the verdicts by the window the same way the real
    query's WHERE clause does, so a test can prove the window is actually applied
    rather than accepted and ignored.
    """

    def __init__(self, models: list[MLModel], scored: list[Scored]) -> None:
        self.models = models
        self.scored = scored

    def list(self) -> list[MLModel]:
        return sorted(self.models, key=lambda m: m.model_id)

    def get(self, model_id: int) -> MLModel | None:
        return next((m for m in self.models if m.model_id == model_id), None)

    def active_for(self, tier: ModelTier) -> MLModel | None:
        return next(
            (m for m in self.models if m.tier == tier and m.mode == ModelMode.active),
            None,
        )

    def scored_since(self, start: datetime) -> list[Scored]:
        return [s for s in self.scored if s.created_at >= start]


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
def administrator() -> User:
    """Proposes actions, and deliberately cannot approve them."""
    return User(
        user_id=3,
        username="admin",
        email="admin@example.test",
        password_hash=ENGINEER_HASH,
        role_id=3,
        is_active=True,
        role=_role(ADMINISTRATOR),
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
def alerts(alert: Alert) -> list[Alert]:
    """The feed the repository serves.

    A list rather than the single ``alert`` fixture, so a test that needs more than
    one - an export hitting its cap, for instance - can append to it instead of
    rebuilding the application.
    """
    return [alert]


@pytest.fixture
def asset() -> Asset:
    return Asset(asset_id=1, hostname="victim-web", ip_address="172.30.0.10",
                 os="alpine", criticality=Criticality.high)


@pytest.fixture
def vulnerabilities() -> list[Vulnerability]:
    return [
        Vulnerability(vuln_id=1, asset_id=1, cve_id="CVE-2021-44228", cvss=10.0,
                      detected_at=NOW),
        Vulnerability(vuln_id=2, asset_id=1, cve_id="CVE-2019-0708", cvss=None,
                      detected_at=NOW),
        Vulnerability(vuln_id=3, asset_id=1, cve_id="CVE-2020-1472", cvss=5.5,
                      detected_at=NOW),
    ]


@pytest.fixture
def models() -> list[MLModel]:
    """One model deciding, one observing. The state the page exists to show."""
    return [
        MLModel(model_id=1, name="tier-a-lgbm", tier=ModelTier.A, version="1.0.0",
                onnx_sha256="a" * 64, threshold=0.5, mode=ModelMode.active,
                pr_auc=0.91, deployed_at=NOW - timedelta(days=30)),
        MLModel(model_id=2, name="tier-a-lgbm", tier=ModelTier.A, version="1.1.0",
                onnx_sha256="b" * 64, threshold=0.5, mode=ModelMode.shadow,
                pr_auc=0.94, deployed_at=None),
    ]


@pytest.fixture
def scored() -> list[Scored]:
    """A shadow period the candidate wins: it ranks the true positives above the
    false ones where the incumbent interleaves them.

    Sixty labelled flows over eight days, which clears both default bars, so a test
    that wants a refusal has to create the shortfall deliberately.

    Anchored on the real clock rather than on ``NOW``. The window is computed from
    ``datetime.now``, so a fixture pinned to a date in 2026 would silently fall out
    of every window the day after it was written, and the suite would start
    measuring nothing while still passing.
    """
    latest = datetime.now(timezone.utc) - timedelta(hours=1)
    verdicts: list[Scored] = []
    for index in range(60):
        label = index % 3 == 0
        moment = latest - timedelta(hours=(59 - index) * 3)
        # The incumbent scores the true ones a little above the false ones; the
        # candidate separates them cleanly.
        verdicts.append(Scored(model_id=1, risk_score=0.6 if label else 0.55,
                               created_at=moment, label=label))
        verdicts.append(Scored(model_id=2, risk_score=0.9 if label else 0.1,
                               created_at=moment, label=label))
    return verdicts


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
    administrator: User,
    alerts: list[Alert],
    asset: Asset,
    vulnerabilities: list[Vulnerability],
    action: ResponseAction,
    models: list[MLModel],
    scored: list[Scored],
) -> Iterator[TestClient]:
    app = create_app()

    def _session() -> Iterator[FakeSession]:
        yield session

    app.dependency_overrides[get_settings] = lambda: settings
    app.dependency_overrides[get_session] = _session
    app.dependency_overrides[get_user_repo] = lambda: FakeUserRepo(
        {
            analyst.username: analyst,
            ml_engineer.username: ml_engineer,
            administrator.username: administrator,
        }
    )
    app.dependency_overrides[get_alert_repo] = lambda: FakeAlertRepo(alerts)
    app.dependency_overrides[get_asset_repo] = lambda: FakeAssetRepo(
        [asset], vulnerabilities
    )
    app.dependency_overrides[get_action_repo] = lambda: FakeActionRepo([action])
    app.dependency_overrides[get_model_repo] = lambda: FakeModelRepo(models, scored)

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


@pytest.fixture
def admin_header(settings: Settings, administrator: User, session: FakeSession) -> dict[str, str]:
    """Authenticates as the administrator, who proposes but cannot approve."""
    session.user = administrator
    token = create_access_token(settings, administrator.user_id, ADMINISTRATOR)
    return {"Authorization": f"Bearer {token}"}
