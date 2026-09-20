"""Fixtures for the end-to-end chain.

Everything real except the four edges: the bus, the database, and the two systems
this one talks out to. Those are fakes because a test that needs Redpanda,
PostgreSQL, IRIS and CrowdSec running is a test nobody runs.

The explainer is a stub here, and deliberately. What TreeSHAP computes is covered
in ``writer/tests`` against a real booster; what this suite is for is the chain -
that a scored flow becomes a detection, an alert, an enriched alert, a case, a
proposal, an approval and a block, in that order and with nothing skipped.
"""

from __future__ import annotations

import pytest
from netsentinel_api.db.models import (
    Alert,
    Asset,
    AuditLog,
    Criticality,
    Detection,
    Incident,
    IoC,
    IoCType,
    ResponseAction,
    Role,
    User,
)
from netsentinel_api.rbac import (
    ADMINISTRATOR,
    DEFAULT_ROLE_PERMISSIONS,
    SOC_ANALYST,
    as_column,
)
from netsentinel_core.features.contract import FEATURE_DIM, TIER_A_FEATURES

MODEL_NAME = "tier_a_lightgbm"
VERSION = "0.1.0-e2e"
THRESHOLD = 0.5
SENSOR_ID, MODEL_ID = 3, 7

#: The attacker in every scenario below, and the host it goes after.
ATTACKER = "203.0.113.9"
VICTIM = "172.30.0.10"


class StubExplainer:
    """The slice of ``writer.explain.Explainer`` the writer actually uses."""

    name, tier, version, threshold = MODEL_NAME, "A", VERSION, THRESHOLD

    @property
    def identity(self) -> str:
        return f"{self.name}:{self.version}"

    def explain(self, flow) -> dict[str, float]:
        # Shaped like a real explanation - one contribution per contract feature -
        # so the writer's NOT NULL rule is exercised with something of the right
        # size rather than an empty dict.
        return {name: 0.01 for name in TIER_A_FEATURES}


class FakeSession:
    """One session for the whole chain, so later steps see earlier rows."""

    def __init__(self) -> None:
        self.added: list = []
        self.iocs: list = []
        self.commits = 0
        self.case_id: int | None = None
        self.user: User | None = None
        self._next_id = 0

    def add(self, instance, /) -> None:
        self.added.append(instance)

    def flush(self) -> None:
        for row in self.added:
            if isinstance(row, Detection) and row.detection_id is None:
                row.detection_id = self._identity()
            elif isinstance(row, Alert) and row.alert_id is None:
                row.alert_id = self._identity()
            elif isinstance(row, Incident) and row.incident_id is None:
                row.incident_id = self._identity()
            elif isinstance(row, ResponseAction) and row.action_id is None:
                row.action_id = self._identity()

    def _identity(self) -> int:
        self._next_id += 1
        return self._next_id

    def scalars(self, _statement=None):
        # The one query the writer makes: the indicators to match an alert against.
        return list(self.iocs)

    def scalar(self, *_args, **_kwargs):
        # The one the responder makes: the IRIS case behind an action.
        return self.case_id

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:  # pragma: no cover - the chain does not fail
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def rows(self, kind):
        return [row for row in self.added if isinstance(row, kind)]

    def audit_actions(self) -> list[str]:
        return [row.action for row in self.rows(AuditLog)]


class StubKeep:
    def __init__(self) -> None:
        self.sent: list = []

    def send(self, alert, iocs=()) -> None:
        self.sent.append((alert, list(iocs)))


class StubIris:
    def __init__(self, case_id: int = 4242) -> None:
        self.case_id = case_id
        self.cases: list = []
        self.timeline: list = []

    def create_case(self, alert, title, description) -> int:
        self.cases.append((alert.alert_id, title, description))
        return self.case_id

    def add_timeline_event(self, case_id: int, event: dict) -> None:
        self.timeline.append((case_id, event))


class StubEnforcer:
    def __init__(self) -> None:
        self.applied: list = []
        self.undone: list = []

    def apply(self, action) -> dict:
        self.applied.append((action.action_type.value, action.target))
        return {"backend": "stub"}

    def undo(self, action) -> dict:
        self.undone.append((action.action_type.value, action.target))
        return {"backend": "stub"}


@pytest.fixture
def session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def attacker() -> str:
    return ATTACKER


@pytest.fixture
def victim() -> str:
    return VICTIM


@pytest.fixture
def run_writer(session, keep):
    """The writer, consuming one batch from a replayed topic.

    Handed out as a fixture rather than imported: test directories are not
    packages, so ``from conftest import ...`` resolves through whichever conftest
    reached sys.modules first - invisible in one directory's run, broken in the
    full suite.
    """
    from netsentinel_writer.consumer import ReplayConsumer
    from netsentinel_writer.writer import DetectionWriter

    def _run(payloads, iocs=()):
        session.iocs = list(iocs)
        writer = DetectionWriter(
            lambda: session, StubExplainer(), SENSOR_ID, MODEL_ID, forwarder=keep
        )
        writer.run(ReplayConsumer(list(payloads)))
        return session

    return _run


@pytest.fixture
def keep() -> StubKeep:
    return StubKeep()


@pytest.fixture
def iris() -> StubIris:
    return StubIris()


@pytest.fixture
def enforcer() -> StubEnforcer:
    return StubEnforcer()


def _user(user_id: int, username: str, role_name: str) -> User:
    return User(
        user_id=user_id,
        username=username,
        email=f"{username}@example.test",
        password_hash="x",
        role_id=user_id,
        is_active=True,
        role=Role(role_id=user_id, name=role_name,
                  permissions=as_column(DEFAULT_ROLE_PERMISSIONS[role_name])),
    )


@pytest.fixture
def analyst() -> User:
    """Triages, escalates, approves. Cannot propose."""
    return _user(1, "analyst", SOC_ANALYST)


@pytest.fixture
def administrator() -> User:
    """Proposes. Cannot approve."""
    return _user(2, "admin", ADMINISTRATOR)


@pytest.fixture
def estate() -> list[Asset]:
    return [
        Asset(asset_id=1, hostname="victim-web", ip_address=VICTIM, os="alpine",
              criticality=Criticality.high)
    ]


@pytest.fixture
def known_bad() -> IoC:
    """The attacker, already in the IoC table from a MISP sync."""
    return IoC(ioc_id=1, value=ATTACKER, type=IoCType.ip, misp_event_id=99,
               threat_level=1)


@pytest.fixture
def scenario():
    """A scored flow as the sensor publishes it, per attack scenario."""

    def _payload(flow_id: str, risk_score: float = 0.93) -> dict:
        # No technique: nothing in the ML path assigns one. See
        # test_an_ml_alert_carries_no_technique_yet.
        flow = {
            "flow_id": flow_id,
            "src_ip": ATTACKER,
            "dst_ip": VICTIM,
            "src_port": 44321,
            "dst_port": 443,
            "sensor": "early_flow",
        }
        flow.update({name: 50.0 for name in TIER_A_FEATURES})
        return {
            "flow": flow,
            "verdict": {
                "risk_score": risk_score,
                "threshold": THRESHOLD,
                "model_scores": {"tier_a": risk_score},
                "decided_by": [f"{MODEL_NAME}:{VERSION}"],
                "shadow": False,
                "undecided": False,
                "is_alert": risk_score >= THRESHOLD,
            },
            "models": [
                {"tier": "A", "name": MODEL_NAME, "version": VERSION, "mode": "active"}
            ],
            "contract": {"features": FEATURE_DIM},
        }

    return _payload
