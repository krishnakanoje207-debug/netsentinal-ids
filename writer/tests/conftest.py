"""Fixtures for the writer.

A real LightGBM booster rather than a stub. The thing most worth proving here is
that a contribution really lands under the feature name it belongs to, and a fake
explainer would prove nothing about that - it would only restate the mapping the
test itself wrote.

The database is faked, though. What the writer decides is the interesting part; that
SQLAlchemy can insert a row is not.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from netsentinel_api.db.models import Alert, Detection
from netsentinel_core.features.contract import FEATURE_DIM, TIER_A_FEATURES

VERSION = "0.1.0-test"
MODEL_NAME = "tier_a_lightgbm"
THRESHOLD = 0.5


def _training_frame(rows: int = 800, seed: int = 11):
    """Two populations separated by one feature, so the explanation is checkable.

    ``duration_ms`` carries the signal and nothing else does, which means TreeSHAP
    has exactly one feature it can credit. A test that asserts on a specific feature
    name needs the model to have a defensible reason to name it.
    """
    rng = np.random.default_rng(seed)
    is_attack = rng.random(rows) < 0.4
    x = rng.normal(50, 5, size=(rows, len(TIER_A_FEATURES)))
    duration_index = TIER_A_FEATURES.index("duration_ms")
    x[:, duration_index] = np.where(is_attack, rng.normal(5, 1, rows), rng.normal(900, 40, rows))
    return x, is_attack.astype(int)


@pytest.fixture(scope="session")
def artefacts(tmp_path_factory):
    """A trained booster plus the card that pins it, as training would emit them."""
    import hashlib

    import lightgbm as lgb

    out = tmp_path_factory.mktemp("tier_a")
    x, y = _training_frame()
    model = lgb.LGBMClassifier(n_estimators=40, num_leaves=8, verbose=-1)
    model.fit(x, y)

    booster_path = out / "tier_a.lgb.txt"
    model.booster_.save_model(str(booster_path))

    card = {
        "name": MODEL_NAME,
        "tier": "A",
        "version": VERSION,
        "onnx_sha256": "0" * 64,
        "booster_sha256": hashlib.sha256(booster_path.read_bytes()).hexdigest(),
        "threshold": THRESHOLD,
        "mode": "shadow",
        "feature_order": list(TIER_A_FEATURES),
    }
    (out / "model_card.json").write_text(json.dumps(card), encoding="utf-8")
    return out


@pytest.fixture(scope="session")
def explainer(artefacts):
    from netsentinel_writer.explain import load_explainer

    return load_explainer(artefacts / "model_card.json")


def _make_flow(**overrides) -> dict:
    """A flow row shaped like the one the sensor publishes."""
    flow = {
        "flow_id": "10.0.0.5:44321-10.0.0.9:80-6",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.9",
        "src_port": 44321,
        "dst_port": 80,
        "sensor": "early_flow",
    }
    flow.update({name: 50.0 for name in TIER_A_FEATURES})
    flow.update(overrides)
    return flow


def _make_payload(
    *,
    risk_score: float | None = 0.9,
    threshold: float | None = THRESHOLD,
    shadow: bool = False,
    is_alert: bool = True,
    model_scores: dict | None = None,
    models: list | None = None,
    features: int = FEATURE_DIM,
    flow: dict | None = None,
) -> dict:
    return {
        "flow": flow if flow is not None else _make_flow(),
        "verdict": {
            "risk_score": risk_score,
            "threshold": threshold,
            "model_scores": model_scores if model_scores is not None else {"tier_a": 0.9},
            "decided_by": [] if shadow else [f"{MODEL_NAME}:{VERSION}"],
            "shadow": shadow,
            "undecided": risk_score is None,
            "is_alert": is_alert,
        },
        "models": models
        if models is not None
        else [
            {
                "tier": "A",
                "name": MODEL_NAME,
                "version": VERSION,
                "mode": "shadow" if shadow else "active",
            }
        ],
        "contract": {"features": features},
    }


@pytest.fixture(scope="session")
def make_flow():
    """Handed out as a fixture rather than imported.

    Test directories are not packages, so ``from conftest import ...`` resolves
    through whichever conftest reached sys.modules first - a collision that is
    invisible in one directory's run and breaks the full suite.
    """
    return _make_flow


@pytest.fixture(scope="session")
def make_payload():
    return _make_payload


class FakeSession:
    """Collects what was added. Hands out identities on flush, like the real one.

    ``iocs`` is what an IoC lookup returns, so an enrichment test seeds the table by
    assigning to it rather than by running a query.
    """

    def __init__(self) -> None:
        self.added: list = []
        self.iocs: list = []
        self.flushes = 0
        self.commits = 0
        self.closed = False

    def add(self, instance, /) -> None:
        self.added.append(instance)

    def flush(self) -> None:
        self.flushes += 1
        for index, row in enumerate(self.added, start=1):
            if isinstance(row, Detection) and row.detection_id is None:
                row.detection_id = index
            if isinstance(row, Alert) and row.alert_id is None:
                row.alert_id = index

    def scalars(self, _statement):
        return list(self.iocs)

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False


@pytest.fixture
def session() -> FakeSession:
    return FakeSession()
