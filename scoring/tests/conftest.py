"""A real trained model to score with.

Rather than mocking an ONNX session, the fixtures train a small LightGBM model on
synthetic flows and export it exactly as the D5 pipeline does. That means these tests
exercise the real loader against a real artefact, including the hash and contract
checks, which is the only way those checks are worth anything.

Named ``scoring_model.py`` values are avoided here: this conftest is the only shared
module in this package, and nothing imports it by name.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES, FlowFeatures, FlowKey

# The fixtures build a genuine artefact with the training toolchain, so the loader
# is tested against a real file rather than a mock. That is a test-time dependency
# only - netsentinel-scoring itself never imports netsentinel-training.
pytest.importorskip("lightgbm", reason="building a Tier A artefact needs the training extras")

ATTACK_RATE = 0.2


def _synthetic(rows: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    is_attack = rng.random(rows) < ATTACK_RATE
    # One clearly separable axis is enough; this model exists to be loaded, not
    # to be evaluated.
    base = rng.normal(0.0, 1.0, (rows, len(TIER_A_FEATURES)))
    base[:, 0] += np.where(is_attack, 8.0, 0.0)
    return base.astype(np.float32), is_attack.astype(np.int8)


def _train_and_export(directory: Path, mode: str, threshold: float = 0.5) -> Path:
    """Train, export to ONNX and write a model card. Returns the card path."""
    import lightgbm as lgb
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    from netsentinel_scoring.registry import sha256_of

    x, y = _synthetic(600, seed=11)
    model = lgb.LGBMClassifier(n_estimators=25, num_leaves=7, verbose=-1)
    model.fit(x, y)

    onnx_path = directory / "tier_a.onnx"
    onnx_model = convert_lightgbm(
        model,
        initial_types=[("input", FloatTensorType([None, len(TIER_A_FEATURES)]))],
        zipmap=False,
    )
    onnx_path.write_bytes(onnx_model.SerializeToString())

    card_path = directory / "model_card.json"
    card_path.write_text(
        json.dumps(
            {
                "name": "tier_a_lightgbm",
                "tier": "A",
                "version": "0.1.0-test",
                "onnx_sha256": sha256_of(onnx_path),
                "threshold": threshold,
                "mode": mode,
                "pr_auc": 0.99,
                "feature_order": list(TIER_A_FEATURES),
                "calibration": {"method": "platt", "a": 1.0, "b": 0.0},
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return card_path


@pytest.fixture(scope="session")
def active_card(tmp_path_factory) -> Path:
    return _train_and_export(tmp_path_factory.mktemp("active"), mode="active")


@pytest.fixture(scope="session")
def shadow_card(tmp_path_factory) -> Path:
    return _train_and_export(tmp_path_factory.mktemp("shadow"), mode="shadow")


def _features(first_value: float) -> FlowFeatures:
    from netsentinel_core.features.contract import SPLT_N

    return FlowFeatures(
        key=FlowKey("10.0.0.5", "10.0.0.9", 44321, 80, 6),
        ts_start=1000.0,
        ts_last=1000.06,
        scalars={name: 0.0 for name in TIER_A_FEATURES} | {TIER_A_FEATURES[0]: first_value},
        splt_len=[40] * SPLT_N,
        splt_iat=[10.0] * SPLT_N,
    )


@pytest.fixture
def benign_flow() -> FlowFeatures:
    return _features(0.0)


@pytest.fixture
def malicious_flow() -> FlowFeatures:
    return _features(8.0)


def _train_tier_d(directory: Path, mode: str) -> Path:
    """A real Isolation Forest artefact, so the quantile calibration is exercised."""
    from sklearn.ensemble import IsolationForest
    from skl2onnx import to_onnx

    from netsentinel_scoring.registry import sha256_of
    from netsentinel_training.models.tier_d import TARGET_OPSET, fit_quantiles

    # Benign rows only, selected by label rather than by slicing: the attack rows are
    # displaced on feature 0, and including them would teach the forest that the
    # displacement is normal - which is exactly the bug this fixture first had.
    x, y = _synthetic(1200, seed=21)
    benign = x[y == 0]
    fit_rows, calibration_rows = benign[: len(benign) // 2], benign[len(benign) // 2 :]

    model = IsolationForest(n_estimators=20, random_state=0).fit(fit_rows)

    onnx_path = directory / "tier_d.onnx"
    onnx_path.write_bytes(
        to_onnx(model, fit_rows[:1], target_opset=TARGET_OPSET).SerializeToString()
    )

    levels, quantiles = fit_quantiles(model.decision_function(calibration_rows))
    card_path = directory / "model_card.json"
    card_path.write_text(
        json.dumps(
            {
                "name": "tier_d_isolation_forest",
                "tier": "D",
                "version": "0.1.0-test",
                "onnx_sha256": sha256_of(onnx_path),
                "threshold": 0.99,
                "mode": mode,
                "feature_order": list(TIER_A_FEATURES),
                "calibration": {
                    "method": "empirical_quantiles",
                    "levels": levels,
                    "scores": quantiles,
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return card_path


@pytest.fixture(scope="session")
def tier_d_shadow_card(tmp_path_factory) -> Path:
    pytest.importorskip("skl2onnx", reason="Tier D export needs the training extras")
    return _train_tier_d(tmp_path_factory.mktemp("tier_d_shadow"), mode="shadow")
