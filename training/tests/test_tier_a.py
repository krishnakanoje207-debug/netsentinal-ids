"""Tier A training pipeline tests.

Run end to end on synthetic splits with a deliberately learnable signal plus
label noise, so the assertions check that the pipeline works rather than that a
particular dataset is easy. The two that matter:

* the ONNX export agrees with LightGBM (the D5 exit criterion),
* the chosen threshold respects the false-positive budget.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_a import (
    ONNX_TOLERANCE,
    TARGET_MAX_FPR,
    apply_platt,
    choose_threshold,
    load_split,
    sha256,
    train,
)

ATTACK_RATE = 0.12
LABEL_NOISE = 0.03


def _make_split(rows: int, rng: np.random.Generator) -> pl.DataFrame:
    """Two separable-but-overlapping populations over the Tier A features."""
    is_attack = rng.random(rows) < ATTACK_RATE

    # Benign: longer conversations, fuller packets. Attack: short, bursty, small
    # packets - the shape of a scan or a brute-force attempt.
    duration_ms = np.where(is_attack, rng.gamma(2, 20, rows), rng.gamma(8, 120, rows))
    in_pkts = np.where(is_attack, rng.poisson(3, rows) + 1, rng.poisson(24, rows) + 1)
    out_pkts = np.where(is_attack, rng.poisson(1, rows), rng.poisson(20, rows) + 1)
    bytes_per_pkt_in = np.where(is_attack, rng.normal(60, 12, rows), rng.normal(700, 180, rows))
    bytes_per_pkt_out = np.where(is_attack, rng.normal(52, 8, rows), rng.normal(900, 220, rows))

    in_bytes = np.clip(in_pkts * bytes_per_pkt_in, 1, None)
    out_bytes = np.clip(out_pkts * bytes_per_pkt_out, 0, None)
    duration_s = np.clip(duration_ms, 1e-3, None) / 1000.0

    data = {
        "proto": np.where(is_attack, 6, rng.choice([6, 17], rows)).astype(float),
        "l4_src_port": rng.integers(1024, 65535, rows).astype(float),
        "l4_dst_port": np.where(is_attack, rng.integers(1, 1024, rows), 443).astype(float),
        "duration_ms": duration_ms,
        "in_pkts": in_pkts.astype(float),
        "out_pkts": out_pkts.astype(float),
        "in_bytes": in_bytes,
        "out_bytes": out_bytes,
        "pkt_rate": (in_pkts + out_pkts) / duration_s,
        "byte_rate": (in_bytes + out_bytes) / duration_s,
        "bytes_per_pkt_in": bytes_per_pkt_in,
        "bytes_per_pkt_out": np.where(out_pkts > 0, bytes_per_pkt_out, 0.0),
        "bytes_ratio_out_in": out_bytes / in_bytes,
        "min_ttl": np.where(is_attack, 64.0, rng.choice([64.0, 128.0], rows)),
        "max_ttl": np.where(is_attack, 64.0, 128.0),
    }
    assert set(data) == set(TIER_A_FEATURES), "fixture drifted from the contract"

    # Flip a few labels so a perfect score is not achievable.
    label = is_attack.copy()
    flip = rng.random(rows) < LABEL_NOISE
    label[flip] = ~label[flip]

    data["Label"] = label.astype(np.int8)
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("processed")
    rng = np.random.default_rng(7)
    for name, rows in (("train", 6000), ("val", 1500), ("test", 1500)):
        _make_split(rows, rng).write_parquet(out / f"{name}.parquet")
    return out


@pytest.fixture(scope="module")
def artefacts(tmp_path_factory):
    return tmp_path_factory.mktemp("artefacts")


@pytest.fixture(scope="module")
def card(data_dir, artefacts):
    """Train once; the assertions below all read the same run."""
    return train(data_dir, artefacts, version="0.1.0-test")


# --- unit level ------------------------------------------------------------

def test_apply_platt_is_a_sigmoid():
    margins = np.array([-2.0, 0.0, 2.0])
    probs = apply_platt(margins, 1.0, 0.0)
    assert probs[1] == pytest.approx(0.5)
    assert probs[0] < probs[1] < probs[2]
    assert np.all((probs > 0) & (probs < 1))


def test_apply_platt_survives_extreme_margins():
    """A confident ensemble emits margins that would overflow exp()."""
    probs = apply_platt(np.array([-1e6, 1e6]), 3.0, 0.0)
    assert probs[0] == pytest.approx(0.0)
    assert probs[1] == pytest.approx(1.0)


def test_threshold_respects_the_false_positive_budget():
    rng = np.random.default_rng(0)
    y = np.concatenate([np.zeros(2000, dtype=np.int8), np.ones(200, dtype=np.int8)])
    probs = np.concatenate([rng.beta(2, 8, 2000), rng.beta(8, 2, 200)])

    threshold = choose_threshold(probs, y, target_max_fpr=0.01)
    predicted = probs >= threshold
    realised_fpr = predicted[y == 0].mean()
    assert realised_fpr <= 0.01 + 1e-9


def test_load_split_rejects_a_frame_missing_features(tmp_path):
    pl.DataFrame({"proto": [6.0], "Label": [1]}).write_parquet(tmp_path / "train.parquet")
    with pytest.raises(ValueError, match="missing Tier A features"):
        load_split(tmp_path, "train")


def test_single_class_split_is_refused(tmp_path):
    rng = np.random.default_rng(1)
    for name in ("train", "val", "test"):
        frame = _make_split(300, rng).with_columns(pl.lit(0, dtype=pl.Int8).alias("Label"))
        frame.write_parquet(tmp_path / f"{name}.parquet")
    with pytest.raises(ValueError, match="only one class"):
        train(tmp_path, tmp_path / "out")


# --- the trained model -----------------------------------------------------

def test_onnx_matches_lightgbm(card):
    """The D5 exit criterion: the served model is the evaluated model."""
    assert card["onnx_max_abs_drift"] <= ONNX_TOLERANCE


def test_pipeline_actually_learns(card):
    """Guards against a pipeline that silently stops learning.

    The bar is set from a measured ceiling, not a guess. With this fixture the
    pipeline scores PR-AUC 1.000 at 0% label noise, 0.929 at 1%, 0.855 at 3% and
    0.762 at 5%: symmetric flips at LABEL_NOISE=0.03 turn roughly a fifth of the
    positive class into unlearnable noise, so ~0.85 is the Bayes limit here, not
    a shortfall. Do not raise this bar without lowering LABEL_NOISE.
    """
    assert card["pr_auc"] > 0.82
    assert card["metrics_test"]["recall"] > 0.5


def test_threshold_holds_on_unseen_data(card):
    """The budget was set on validation; check it survives on test."""
    assert card["metrics_test"]["false_positive_rate"] <= TARGET_MAX_FPR * 3


def test_calibration_improves_the_brier_score(card):
    assert card["metrics_test"]["brier"] <= card["metrics_test_uncalibrated"]["brier"]


def test_card_carries_every_ml_models_column(card):
    # These map one-to-one onto the ml_models table in the M2 schema.
    for field in ("name", "tier", "version", "onnx_sha256", "threshold", "mode", "pr_auc"):
        assert field in card, f"ml_models.{field} has nowhere to come from"
    assert card["mode"] == "shadow", "a new model must not go straight to active"
    assert len(card["onnx_sha256"]) == 64


def test_booster_is_saved_and_matches_its_hash(card, artefacts, data_dir):
    """The writer explains a detection from the tree structure ONNX does not carry.

    Hashed like the ONNX is, so a detection cannot be explained by a model other
    than the one that scored it.
    """
    import lightgbm as lgb

    booster_path = artefacts / "tier_a.lgb.txt"
    assert booster_path.exists(), "per-detection SHAP has no tree structure to read"
    assert sha256(booster_path) == card["booster_sha256"]
    assert len(card["booster_sha256"]) == 64

    reloaded = lgb.Booster(model_file=str(booster_path))
    assert reloaded.num_feature() == len(TIER_A_FEATURES)


def test_card_pins_the_feature_order(card):
    assert card["feature_order"] == list(TIER_A_FEATURES)


def test_shap_covers_every_feature(card):
    assert set(card["shap_global"]) == set(TIER_A_FEATURES)
    assert sum(card["shap_global"].values()) > 0


def test_card_is_json_serialisable(card):
    """It has to survive a write to disk and a read by the API."""
    assert json.loads(json.dumps(card))["tier"] == "A"
