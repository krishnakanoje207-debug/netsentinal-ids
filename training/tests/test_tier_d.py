"""Tier D: unsupervised anomaly detection.

The claim worth testing is not accuracy - the forest never sees an attack - but that
the calibration behaves as advertised: benign scores map to a uniform distribution, so
a threshold of ``1 - target_fpr`` delivers that false-positive rate by construction.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_d import (
    ONNX_TOLERANCE,
    QUANTILE_COUNT,
    TARGET_MAX_FPR,
    anomaly_probability,
    fit_quantiles,
    load_benign,
    train,
)

BENIGN_ROWS = 4000
ATTACK_RATE = 0.1


def _rows(rows: int, rng: np.random.Generator) -> pl.DataFrame:
    """Benign flows cluster; attacks sit off the cluster on several axes."""
    is_attack = rng.random(rows) < ATTACK_RATE
    data = {}
    for index, name in enumerate(TIER_A_FEATURES):
        benign = rng.normal(0.0, 1.0, rows)
        # Attacks are displaced on the first five features only, so the forest has to
        # notice a subspace rather than a global outlier.
        shift = 6.0 if index < 5 else 0.0
        data[name] = np.where(is_attack, benign + shift, benign)
    data["Label"] = is_attack.astype(np.int8)
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("tier_d")
    rng = np.random.default_rng(3)
    for name, rows in (("train", BENIGN_ROWS), ("val", 1500), ("test", 2000)):
        _rows(rows, rng).write_parquet(out / f"{name}.parquet")
    return out


@pytest.fixture(scope="module")
def card(data_dir, tmp_path_factory):
    """Trained once, with a smaller forest.

    The production 200 trees take about a minute to convert to ONNX, and none of the
    assertions below depend on the count; a suite this slow stops being run.
    """
    from netsentinel_training.models import tier_d

    with pytest.MonkeyPatch.context() as patch:
        patch.setitem(tier_d.FOREST_PARAMS, "n_estimators", 40)
        return train(data_dir, tmp_path_factory.mktemp("artefacts"), version="0.1.0-test")


# --- calibration ----------------------------------------------------------

def test_quantiles_cover_the_distribution():
    scores = np.linspace(-0.5, 0.5, 1000)
    levels, quantiles = fit_quantiles(scores)
    assert len(levels) == len(quantiles) == QUANTILE_COUNT
    assert levels[0] == 0.0 and levels[-1] == 1.0
    assert quantiles == sorted(quantiles)


def test_a_normal_score_maps_low_and_an_odd_one_high():
    """decision_function is higher for more normal points, so the mapping inverts."""
    levels, quantiles = fit_quantiles(np.linspace(-0.2, 0.2, 1000))
    probabilities = anomaly_probability(np.array([-0.2, 0.0, 0.2]), levels, quantiles)
    assert probabilities[0] > probabilities[1] > probabilities[2]
    assert probabilities[0] == pytest.approx(1.0, abs=0.01)
    assert probabilities[2] == pytest.approx(0.0, abs=0.01)


def test_benign_probabilities_are_uniform_so_the_threshold_is_analytic():
    """The property that makes 1 - target_fpr the correct cut-off without searching."""
    rng = np.random.default_rng(0)
    calibration_sample = rng.normal(0, 1, 5000)
    levels, quantiles = fit_quantiles(calibration_sample)

    fresh_benign = rng.normal(0, 1, 20000)
    probabilities = anomaly_probability(fresh_benign, levels, quantiles)
    realised = float((probabilities >= 1.0 - TARGET_MAX_FPR).mean())
    assert realised == pytest.approx(TARGET_MAX_FPR, abs=0.005)


# --- data loading ---------------------------------------------------------

def test_only_benign_rows_are_used_for_training(data_dir):
    x = load_benign(data_dir, "train")
    # Around 90% of the rows, since 10% were labelled attacks.
    assert 0.85 * BENIGN_ROWS < len(x) < 0.95 * BENIGN_ROWS
    assert x.shape[1] == len(TIER_A_FEATURES)


def test_a_split_with_no_benign_rows_is_refused(tmp_path):
    frame = pl.DataFrame(
        {name: [1.0] for name in TIER_A_FEATURES} | {"Label": [1]},
    )
    frame.write_parquet(tmp_path / "train.parquet")
    with pytest.raises(ValueError, match="no benign rows"):
        load_benign(tmp_path, "train")


def test_a_split_missing_features_is_refused(tmp_path):
    pl.DataFrame({"proto": [6.0], "Label": [0]}).write_parquet(tmp_path / "train.parquet")
    with pytest.raises(ValueError, match="missing features"):
        load_benign(tmp_path, "train")


# --- the trained model ----------------------------------------------------

def test_onnx_matches_scikit_learn(card):
    assert card["onnx_max_abs_drift"] <= ONNX_TOLERANCE


def test_threshold_is_the_analytic_value(card):
    assert card["threshold"] == pytest.approx(1.0 - TARGET_MAX_FPR)


def test_false_positive_budget_is_respected_on_unseen_data(card):
    """Calibrated on validation, measured on test: the budget must survive the move."""
    assert card["metrics_test"]["false_positive_rate"] <= TARGET_MAX_FPR * 3


def test_it_finds_attacks_it_was_never_trained_on(card):
    """The reason for having an unsupervised tier at all."""
    assert card["metrics_test"]["recall"] > 0.5


def test_card_is_born_in_shadow_mode(card):
    assert card["mode"] == "shadow"
    assert card["tier"] == "D"
    assert card["trained_on"] == "benign flows only"


def test_card_pins_the_feature_order_and_calibration(card):
    assert card["feature_order"] == list(TIER_A_FEATURES)
    assert card["calibration"]["method"] == "empirical_quantiles"
    assert len(card["calibration"]["levels"]) == QUANTILE_COUNT
    assert len(card["calibration"]["scores"]) == QUANTILE_COUNT
