"""Calibration at serving time.

Tiers emit different things - the tree classifier a probability, the Isolation Forest
an arbitrary-scale decision function - so fusion can only average them once each has
been mapped back onto the same meaning. These tests pin that mapping, and that a card
naming a method this path cannot reproduce is refused at load rather than at first
score.
"""

from __future__ import annotations

import json

import numpy as np
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_scoring.engine import FusionScorer
from netsentinel_scoring.registry import ModelLoadError, apply_calibration, load_model


# --- the mappings ---------------------------------------------------------

def test_no_calibration_passes_scores_through():
    raw = np.array([0.1, 0.9])
    assert np.allclose(apply_calibration(raw, None), raw)
    assert np.allclose(apply_calibration(raw, {}), raw)


def test_identity_platt_leaves_a_probability_unchanged():
    """a=1, b=0 recovers the margin and re-applies the same sigmoid."""
    raw = np.array([0.05, 0.5, 0.95])
    calibrated = apply_calibration(raw, {"method": "platt", "a": 1.0, "b": 0.0})
    assert np.allclose(calibrated, raw, atol=1e-9)


def test_platt_shifts_probabilities_monotonically():
    raw = np.array([0.2, 0.5, 0.8])
    calibrated = apply_calibration(raw, {"method": "platt", "a": 2.0, "b": -1.0})
    assert np.all(np.diff(calibrated) > 0), "ordering must be preserved"
    assert np.all((calibrated > 0) & (calibrated < 1))


def test_platt_survives_a_probability_of_exactly_zero_or_one():
    """logit(0) is negative infinity; the clip is what keeps this finite."""
    calibrated = apply_calibration(
        np.array([0.0, 1.0]), {"method": "platt", "a": 1.0, "b": 0.0}
    )
    assert np.all(np.isfinite(calibrated))
    assert calibrated[0] == pytest.approx(0.0)
    assert calibrated[1] == pytest.approx(1.0)


def test_empirical_quantiles_inverts_the_decision_function():
    """Higher decision_function means more normal, so the probability must fall."""
    calibration = {
        "method": "empirical_quantiles",
        "levels": [0.0, 0.5, 1.0],
        "scores": [-1.0, 0.0, 1.0],
    }
    calibrated = apply_calibration(np.array([-1.0, 0.0, 1.0]), calibration)
    assert calibrated[0] == pytest.approx(1.0)
    assert calibrated[1] == pytest.approx(0.5)
    assert calibrated[2] == pytest.approx(0.0)


def test_empirical_quantiles_clamps_outside_the_observed_range():
    """A flow stranger than anything in calibration saturates rather than extrapolates."""
    calibration = {
        "method": "empirical_quantiles",
        "levels": [0.0, 1.0],
        "scores": [-1.0, 1.0],
    }
    calibrated = apply_calibration(np.array([-99.0, 99.0]), calibration)
    assert calibrated[0] == pytest.approx(1.0)
    assert calibrated[1] == pytest.approx(0.0)


def test_an_unknown_method_raises():
    with pytest.raises(ModelLoadError, match="unsupported calibration method"):
        apply_calibration(np.array([0.5]), {"method": "vibes"})


# --- refused at load -------------------------------------------------------

def _card_with_calibration(active_card, tmp_path, calibration) -> object:
    import shutil

    directory = tmp_path / "variant"
    directory.mkdir()
    shutil.copy(active_card.parent / "tier_a.onnx", directory / "tier_a.onnx")
    card = json.loads(active_card.read_text(encoding="utf-8"))
    card["calibration"] = calibration
    (directory / "model_card.json").write_text(json.dumps(card), encoding="utf-8")
    return directory / "model_card.json"


def test_a_card_with_an_unserveable_calibration_is_refused(active_card, tmp_path):
    """Refused at load, so a model that cannot be served correctly never registers."""
    path = _card_with_calibration(active_card, tmp_path, {"method": "isotonic"})
    with pytest.raises(ModelLoadError, match="cannot reproduce"):
        load_model(path)


def test_incomplete_quantile_calibration_is_refused(active_card, tmp_path):
    path = _card_with_calibration(
        active_card, tmp_path, {"method": "empirical_quantiles", "levels": [0.0, 1.0]}
    )
    with pytest.raises(ModelLoadError, match="missing \\['scores'\\]"):
        load_model(path)


# --- a real Tier D artefact -----------------------------------------------

def test_tier_d_loads_and_yields_a_probability(tier_d_shadow_card, malicious_flow):
    model = load_model(tier_d_shadow_card)
    assert model.tier == "D"
    assert model.feature_order == TIER_A_FEATURES

    matrix = np.array([[malicious_flow.scalars[n] for n in TIER_A_FEATURES]])
    probability = model.score(matrix)[0]
    # The raw decision_function is unbounded; calibration must land it in [0, 1].
    assert 0.0 <= probability <= 1.0


def test_an_unfamiliar_flow_is_more_anomalous_than_a_typical_one(
    tier_d_shadow_card, benign_flow, malicious_flow
):
    model = load_model(tier_d_shadow_card)

    def score(flow):
        return model.score(np.array([[flow.scalars[n] for n in TIER_A_FEATURES]]))[0]

    assert score(malicious_flow) > score(benign_flow)


def test_fusion_reports_a_shadow_tier_without_letting_it_decide(
    active_card, tier_d_shadow_card, malicious_flow
):
    """Both tiers score; only the active one moves the number anything acts on."""
    scorer = FusionScorer([load_model(active_card), load_model(tier_d_shadow_card)])
    verdict = scorer.score(malicious_flow)

    assert set(verdict.model_scores) == {"tier_a", "tier_d"}
    assert verdict.decided_by == ["tier_a_lightgbm:0.1.0-test"]
    assert not verdict.is_undecided
    # The fused score is Tier A's alone, despite Tier D having voiced an opinion.
    assert verdict.risk_score == pytest.approx(verdict.model_scores["tier_a"])
