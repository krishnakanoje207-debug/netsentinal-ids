"""Fusion behaviour, especially the distinction between undecided and benign."""

from __future__ import annotations

import dataclasses

import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_scoring.engine import FusionScorer, ScoringError, Verdict
from netsentinel_scoring.registry import load_model


@pytest.fixture
def active_scorer(active_card) -> FusionScorer:
    return FusionScorer([load_model(active_card)])


@pytest.fixture
def shadow_scorer(shadow_card) -> FusionScorer:
    return FusionScorer([load_model(shadow_card)])


# --- scoring ---------------------------------------------------------------

def test_a_malicious_flow_scores_higher_than_a_benign_one(
    active_scorer, benign_flow, malicious_flow
):
    benign = active_scorer.score(benign_flow)
    malicious = active_scorer.score(malicious_flow)
    assert malicious.risk_score > benign.risk_score


def test_an_active_model_produces_a_decided_verdict(active_scorer, malicious_flow):
    verdict = active_scorer.score(malicious_flow)
    assert not verdict.is_undecided
    assert verdict.shadow is False
    assert verdict.decided_by == ["tier_a_lightgbm:0.1.0-test"]
    assert verdict.threshold == pytest.approx(0.5)


def test_every_tier_is_reported_even_when_it_does_not_decide(shadow_scorer, malicious_flow):
    """A shadow tier's judgement is recorded so it can be compared with the analyst's."""
    verdict = shadow_scorer.score(malicious_flow)
    assert "tier_a" in verdict.model_scores
    assert 0.0 <= verdict.model_scores["tier_a"] <= 1.0


def test_a_shadow_only_scorer_is_undecided_not_benign(shadow_scorer, malicious_flow):
    """The distinction this design depends on: silence is not a clean bill of health."""
    verdict = shadow_scorer.score(malicious_flow)
    assert verdict.is_undecided
    assert verdict.risk_score is None
    assert verdict.shadow is True
    assert verdict.decided_by == []
    # And it must never present as an alert.
    assert verdict.is_alert is False


def test_shadow_mode_cannot_raise_an_alert(shadow_scorer, malicious_flow):
    assert shadow_scorer.score(malicious_flow).is_alert is False


def test_an_active_model_over_threshold_raises_an_alert(active_scorer, malicious_flow):
    verdict = active_scorer.score(malicious_flow)
    assert verdict.risk_score >= verdict.threshold
    assert verdict.is_alert


def test_the_flow_id_is_carried_through(active_scorer, malicious_flow):
    verdict = active_scorer.score(malicious_flow)
    assert verdict.flow_id == "10.0.0.5:44321-10.0.0.9:80-6"


def test_a_scorer_needs_at_least_one_model():
    with pytest.raises(ScoringError, match="at least one model"):
        FusionScorer([])


def test_zero_weight_excludes_a_tier(active_card, malicious_flow):
    """Weights are how a tier is benched without unloading it."""
    scorer = FusionScorer([load_model(active_card)], weights={"A": 0.0})
    assert scorer.score(malicious_flow).is_undecided


# --- undecided is not a score ---------------------------------------------

def test_undecided_verdict_reports_no_alert_by_construction():
    verdict = Verdict(flow_id="x", risk_score=None, threshold=0.5)
    assert verdict.is_undecided
    assert verdict.is_alert is False


def test_a_verdict_without_a_threshold_is_not_an_alert():
    """A score with nothing to compare it against decides nothing."""
    verdict = Verdict(flow_id="x", risk_score=0.99, threshold=None)
    assert verdict.is_alert is False


# --- explanations ---------------------------------------------------------

def test_explanations_must_name_contract_features(active_scorer, malicious_flow):
    contributions = {TIER_A_FEATURES[0]: 0.4, "splt_len_0": -0.1}
    assert active_scorer.explain(malicious_flow, contributions) == contributions


def test_an_explanation_naming_an_unknown_feature_is_refused(active_scorer, malicious_flow):
    """A dashboard must never be handed a feature name the contract does not know."""
    with pytest.raises(ScoringError, match="outside the contract"):
        active_scorer.explain(malicious_flow, {"vibes": 0.9})


def test_a_flow_missing_a_required_feature_is_refused(active_scorer, malicious_flow):
    del malicious_flow.scalars[TIER_A_FEATURES[0]]
    with pytest.raises(ScoringError, match="absent from this flow"):
        active_scorer.score(malicious_flow)


# --- two models of one tier -----------------------------------------------

def _tier_d_pair(card):
    """The served forest and a shadow challenger of the same tier."""
    forest = dataclasses.replace(load_model(card), mode="active")
    challenger = dataclasses.replace(load_model(card), name="tier_d_autoencoder")
    return forest, challenger


def test_a_shadow_model_of_a_served_tier_does_not_move_the_verdict(
    tier_d_shadow_card, malicious_flow
):
    forest, challenger = _tier_d_pair(tier_d_shadow_card)
    alone = FusionScorer([forest]).score(malicious_flow)
    verdict = FusionScorer([forest, challenger]).score(malicious_flow)

    assert verdict.risk_score == alone.risk_score
    assert verdict.threshold == alone.threshold
    assert verdict.decided_by == alone.decided_by
    # Recorded under its own name, beside the forest's score rather than over it.
    assert verdict.model_scores["tier_d"] == alone.model_scores["tier_d"]
    assert 0.0 <= verdict.model_scores["tier_d_autoencoder"] <= 1.0


def test_two_active_models_of_one_tier_are_refused(tier_d_shadow_card):
    """Weights are per tier, so the second would count the tier twice."""
    forest, challenger = _tier_d_pair(tier_d_shadow_card)
    with pytest.raises(ScoringError, match="more than one active model per tier"):
        FusionScorer([forest, dataclasses.replace(challenger, mode="active")])


# --- several shadow models of one tier, none active ------------------------

def test_two_shadow_models_of_a_tier_with_no_active_one_are_each_recorded(
    shadow_card, malicious_flow
):
    """No model speaks for the tier, so none is reported as ``tier_a``; each shadow
    score is kept under its own name and the verdict stays undecided."""
    first = load_model(shadow_card)
    second = dataclasses.replace(first, name="tier_a_challenger")
    verdict = FusionScorer([first, second]).score(malicious_flow)

    assert verdict.is_undecided and verdict.shadow is True
    assert set(verdict.model_scores) == {first.name, "tier_a_challenger"}
    assert all(0.0 <= score <= 1.0 for score in verdict.model_scores.values())


def test_two_versions_of_one_shadow_model_are_both_recorded(shadow_card, malicious_flow):
    """Same name, so the name alone would let the second overwrite the first."""
    first = load_model(shadow_card)
    second = dataclasses.replace(first, version="0.2.0")
    verdict = FusionScorer([first, second]).score(malicious_flow)

    assert set(verdict.model_scores) == {
        f"{first.name}:{first.version}",
        f"{first.name}:0.2.0",
    }
    assert verdict.is_undecided


def test_the_same_model_loaded_twice_is_refused(shadow_card):
    model = load_model(shadow_card)
    with pytest.raises(ScoringError, match="more than once"):
        FusionScorer([model, model])
