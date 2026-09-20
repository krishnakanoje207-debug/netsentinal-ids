"""Per-detection explanation.

The load-time checks are the same discipline the scoring registry applies to the
ONNX: an artefact that is not the one the card describes does not get used. An
explanation from the wrong model is worse than none, because it reads as an answer.
"""

from __future__ import annotations

import json

import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_writer.explain import ExplainerError, load_explainer


def _card(artefacts, tmp_path, **overrides):
    """The real card with fields changed, written somewhere the booster is not."""
    card = json.loads((artefacts / "model_card.json").read_text(encoding="utf-8"))
    card.update(overrides)
    path = tmp_path / "model_card.json"
    path.write_text(json.dumps(card), encoding="utf-8")
    return path


# --- loading ---------------------------------------------------------------

def test_a_matching_booster_loads(explainer):
    assert explainer.identity == "tier_a_lightgbm:0.1.0-test"
    assert explainer.feature_order == TIER_A_FEATURES


def test_a_missing_card_is_refused(tmp_path):
    with pytest.raises(ExplainerError, match="cannot read"):
        load_explainer(tmp_path / "absent.json")


def test_a_card_without_a_booster_hash_is_refused(artefacts, tmp_path):
    """Unpinned means unprovable, which is the same as wrong here."""
    card = _card(artefacts, tmp_path, booster_sha256=None)
    with pytest.raises(ExplainerError, match="booster_sha256"):
        load_explainer(card, artefacts / "tier_a.lgb.txt")


def test_a_booster_that_does_not_match_its_card_is_refused(artefacts, tmp_path):
    card = _card(artefacts, tmp_path, booster_sha256="b" * 64)
    with pytest.raises(ExplainerError, match="does not match its card"):
        load_explainer(card, artefacts / "tier_a.lgb.txt")


def test_a_missing_booster_says_to_retrain(artefacts, tmp_path):
    with pytest.raises(ExplainerError, match="retrained"):
        load_explainer(_card(artefacts, tmp_path))


def test_a_card_naming_features_outside_the_contract_is_refused(artefacts, tmp_path):
    card = _card(artefacts, tmp_path, feature_order=list(TIER_A_FEATURES) + ["vibes"])
    with pytest.raises(ExplainerError, match="outside the contract"):
        load_explainer(card, artefacts / "tier_a.lgb.txt")


def test_a_card_declaring_the_wrong_width_is_refused(artefacts, tmp_path):
    """Contributions would be named by shifted-up feature names."""
    card = _card(artefacts, tmp_path, feature_order=list(TIER_A_FEATURES[:-1]))
    with pytest.raises(ExplainerError, match="misnamed"):
        load_explainer(card, artefacts / "tier_a.lgb.txt")


# --- explaining ------------------------------------------------------------

def test_every_contract_feature_gets_a_contribution(explainer, make_flow):
    contributions = explainer.explain(make_flow())
    assert set(contributions) == set(TIER_A_FEATURES)
    assert all(isinstance(value, float) for value in contributions.values())


def test_the_base_value_is_not_smuggled_in_as_a_feature(explainer, make_flow):
    """The dashboard looks every key up in the contract; a base value has no entry."""
    assert len(explainer.explain(make_flow())) == len(TIER_A_FEATURES)


def test_the_signal_feature_is_credited(explainer, make_flow):
    """The fixture gave one feature the whole signal, so SHAP must name that one."""
    contributions = explainer.explain(make_flow(duration_ms=5.0))
    strongest = max(contributions, key=lambda name: abs(contributions[name]))
    assert strongest == "duration_ms"


def test_opposite_flows_get_opposite_contributions(explainer, make_flow):
    """A short flow looks like the attack population, a long one like the benign."""
    attackish = explainer.explain(make_flow(duration_ms=5.0))["duration_ms"]
    benignish = explainer.explain(make_flow(duration_ms=900.0))["duration_ms"]
    assert attackish > 0 > benignish


def test_a_flow_missing_a_feature_is_refused(explainer, make_flow):
    flow = make_flow()
    del flow["in_pkts"]
    with pytest.raises(ExplainerError, match="in_pkts"):
        explainer.explain(flow)


def test_a_non_numeric_feature_is_refused(explainer, make_flow):
    with pytest.raises(ExplainerError, match="non-numeric"):
        explainer.explain(make_flow(in_pkts="many"))
