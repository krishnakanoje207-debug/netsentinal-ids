"""The technique on an ML alert: claimed only when the family model is sure, and only
for a family that maps to one ATT&CK technique.

A real three-family booster, separated on ``duration_ms`` alone, so what the model is
confident about is controlled by the test rather than by chance.
"""

from __future__ import annotations

import hashlib
import json

import numpy as np
import pytest

from netsentinel_api.db.models import Alert
from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_writer.technique import LabellerError, load_labeller
from netsentinel_writer.writer import DetectionWriter

CLASSES = ["Backdoor", "DoS", "Reconnaissance"]
DURATION = {"Backdoor": 500.0, "DoS": 5000.0, "Reconnaissance": 5.0}


@pytest.fixture(scope="module")
def family_dir(tmp_path_factory):
    import lightgbm as lgb

    rng = np.random.default_rng(5)
    rows = 900
    labels = rng.integers(0, len(CLASSES), rows)
    x = rng.normal(50, 5, size=(rows, len(TIER_A_FEATURES)))
    index = TIER_A_FEATURES.index("duration_ms")
    x[:, index] = [DURATION[CLASSES[k]] * rng.uniform(0.9, 1.1) for k in labels]
    model = lgb.LGBMClassifier(objective="multiclass", n_estimators=30, num_leaves=8, verbose=-1)
    model.fit(x, labels)

    out = tmp_path_factory.mktemp("family")
    booster = out / "family.lgb.txt"
    model.booster_.save_model(str(booster))
    card = {
        "name": "family_lightgbm",
        "version": "0.1.0-test",
        "booster_sha256": hashlib.sha256(booster.read_bytes()).hexdigest(),
        "feature_order": list(TIER_A_FEATURES),
        "classes": CLASSES,
        "min_confidence": 0.7,
        "techniques": {"DoS": "T1499", "Reconnaissance": "T1046"},
    }
    (out / "model_card.json").write_text(json.dumps(card), encoding="utf-8")
    return out


@pytest.fixture(scope="module")
def labeller(family_dir):
    return load_labeller(family_dir / "model_card.json")


def test_a_confident_mapped_family_names_its_technique(labeller, make_flow):
    label = labeller.label(make_flow(duration_ms=5.0))
    assert label.family == "Reconnaissance"
    assert label.confidence >= 0.7
    assert label.technique == "T1046"


def test_an_unmapped_family_gets_no_technique(labeller, make_flow):
    label = labeller.label(make_flow(duration_ms=500.0))
    assert label.family == "Backdoor"
    assert label.technique is None


def test_an_unsure_answer_gets_no_technique(family_dir, make_flow):
    card = json.loads((family_dir / "model_card.json").read_text(encoding="utf-8"))
    card["min_confidence"] = 1.01  # nothing can clear this
    (family_dir / "strict.json").write_text(json.dumps(card), encoding="utf-8")
    strict = load_labeller(family_dir / "strict.json")
    assert strict.label(make_flow(duration_ms=5000.0)).technique is None


def test_a_booster_that_does_not_match_its_card_is_refused(family_dir):
    card = json.loads((family_dir / "model_card.json").read_text(encoding="utf-8"))
    card["booster_sha256"] = "0" * 64
    (family_dir / "tampered.json").write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(LabellerError, match="does not match its card"):
        load_labeller(family_dir / "tampered.json")


def test_a_card_reading_features_outside_the_contract_is_refused(family_dir):
    card = json.loads((family_dir / "model_card.json").read_text(encoding="utf-8"))
    card["feature_order"] = ["vibes"] + card["feature_order"][1:]
    (family_dir / "foreign.json").write_text(json.dumps(card), encoding="utf-8")
    with pytest.raises(LabellerError, match="outside the contract"):
        load_labeller(family_dir / "foreign.json")


def test_the_writer_puts_the_technique_on_the_alert(explainer, labeller, session, make_payload, make_flow):
    writer = DetectionWriter(lambda: session, explainer, 1, 1, labeller=labeller)
    writer.handle(session, make_payload(flow=make_flow(duration_ms=5000.0)))
    alert, = [row for row in session.added if isinstance(row, Alert)]
    assert alert.mitre_technique == "T1499"


def test_without_a_family_model_the_alert_carries_none(explainer, session, make_payload, make_flow):
    writer = DetectionWriter(lambda: session, explainer, 1, 1)
    writer.handle(session, make_payload(flow=make_flow(duration_ms=5000.0)))
    alert, = [row for row in session.added if isinstance(row, Alert)]
    assert alert.mitre_technique is None
