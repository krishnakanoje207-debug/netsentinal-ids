"""The family model: which kind of attack, and when it is allowed to say so.

Synthetic families that separate cleanly on different features, so the tests pin the
rules rather than the accuracy: attack flows only, a technique only for mapped
families, and the confidence floor written into the card the writer enforces.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models import family

FAMILIES = ("Reconnaissance", "DoS", "Backdoor")


def _rows(rng, rows: int) -> pl.DataFrame:
    labels = rng.choice(("Benign",) + FAMILIES, rows)
    data = {name: rng.normal(0.0, 1.0, rows) for name in TIER_A_FEATURES}
    # Each family is displaced on a feature of its own, so they separate cleanly.
    for index, name in enumerate(FAMILIES):
        feature = TIER_A_FEATURES[index]
        data[feature] = np.where(labels == name, data[feature] + 8, data[feature])
    data["Label"] = (labels != "Benign").astype(np.int8)
    data["Attack"] = labels
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def trained(tmp_path_factory):
    rng = np.random.default_rng(11)
    data = tmp_path_factory.mktemp("processed")
    for name, rows in (("train", 3000), ("val", 800), ("test", 800)):
        _rows(rng, rows).write_parquet(data / f"{name}.parquet")
    out = tmp_path_factory.mktemp("family")
    return family.train(data, out, version="0.1.0-test"), out


def test_benign_traffic_is_not_a_family(trained):
    card, _ = trained
    assert card["classes"] == sorted(FAMILIES)
    assert card["trained_on"] == "attack flows only"


def test_only_mapped_families_carry_a_technique(trained):
    card, _ = trained
    # Backdoor spans several behaviours and is deliberately unmapped.
    assert card["techniques"] == {"DoS": "T1499", "Reconnaissance": "T1046"}


def test_a_family_whose_confident_answers_are_unreliable_loses_its_technique():
    # Two classes; confident "DoS" predictions are right one time in two.
    probs = np.array([[0.9, 0.1], [0.9, 0.1], [0.1, 0.9], [0.1, 0.9]])
    y = np.array([0, 1, 1, 1])
    kept, precision = family.earned_techniques(probs, y, ["DoS", "Reconnaissance"])
    assert precision == {"DoS": 0.5, "Reconnaissance": 1.0}
    assert kept == {"Reconnaissance": "T1046"}


def test_the_confidence_floor_travels_with_the_model(trained):
    card, _ = trained
    assert card["min_confidence"] == family.MIN_CONFIDENCE


def test_separable_families_are_learned(trained):
    card, _ = trained
    assert card["metrics_test"]["accuracy"] > 0.9
    assert 0.0 < card["metrics_test"]["confident_share"] <= 1.0


def test_the_booster_is_pinned_by_hash(trained):
    card, out = trained
    assert card["booster_sha256"] == family.sha256(out / "family.lgb.txt")
    assert json.loads((out / "model_card.json").read_text(encoding="utf-8")) == card


def test_a_split_without_attacks_is_refused(tmp_path):
    frame = pl.DataFrame({**{f: [0.0] for f in TIER_A_FEATURES}, "Label": [0], "Attack": ["Benign"]})
    frame.write_parquet(tmp_path / "train.parquet")
    with pytest.raises(ValueError, match="no attack flows"):
        family.load_attacks(tmp_path, "train")
