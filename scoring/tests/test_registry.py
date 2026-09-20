"""What the loader refuses, and why each refusal matters."""

from __future__ import annotations

import json

import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_scoring.registry import ModelLoadError, load_model, sha256_of


def test_a_valid_model_loads(active_card):
    model = load_model(active_card)
    assert model.tier == "A"
    assert model.mode == "active"
    assert model.is_active
    assert model.feature_order == TIER_A_FEATURES


def test_shadow_model_is_not_active(shadow_card):
    assert load_model(shadow_card).is_active is False


def test_a_tampered_artefact_is_refused(active_card, tmp_path):
    """The artefact must be the one that was evaluated."""
    import shutil

    directory = tmp_path / "tampered"
    directory.mkdir()
    shutil.copy(active_card, directory / "model_card.json")
    shutil.copy(active_card.parent / "tier_a.onnx", directory / "tier_a.onnx")

    # Append a byte: still a loadable ONNX file, no longer the evaluated one.
    with open(directory / "tier_a.onnx", "ab") as handle:
        handle.write(b"\x00")

    with pytest.raises(ModelLoadError, match="does not match its card"):
        load_model(directory / "model_card.json")


def test_a_model_from_a_different_contract_is_refused(active_card, tmp_path):
    """The payoff of the feature contract: train/serve skew cannot load."""
    import shutil

    directory = tmp_path / "stale"
    directory.mkdir()
    shutil.copy(active_card.parent / "tier_a.onnx", directory / "tier_a.onnx")
    card = json.loads(active_card.read_text(encoding="utf-8"))
    # A model trained before a feature was renamed.
    card["feature_order"] = ["packet_rate"] + list(TIER_A_FEATURES[1:])
    (directory / "model_card.json").write_text(json.dumps(card), encoding="utf-8")

    with pytest.raises(ModelLoadError, match="different feature contract") as exc:
        load_model(directory / "model_card.json")
    # The message must say where they diverge, or nobody can act on it.
    assert "index 0" in str(exc.value)
    assert "packet_rate" in str(exc.value)


def test_a_model_with_fewer_features_is_refused(active_card, tmp_path):
    import shutil

    directory = tmp_path / "short"
    directory.mkdir()
    shutil.copy(active_card.parent / "tier_a.onnx", directory / "tier_a.onnx")
    card = json.loads(active_card.read_text(encoding="utf-8"))
    card["feature_order"] = list(TIER_A_FEATURES[:-1])
    (directory / "model_card.json").write_text(json.dumps(card), encoding="utf-8")

    with pytest.raises(ModelLoadError, match="different feature contract"):
        load_model(directory / "model_card.json")


def test_a_missing_artefact_is_refused(tmp_path):
    card = tmp_path / "model_card.json"
    card.write_text(
        json.dumps(
            {
                "name": "n", "tier": "A", "version": "1", "onnx_sha256": "0" * 64,
                "threshold": 0.5, "mode": "active", "feature_order": list(TIER_A_FEATURES),
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ModelLoadError, match="not found"):
        load_model(card)


def test_an_incomplete_card_is_refused(tmp_path):
    card = tmp_path / "model_card.json"
    card.write_text(json.dumps({"name": "n", "tier": "A"}), encoding="utf-8")
    with pytest.raises(ModelLoadError, match="missing fields"):
        load_model(card)


def test_an_unknown_tier_is_refused(active_card, tmp_path):
    import shutil

    directory = tmp_path / "tier_z"
    directory.mkdir()
    shutil.copy(active_card.parent / "tier_a.onnx", directory / "tier_a.onnx")
    card = json.loads(active_card.read_text(encoding="utf-8"))
    card["tier"] = "Z"
    (directory / "model_card.json").write_text(json.dumps(card), encoding="utf-8")

    with pytest.raises(ModelLoadError, match="unknown tier"):
        load_model(directory / "model_card.json")


def test_unreadable_card_is_refused(tmp_path):
    card = tmp_path / "model_card.json"
    card.write_text("{not json", encoding="utf-8")
    with pytest.raises(ModelLoadError, match="cannot read model card"):
        load_model(card)


def test_hash_helper_matches_the_training_pipeline(active_card):
    """The loader and the trainer must compute the same digest.

    They are separate five-line implementations on purpose - scoring must not depend
    on training, and core must stay tiny - so this asserts the duplication has not
    drifted.
    """
    tier_a = pytest.importorskip(
        "netsentinel_training.models.tier_a", reason="training package not installed"
    )
    sha256 = tier_a.sha256

    onnx_path = active_card.parent / "tier_a.onnx"
    assert sha256_of(onnx_path) == sha256(onnx_path)
