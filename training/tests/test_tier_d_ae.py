"""Tier D's second half: a dense autoencoder over benign flows.

Held to the same claims as the forest - benign-only training, the log inside the graph,
an analytic threshold from quantile calibration - plus the one a neural network adds:
the exported graph must compute what PyTorch computed.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl
import pytest

torch = pytest.importorskip("torch", reason="the autoencoder needs the deep dependency group")

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_d import QUANTILE_COUNT, TARGET_MAX_FPR
from netsentinel_training.models.tier_d_ae import (
    ONNX_TOLERANCE,
    build_model,
    input_statistics,
    train,
)

ATTACK_RATE = 0.1

#: How three hidden factors drive the benign features; shared by every split, since it
#: is what "benign" means here.
MIXING = np.random.default_rng(0).normal(0.0, 1.0, (3, len(TIER_A_FEATURES)))


def _rows(rows: int, rng: np.random.Generator) -> pl.DataFrame:
    """Benign flows share a structure the attacks break.

    Benign features are driven by three hidden factors, so they are correlated and an
    autoencoder with a narrow bottleneck can rebuild them. Attacks keep a similar
    marginal scale but not the correlation, which is what reconstruction error sees.
    """
    is_attack = rng.random(rows) < ATTACK_RATE
    width = len(TIER_A_FEATURES)
    benign = np.exp(rng.normal(0.0, 1.0, (rows, 3)) @ MIXING * 0.5 + 3.0)
    attack = np.exp(rng.normal(0.0, 1.5, (rows, width)) + 3.0)
    x = np.where(is_attack[:, None], attack, benign)
    data = {name: x[:, i] for i, name in enumerate(TIER_A_FEATURES)}
    data["Label"] = is_attack.astype(np.int8)
    data["Attack"] = np.where(is_attack, "Exploits", "Benign")
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("tier_d_ae")
    rng = np.random.default_rng(5)
    for name, rows in (("train", 6000), ("val", 2000), ("test", 2000)):
        _rows(rows, rng).write_parquet(out / f"{name}.parquet")
    return out


@pytest.fixture(scope="module")
def out_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("artefacts_ae")


@pytest.fixture(scope="module")
def card(data_dir, out_dir):
    """Trained once, with smaller batches.

    Production batches of 1024 over a few thousand synthetic flows give five updates
    an epoch, too few to learn anything; the batch size is not what the tests check.
    """
    from netsentinel_training.models import tier_d_ae

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tier_d_ae, "BATCH_SIZE", 64)
        return train(data_dir, out_dir, version="0.1.0-test", epochs=15)


# --- the graph -------------------------------------------------------------

def _model(rng_seed: int = 0):
    x = np.random.default_rng(rng_seed).lognormal(3.0, 1.0, (500, len(TIER_A_FEATURES)))
    mean, std = input_statistics(x.astype(np.float32))
    return build_model(mean, std)


def test_one_score_per_flow():
    model = _model().eval()
    with torch.no_grad():
        out = model(torch.rand(7, len(TIER_A_FEATURES)) * 1000)
    assert out.shape == (7,)


def test_score_is_negated_reconstruction_error():
    """Higher is more normal, the forest's convention, so the registry's calibration fits."""
    model = _model().eval()
    with torch.no_grad():
        out = model(torch.rand(50, len(TIER_A_FEATURES)) * 1000)
    assert torch.all(out <= 0)


def test_a_flow_is_scored_the_same_alone_or_in_a_batch():
    model = _model().eval()
    x = torch.rand(6, len(TIER_A_FEATURES)) * 1000
    with torch.no_grad():
        together = model(x)
        separately = torch.cat([model(x[i : i + 1]) for i in range(len(x))])
    assert torch.allclose(together, separately, atol=1e-6)


def test_negative_inputs_are_clipped_like_the_forest():
    """Counts are never negative; a stray -1 must read as 0, not as NaN from the log."""
    model = _model().eval()
    x = torch.zeros(1, len(TIER_A_FEATURES))
    with torch.no_grad():
        assert torch.equal(model(x - 1.0), model(x))


def test_statistics_are_of_the_logged_inputs():
    x = np.full((10, len(TIER_A_FEATURES)), np.e - 1.0, dtype=np.float32)
    mean, std = input_statistics(x)
    assert mean == pytest.approx(np.ones(len(TIER_A_FEATURES)), abs=1e-6)
    # A constant column would divide by zero; it is left unscaled instead.
    assert std == pytest.approx(np.ones(len(TIER_A_FEATURES)))


# --- the trained model -----------------------------------------------------

def test_onnx_matches_pytorch(card):
    assert card["onnx_max_abs_drift"] <= ONNX_TOLERANCE


def test_the_graph_takes_raw_features_and_logs_them_itself(card, out_dir):
    import onnx
    import onnxruntime as ort

    path = out_dir / "tier_d.onnx"
    ops = {node.op_type for node in onnx.load(str(path)).graph.node}
    assert "Log" in ops
    session = ort.InferenceSession(str(path), providers=["CPUExecutionProvider"])
    assert session.get_inputs()[0].shape[1] == len(TIER_A_FEATURES)


def test_threshold_is_the_analytic_value_or_just_above_it(card):
    # A few hundred validation flows are coarse enough to tie on the quantile.
    assert 1.0 - TARGET_MAX_FPR <= card["threshold"] < 1.0


def test_false_positive_budget_is_respected_on_unseen_data(card):
    assert card["metrics_test"]["false_positive_rate"] <= TARGET_MAX_FPR * 3


def test_it_finds_attacks_it_was_never_trained_on(card):
    assert card["metrics_test"]["recall"] > 0.5


def test_recall_is_reported_per_family(card):
    assert set(card["family_recall_test"]) == {"Exploits"}
    assert card["family_recall_test"]["Exploits"] == pytest.approx(card["metrics_test"]["recall"])


def test_latency_is_measured_one_flow_per_call(card):
    latency = card["latency_ms"]
    assert latency["calls"] > 0
    assert 0 < latency["p50"] <= latency["p99"]


def test_card_is_born_in_shadow_mode(card):
    assert card["mode"] == "shadow"
    assert card["tier"] == "D"
    assert card["trained_on"] == "benign flows only"
    assert card["input"] == "log1p"


def test_card_pins_the_feature_order_and_calibration(card):
    assert card["feature_order"] == list(TIER_A_FEATURES)
    assert card["calibration"]["method"] == "empirical_quantiles"
    assert len(card["calibration"]["levels"]) == QUANTILE_COUNT
    assert len(card["calibration"]["scores"]) == QUANTILE_COUNT


def test_the_training_sample_is_capped_and_recorded(data_dir, tmp_path):
    from netsentinel_training.models import tier_d_ae

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(tier_d_ae, "MAX_TRAIN_ROWS", 1000)
        small = train(data_dir, tmp_path, version="0.1.0-test", epochs=1)
    assert small["rows"]["train_benign"] == 1000
    assert small["rows"]["train_benign_available"] > 1000


def test_the_registry_loads_it_and_yields_probabilities(card, out_dir):
    """The card is a Tier D card, so it must pass the same load checks as the forest."""
    from netsentinel_scoring.registry import load_model

    model = load_model(out_dir / "model_card.json")
    assert model.tier == "D" and model.name == "tier_d_autoencoder"
    x = np.random.default_rng(1).lognormal(3.0, 1.0, (5, len(TIER_A_FEATURES)))
    probabilities = model.score(x.astype(np.float32))
    assert probabilities.shape == (5,)
    assert np.all((probabilities >= 0) & (probabilities <= 1))


def test_the_weights_are_inside_the_hashed_file(card, out_dir):
    """An external .data file would hold the weights outside what onnx_sha256 covers."""
    assert [p.name for p in out_dir.iterdir() if p.name.startswith("tier_d.onnx")] == [
        "tier_d.onnx"
    ]


def test_card_hash_matches_the_artefact(card, out_dir):
    from netsentinel_training.models.tier_a import sha256

    written = json.loads((out_dir / "model_card.json").read_text(encoding="utf-8"))
    assert written["onnx_sha256"] == sha256(out_dir / "tier_d.onnx")
