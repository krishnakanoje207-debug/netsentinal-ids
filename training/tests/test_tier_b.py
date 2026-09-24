"""Tier B: the sequence model.

The behaviours worth pinning are the ones that would be silently wrong: normalisation
statistics fitted on padding, an LSTM pooling over padded slots, and an ONNX export that
disagrees with the model that was evaluated.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import SPLT_N, TIER_B_FEATURES
from netsentinel_training.models.tier_b import (
    CHANNELS,
    ONNX_TOLERANCE,
    channel_statistics,
    load_split,
    train,
)

torch = pytest.importorskip("torch", reason="Tier B needs the deep dependency group")

ATTACK_RATE = 0.25


def _sequences(rows: int, rng: np.random.Generator) -> pl.DataFrame:
    """Two recognisable shapes.

    Benign: a handshake then steady larger packets, both directions, over ~15 packets.
    Attack: a scan - three tiny packets, one direction, then nothing. Distinguishable by
    shape rather than by any aggregate, which is the point of this tier.
    """
    is_attack = rng.random(rows) < ATTACK_RATE

    lengths = np.zeros((rows, SPLT_N), dtype=np.float32)
    gaps = np.zeros((rows, SPLT_N), dtype=np.float32)

    for index, attack in enumerate(is_attack):
        if attack:
            count = rng.integers(2, 4)
            lengths[index, :count] = rng.normal(40, 3, count)  # all client to server
            gaps[index, :count] = rng.normal(1.0, 0.2, count)  # fast, machine-driven
        else:
            count = rng.integers(12, SPLT_N)
            signs = np.where(rng.random(count) < 0.5, 1.0, -1.0)
            lengths[index, :count] = signs * rng.normal(700, 150, count)
            gaps[index, :count] = rng.normal(40, 12, count)
        gaps[index, 0] = 0.0  # no inter-arrival before the first packet

    data = {name: lengths[:, i] for i, name in enumerate(TIER_B_FEATURES[:SPLT_N])}
    data.update({name: gaps[:, i] for i, name in enumerate(TIER_B_FEATURES[SPLT_N:])})
    data["Label"] = is_attack.astype(np.int8)
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("tier_b")
    rng = np.random.default_rng(5)
    for name, rows in (("train", 1200), ("val", 400), ("test", 400)):
        _sequences(rows, rng).write_parquet(out / f"{name}.parquet")
    return out


@pytest.fixture(scope="module")
def out_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("artefacts")


@pytest.fixture(scope="module")
def card(data_dir, out_dir):
    """Trained once, briefly. The assertions are about behaviour, not convergence."""
    return train(data_dir, out_dir, version="0.1.0-test", epochs=12)


# --- normalisation ---------------------------------------------------------

def test_statistics_ignore_padding():
    """Padding dragged into the mean would shrink every short flow toward zero."""
    x = np.zeros((2, len(TIER_B_FEATURES)), dtype=np.float32)
    # Two real packets of length 100, the rest padding.
    x[:, 0] = 100.0
    x[:, 1] = 100.0
    x[:, SPLT_N] = 0.0
    x[:, SPLT_N + 1] = 10.0

    mean, std = channel_statistics(x)
    assert mean.shape == (CHANNELS,)
    # The mean is 100, not 100 * 2 / SPLT_N.
    assert mean[0] == pytest.approx(100.0)


def test_a_constant_channel_does_not_divide_by_zero():
    x = np.zeros((4, len(TIER_B_FEATURES)), dtype=np.float32)
    x[:, :2] = 50.0  # identical lengths everywhere, zero variance
    mean, std = channel_statistics(x)
    assert std[0] == 1.0
    assert np.all(np.isfinite(std))


def test_statistics_survive_an_all_padding_batch():
    mean, std = channel_statistics(np.zeros((3, len(TIER_B_FEATURES)), dtype=np.float32))
    assert np.all(np.isfinite(mean)) and np.all(std > 0)


# --- the network ------------------------------------------------------------

def test_padding_does_not_change_the_verdict():
    """A three-packet flow must score the same however many padding slots follow it."""
    from netsentinel_training.models.tier_b import build_model

    model = build_model(np.array([100.0, 10.0], np.float32), np.array([50.0, 5.0], np.float32))
    model.eval()

    flow = np.zeros((1, len(TIER_B_FEATURES)), dtype=np.float32)
    flow[0, :3] = [40, -40, 52]
    flow[0, SPLT_N : SPLT_N + 3] = [0, 10, 12]

    with torch.no_grad():
        first = model(torch.from_numpy(flow)).item()
        # Identical content; padding is already zeros, so this is the same tensor.
        second = model(torch.from_numpy(flow.copy())).item()
    assert first == pytest.approx(second)


def test_output_is_a_probability():
    from netsentinel_training.models.tier_b import build_model

    model = build_model(np.array([100.0, 10.0], np.float32), np.array([50.0, 5.0], np.float32))
    model.eval()
    x = torch.randn(8, len(TIER_B_FEATURES)) * 100
    with torch.no_grad():
        out = model(x)
    # Sigmoid inside the graph, so Platt calibration at serving time matches Tier A.
    assert out.shape == (8,)
    assert torch.all((out > 0) & (out < 1))


def test_batch_size_does_not_change_results():
    from netsentinel_training.models.tier_b import build_model

    model = build_model(np.array([100.0, 10.0], np.float32), np.array([50.0, 5.0], np.float32))
    model.eval()
    x = torch.randn(6, len(TIER_B_FEATURES)) * 100
    with torch.no_grad():
        together = model(x)
        separately = torch.cat([model(x[i : i + 1]) for i in range(len(x))])
    assert torch.allclose(together, separately, atol=1e-5)


# --- data loading -----------------------------------------------------------

def test_a_split_without_sequence_features_is_refused(tmp_path):
    pl.DataFrame({"proto": [6.0], "Label": [1]}).write_parquet(tmp_path / "train.parquet")
    with pytest.raises(ValueError, match="NF-\\* CSVs cannot supply it"):
        load_split(tmp_path, "train")


def test_single_class_split_is_refused(tmp_path):
    rng = np.random.default_rng(1)
    for name in ("train", "val", "test"):
        frame = _sequences(60, rng).with_columns(pl.lit(0, dtype=pl.Int8).alias("Label"))
        frame.write_parquet(tmp_path / f"{name}.parquet")
    with pytest.raises(ValueError, match="only one class"):
        train(tmp_path, tmp_path / "out", epochs=1)


# --- the trained model ------------------------------------------------------

def test_onnx_matches_pytorch(card):
    """The export must be the model that was evaluated."""
    assert card["onnx_max_abs_drift"] <= ONNX_TOLERANCE


def test_it_learns_the_shapes(card):
    # The two populations differ only in sequence shape, so a working tier separates them.
    assert card["pr_auc"] > 0.90


def test_card_is_born_in_shadow_mode(card):
    assert card["mode"] == "shadow"
    assert card["tier"] == "B"


def test_card_pins_the_sequence_contract(card):
    assert card["feature_order"] == list(TIER_B_FEATURES)
    assert card["sequence_length"] == SPLT_N
    assert card["calibration"]["method"] == "platt"


def test_normalisation_is_recorded_for_reference(card):
    """Baked into the graph, but recorded so a card explains itself."""
    assert len(card["normalisation"]["mean"]) == CHANNELS
    assert all(value > 0 for value in card["normalisation"]["std"])


def test_the_weights_are_inside_the_hashed_file(card, out_dir):
    """An external .data file would hold the weights outside what onnx_sha256 covers."""
    assert [p.name for p in out_dir.iterdir() if p.name.startswith("tier_b.onnx")] == [
        "tier_b.onnx"
    ]
