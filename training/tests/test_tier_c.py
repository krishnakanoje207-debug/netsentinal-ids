"""Tier C: the graph model.

The claim this tier makes is that topology carries signal a per-flow model cannot see, so
the fixture is built to test exactly that: individual scan flows are indistinguishable from
benign ones on their own features, and only the fan-out gives them away.
"""

from __future__ import annotations

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_c import (
    EDGE_FEATURES,
    ONNX_TOLERANCE,
    GraphBuildError,
    build_graph,
    edge_statistics,
    score_window,
    train,
)

torch = pytest.importorskip("torch", reason="Tier C needs the deep dependency group")


def _flows(rng: np.random.Generator, benign_pairs: int = 60, scanners: int = 3,
           fan_out: int = 25) -> pl.DataFrame:
    """Benign chatter plus a few hosts touching many others.

    Every flow carries feature values drawn from the same distribution, so no per-flow model
    could separate them. The only difference is structural.
    """
    rows = []

    def features():
        return {name: float(rng.normal(0.0, 1.0)) for name in TIER_A_FEATURES}

    for index in range(benign_pairs):
        src = f"10.0.{index % 4}.{10 + index % 50}"
        dst = f"10.0.{(index + 1) % 4}.{100 + index % 40}"
        rows.append({**features(), "src_ip": src, "dst_ip": dst, "Label": 0})

    for scanner in range(scanners):
        src = f"172.16.0.{200 + scanner}"
        for target in range(fan_out):
            dst = f"10.0.{target % 4}.{100 + target % 40}"
            rows.append({**features(), "src_ip": src, "dst_ip": dst, "Label": 1})

    return pl.DataFrame(rows)


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory):
    out = tmp_path_factory.mktemp("tier_c")
    rng = np.random.default_rng(11)
    for name, pairs, scanners in (("train", 200, 8), ("val", 60, 3), ("test", 60, 3)):
        _flows(rng, benign_pairs=pairs, scanners=scanners).write_parquet(out / f"{name}.parquet")
    return out


@pytest.fixture(scope="module")
def out_dir(tmp_path_factory):
    return tmp_path_factory.mktemp("artefacts")


@pytest.fixture(scope="module")
def card(data_dir, out_dir):
    return train(data_dir, out_dir, version="0.1.0-test", epochs=80)


# --- graph construction ----------------------------------------------------

def test_hosts_become_nodes_and_flows_become_edges():
    frame = pl.DataFrame(
        [
            {**{f: 0.0 for f in TIER_A_FEATURES}, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "Label": 0},
            {**{f: 0.0 for f in TIER_A_FEATURES}, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.3", "Label": 1},
        ]
    )
    edge_index, edge_features, labels, nodes = build_graph(frame)

    assert nodes == 3, "three distinct hosts"
    assert edge_index.shape == (2, 2)
    assert edge_features.shape == (2, len(EDGE_FEATURES))
    # Both flows leave the same source, so both edges share a source node id.
    assert edge_index[0][0] == edge_index[0][1]
    assert labels.tolist() == [0.0, 1.0]


def test_a_frame_without_endpoints_is_refused():
    """Feature-only tables (the NF path) cannot build a graph."""
    frame = pl.DataFrame({name: [0.0] for name in TIER_A_FEATURES})
    with pytest.raises(GraphBuildError, match="needs endpoints"):
        build_graph(frame)


def test_an_empty_frame_is_refused():
    frame = pl.DataFrame(
        {**{name: [] for name in TIER_A_FEATURES}, "src_ip": [], "dst_ip": [], "Label": []}
    )
    with pytest.raises(GraphBuildError, match="no flows"):
        build_graph(frame)


def test_labels_default_to_zero_when_absent():
    """A live window has no labels; building its graph must still work."""
    frame = pl.DataFrame(
        [{**{f: 0.0 for f in TIER_A_FEATURES}, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"}]
    )
    _index, _features, labels, _nodes = build_graph(frame)
    assert labels.tolist() == [0.0]


def test_node_ids_are_local_to_the_graph():
    """An address must not become a stable identity the model could memorise."""
    first = pl.DataFrame(
        [{**{f: 0.0 for f in TIER_A_FEATURES}, "src_ip": "10.0.0.9", "dst_ip": "10.0.0.1", "Label": 0}]
    )
    second = pl.DataFrame(
        [{**{f: 0.0 for f in TIER_A_FEATURES}, "src_ip": "192.168.5.5", "dst_ip": "10.0.0.1", "Label": 0}]
    )
    # Both graphs number their first-seen source as node 0, whatever its address.
    assert build_graph(first)[0][0][0] == build_graph(second)[0][0][0] == 0


# --- normalisation ---------------------------------------------------------

def test_constant_features_do_not_divide_by_zero():
    features = np.ones((10, len(EDGE_FEATURES)), dtype=np.float32)
    _mean, std = edge_statistics(features)
    assert np.all(std == 1.0)
    assert np.all(np.isfinite(std))


# --- the network -----------------------------------------------------------

def test_an_isolated_node_does_not_produce_nan():
    """index_add over a node with no incident edges divides by a clamped degree."""
    from netsentinel_training.models.tier_c import build_model

    model = build_model(
        np.zeros(len(EDGE_FEATURES), np.float32), np.ones(len(EDGE_FEATURES), np.float32)
    )
    model.eval()
    # Node 2 exists but has no edges.
    edge_index = torch.tensor([[0], [1]], dtype=torch.int64)
    features = torch.zeros(1, len(EDGE_FEATURES))
    with torch.no_grad():
        out = model(edge_index, features, torch.tensor(3, dtype=torch.int64))
    assert torch.all(torch.isfinite(out))


def test_output_is_one_probability_per_edge():
    from netsentinel_training.models.tier_c import build_model

    model = build_model(
        np.zeros(len(EDGE_FEATURES), np.float32), np.ones(len(EDGE_FEATURES), np.float32)
    )
    model.eval()
    edge_index = torch.tensor([[0, 1, 2], [1, 2, 0]], dtype=torch.int64)
    features = torch.randn(3, len(EDGE_FEATURES))
    with torch.no_grad():
        out = model(edge_index, features, torch.tensor(3, dtype=torch.int64))
    assert out.shape == (3,)
    assert torch.all((out > 0) & (out < 1))


def test_score_window_scores_every_flow(card, data_dir):
    """The deployed unit of work is a window, not a flow."""
    from netsentinel_training.models.tier_c import build_model

    frame = pl.read_parquet(data_dir / "test.parquet")
    model = build_model(
        np.array(card["normalisation"]["mean"], np.float32),
        np.array(card["normalisation"]["std"], np.float32),
    )
    scores = score_window(model, frame)
    assert scores.shape == (frame.height,)
    assert np.all((scores >= 0) & (scores <= 1))


# --- the trained model -----------------------------------------------------

def test_onnx_matches_pytorch_on_a_different_graph(card):
    """Exported on the training graph, verified on the test graph: shapes are dynamic."""
    assert card["onnx_max_abs_drift"] <= ONNX_TOLERANCE


def test_it_finds_structure_per_flow_features_cannot(card):
    # Every flow's features are drawn from one distribution, so anything above chance here
    # came from the topology.
    assert card["pr_auc"] > 0.75


def test_node_features_stay_constant(card):
    assert card["graph"]["node_features"] == "constant ones"


def test_card_records_that_it_scores_a_window(card):
    """It changes how this tier deploys, so it belongs in the card."""
    assert card["scoring_unit"] == "window"
    assert card["mode"] == "shadow"
    assert card["tier"] == "C"


def test_card_pins_the_edge_feature_order(card):
    assert card["feature_order"] == list(EDGE_FEATURES)


def test_the_weights_are_inside_the_hashed_file(card, out_dir):
    """An external .data file would hold the weights outside what onnx_sha256 covers."""
    assert [p.name for p in out_dir.iterdir() if p.name.startswith("tier_c.onnx")] == [
        "tier_c.onnx"
    ]
