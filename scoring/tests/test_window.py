"""Tier C, scored a window of flows at a time off the scored-flow stream."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from netsentinel_core.features.contract import (
    FEATURE_DIM,
    SCALAR_FIELDS,
    SPLT_N,
    FlowFeatures,
    FlowKey,
)
from netsentinel_scoring.registry import ModelLoadError
from netsentinel_scoring.window import (
    WindowScorer,
    WindowScoringError,
    build_graph,
    load_window_model,
    run,
)

REAL_CARD = Path(__file__).resolve().parents[2] / "artefacts" / "tier_c" / "model_card.json"


def _payload(index: int, src: str = "10.0.0.5", dst: str = "10.0.0.9") -> dict:
    """A message as the sensor publishes it, zeroed SPLT and all, as a NetFlow replay's is."""
    features = FlowFeatures(
        key=FlowKey(src, dst, 40000 + index, 80, 6),
        ts_start=1000.0 + index,
        ts_last=1000.5 + index,
        scalars={name: float(index + 1) for name in SCALAR_FIELDS},
        splt_len=[0] * SPLT_N,
        splt_iat=[0.0] * SPLT_N,
    )
    row = features.as_row()
    row["sensor"] = "lab"
    return {"flow": row, "verdict": {}, "models": [], "contract": {"features": FEATURE_DIM}}


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


# --- the graph ---------------------------------------------------------------

def test_the_graph_is_built_as_training_built_it():
    """Train/serve parity for Tier C: same flows, same nodes, same edges, same features."""
    pl = pytest.importorskip("polars")
    training = pytest.importorskip("netsentinel_training.models.tier_c")

    flows = [
        _payload(0, "10.0.0.5", "10.0.0.9")["flow"],
        _payload(1, "10.0.0.9", "10.0.0.7")["flow"],
        _payload(2, "10.0.0.5", "10.0.0.7")["flow"],
    ]
    trained_index, trained_features, _labels, trained_nodes = training.build_graph(
        pl.DataFrame(flows)
    )
    edge_index, edge_features, node_count = build_graph(flows)

    assert node_count == trained_nodes == 3
    np.testing.assert_array_equal(edge_index, trained_index)
    np.testing.assert_array_equal(edge_features, trained_features)


# --- loading -----------------------------------------------------------------

def test_a_window_card_loads(write_tier_c, tier_c_window):
    model = load_window_model(write_tier_c())
    assert model.tier == "C"
    assert model.window_flows == tier_c_window


def test_a_card_that_does_not_score_windows_is_refused(write_tier_c):
    with pytest.raises(ModelLoadError, match="window"):
        load_window_model(write_tier_c(scoring_unit="flow"))


def test_a_card_without_a_window_size_is_refused(write_tier_c):
    with pytest.raises(ModelLoadError, match="window_flows"):
        load_window_model(write_tier_c(window_flows=None))


def test_an_active_window_card_is_refused(write_tier_c):
    """A window score has no place in the per-flow fusion, so it cannot decide anything."""
    with pytest.raises(ModelLoadError, match="shadow"):
        load_window_model(write_tier_c(mode="active"))


def test_a_tampered_window_artefact_is_refused(write_tier_c):
    card = write_tier_c()
    with open(card.parent / "tier_c.onnx", "ab") as handle:
        handle.write(b"\x00")
    with pytest.raises(ModelLoadError, match="does not match its card"):
        load_window_model(card)


def test_a_window_card_on_another_contract_is_refused(write_tier_c):
    with pytest.raises(ModelLoadError, match="feature contract"):
        load_window_model(write_tier_c(feature_order=["proto"]))


# --- windows -----------------------------------------------------------------

def test_nothing_is_scored_until_the_window_is_full(write_tier_c, tier_c_window):
    scorer = WindowScorer(load_window_model(write_tier_c()), clock=Clock())
    for index in range(tier_c_window - 1):
        assert scorer.add(_payload(index)) == []

    scored = scorer.add(_payload(tier_c_window - 1))
    assert [key for key, _ in scored] == [
        _payload(index)["flow"]["flow_id"] for index in range(tier_c_window)
    ]


def test_each_flow_gets_a_shadow_tier_c_score(write_tier_c, tier_c_window):
    model = load_window_model(write_tier_c())
    scorer = WindowScorer(model, clock=Clock())
    scored = [m for i in range(tier_c_window) for m in scorer.add(_payload(i))]

    for _key, message in scored:
        verdict = message["verdict"]
        assert 0.0 <= verdict["model_scores"]["tier_c"] <= 1.0
        # Shadow, and so undecided: a Tier C score moves no verdict and raises nothing.
        assert verdict["shadow"] is True and verdict["undecided"] is True
        assert verdict["risk_score"] is None and verdict["is_alert"] is False
        assert verdict["threshold"] == model.threshold
        assert message["models"] == [
            {"tier": "C", "name": model.name, "version": model.version, "mode": "shadow"}
        ]
        assert message["contract"] == {"features": FEATURE_DIM}
        assert message["window"] == {"flows": tier_c_window, "hosts": 2}
        assert set(message["flow"]) == {"flow_id", "ts", "src_ip", "dst_ip", "sensor"}


def test_a_partial_window_is_scored_once_it_has_waited_long_enough(write_tier_c):
    clock = Clock()
    scorer = WindowScorer(load_window_model(write_tier_c()), max_wait=60.0, clock=clock)
    scorer.add(_payload(0))

    clock.now = 59.0
    assert not scorer.due()
    clock.now = 60.0
    assert scorer.due()
    assert len(scorer.flush()) == 1
    assert not scorer.due()


def test_an_empty_window_flushes_to_nothing(write_tier_c):
    scorer = WindowScorer(load_window_model(write_tier_c()), clock=Clock())
    assert scorer.flush() == []
    assert not scorer.due()


# --- the consumer loop ---------------------------------------------------------

def test_offsets_are_committed_only_after_the_window_is_published(write_tier_c, tier_c_window):
    events: list[str] = []
    scorer = WindowScorer(load_window_model(write_tier_c()), clock=Clock())
    messages = [_payload(i) for i in range(tier_c_window + 1)]

    stats = run(
        scorer,
        iter(messages),
        publish=lambda key, message: events.append("publish"),
        commit=lambda: events.append("commit"),
    )

    # One full window, then the remainder flushed at the end of the stream.
    assert events == ["publish"] * tier_c_window + ["commit", "publish", "commit"]
    assert stats == {"flows": tier_c_window + 1, "windows": 2, "skipped": 0}


def test_an_idle_poll_flushes_a_window_that_has_waited(write_tier_c):
    clock = Clock()
    scorer = WindowScorer(load_window_model(write_tier_c()), max_wait=60.0, clock=clock)
    published: list[str] = []

    def stream():
        yield _payload(0)
        clock.now = 61.0
        yield None
        # Checked here, before the end of the stream would flush it anyway.
        assert published == [_payload(0)["flow"]["flow_id"]]

    run(scorer, stream(), publish=lambda key, _m: published.append(key), commit=lambda: None)


def test_a_message_that_is_not_a_flow_is_skipped(write_tier_c):
    scorer = WindowScorer(load_window_model(write_tier_c()), clock=Clock())
    broken = _payload(1)
    del broken["flow"]["src_ip"]

    stats = run(scorer, iter([_payload(0), broken]), publish=lambda *_: None, commit=lambda: None)
    assert stats["skipped"] == 1 and stats["flows"] == 1


def test_a_stream_on_another_contract_stops_the_scorer(write_tier_c):
    scorer = WindowScorer(load_window_model(write_tier_c()), clock=Clock())
    other = _payload(0)
    other["contract"] = {"features": FEATURE_DIM + 1}

    with pytest.raises(WindowScoringError, match="contract"):
        run(scorer, iter([other]), publish=lambda *_: None, commit=lambda: None)


# --- the real artefact ----------------------------------------------------------

@pytest.mark.skipif(not REAL_CARD.exists(), reason="no trained Tier C artefact in artefacts/")
def test_the_trained_artefact_scores_a_window():
    model = load_window_model(REAL_CARD)
    assert model.window_flows == json.loads(REAL_CARD.read_text())["window_flows"]

    flows = [_payload(i, f"10.0.0.{i % 3 + 1}", f"10.0.1.{i % 5 + 1}")["flow"] for i in range(12)]
    scores = model.score(flows)
    assert scores.shape == (12,)
    assert np.all((scores >= 0.0) & (scores <= 1.0))
