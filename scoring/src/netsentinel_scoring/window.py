"""Tier C: the graph tier, scored a window of flows at a time.

    python -m netsentinel_scoring.window --card artefacts/tier_c/model_card.json \
        --brokers localhost:9092

    python -m netsentinel_scoring.window --card artefacts/tier_c/model_card.json \
        --replay lab/replay/out/flows.jsonl --out lab/replay/out/tier_c.jsonl

E-GraphSAGE classifies a flow by the hosts around it, so it has no score for one flow on
its own and cannot sit in the per-flow ``FusionScorer``. This is its own consumer of the
scored-flow topic instead: it buffers flows, and when the card's ``window_flows`` have
arrived - or the oldest has waited ``--max-wait`` seconds, so a quiet link is still
scored - it builds the graph exactly as training did and scores every edge in one call.

Each flow's score is published to ``TIER_C_TOPIC`` in the scored-flow message shape,
keyed by flow id: the flow's identity, a verdict carrying ``model_scores["tier_c"]``, and
the model that said it. The verdict is always undecided and shadow. A window score has
no fusion rule to join, so a Tier C card is only loaded in shadow mode.

Offsets are committed after a window is published, never before, as in the writer: a
crash re-reads the window rather than losing it.
"""

from __future__ import annotations

import argparse
import json
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

import numpy as np
import onnxruntime as ort

from netsentinel_core.bus import FLOW_TOPIC, TIER_C_TOPIC
from netsentinel_core.features.contract import FEATURE_DIM, TIER_A_FEATURES
from netsentinel_scoring.registry import (
    REQUIRED_CARD_FIELDS,
    SUPPORTED_CALIBRATIONS,
    ModelLoadError,
    apply_calibration,
    sha256_of,
)

logger = logging.getLogger("netsentinel.tier_c")

#: The edge features: the same flow aggregates Tier A reads (training's EDGE_FEATURES).
EDGE_FEATURES = TIER_A_FEATURES

#: The exported graph's inputs, by name.
GRAPH_INPUTS = ("edge_index", "edge_features", "node_count")

#: What a buffered flow keeps of its message: its identity, published back with the score.
IDENTITY_FIELDS = ("flow_id", "ts", "src_ip", "dst_ip", "sensor")


class WindowScoringError(RuntimeError):
    """The stream cannot be scored. Fatal, like the writer's contract mismatch."""


class MalformedFlow(ValueError):
    """One message is not a scored flow. It is skipped; the stream goes on."""


def build_graph(flows: list[Mapping[str, Any]]) -> tuple[np.ndarray, np.ndarray, int]:
    """(edge_index, edge_features, node_count) for one window, as training builds it.

    Hosts are interned per window, sources first and then destinations in first-seen
    order, so an address never becomes an identity the model could remember.
    """
    hosts = [flow["src_ip"] for flow in flows] + [flow["dst_ip"] for flow in flows]
    ids = {host: index for index, host in enumerate(dict.fromkeys(hosts))}
    edge_index = np.array(
        [[ids[flow["src_ip"]] for flow in flows], [ids[flow["dst_ip"]] for flow in flows]],
        dtype=np.int64,
    )
    edge_features = np.array(
        [[float(flow[name]) for name in EDGE_FEATURES] for flow in flows], dtype=np.float32
    )
    return edge_index, edge_features, len(ids)


@dataclass(slots=True)
class WindowModel:
    """Tier C, ready to score a window."""

    name: str
    tier: str
    version: str
    threshold: float
    calibration: dict | None
    window_flows: int
    session: ort.InferenceSession

    def score(self, flows: list[Mapping[str, Any]]) -> np.ndarray:
        """One calibrated probability per flow, in the order given."""
        edge_index, edge_features, node_count = build_graph(flows)
        raw = self.session.run(
            None,
            {
                "edge_index": edge_index,
                "edge_features": edge_features,
                "node_count": np.array(node_count, dtype=np.int64),
            },
        )[0]
        return apply_calibration(np.asarray(raw).ravel().astype(np.float64), self.calibration)


def load_window_model(card_path: str | Path, onnx_path: str | Path | None = None) -> WindowModel:
    """Load a window-scoring card, with the registry's checks and its own.

    Not ``registry.load_model``: that loader serves one-input, per-flow tiers, and this
    graph takes three inputs and scores a window.
    """
    card_path = Path(card_path)
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelLoadError(f"cannot read model card {card_path}: {exc}") from exc

    missing = [name for name in REQUIRED_CARD_FIELDS if name not in card]
    if missing:
        raise ModelLoadError(f"model card {card_path} is missing fields {missing}")
    if card["tier"] != "C" or card.get("scoring_unit") != "window":
        raise ModelLoadError(
            f"{card_path} is tier {card['tier']!r} scoring by {card.get('scoring_unit')!r}; "
            "only a tier C card that scores by window loads here"
        )
    if not isinstance(card.get("window_flows"), int) or card["window_flows"] < 1:
        raise ModelLoadError(f"{card_path} declares no usable window_flows")
    if card["mode"] != "shadow":
        raise ModelLoadError(
            f"{card['name']!r} is {card['mode']!r}; a window score has no fusion rule "
            "to decide with, so Tier C is served in shadow mode only"
        )

    onnx_path = Path(onnx_path) if onnx_path else card_path.parent / "tier_c.onnx"
    if not onnx_path.exists():
        raise ModelLoadError(f"ONNX artefact not found at {onnx_path}")
    actual = sha256_of(onnx_path)
    if actual != card["onnx_sha256"]:
        raise ModelLoadError(
            f"{onnx_path.name} does not match its card: card says "
            f"{card['onnx_sha256'][:12]}..., file is {actual[:12]}.... This is not "
            "the artefact that was evaluated; refusing to load it."
        )

    if tuple(card["feature_order"]) != EDGE_FEATURES:
        raise ModelLoadError(
            f"{card['name']!r} was trained on a different feature contract: its edge "
            f"features are {card['feature_order']}, this build reads {list(EDGE_FEATURES)}"
        )

    calibration = card.get("calibration")
    if calibration and calibration.get("method") not in SUPPORTED_CALIBRATIONS:
        raise ModelLoadError(
            f"model {card['name']!r} declares calibration {calibration.get('method')!r}, "
            f"which this serving path cannot reproduce"
        )

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    names = tuple(sorted(i.name for i in session.get_inputs()))
    if names != tuple(sorted(GRAPH_INPUTS)):
        raise ModelLoadError(f"{onnx_path.name} takes inputs {names}, wanted {GRAPH_INPUTS}")

    return WindowModel(
        name=str(card["name"]),
        tier="C",
        version=str(card["version"]),
        threshold=float(card["threshold"]),
        calibration=calibration,
        window_flows=card["window_flows"],
        session=session,
    )


@dataclass
class WindowScorer:
    """Buffers flows and scores them a window at a time."""

    model: WindowModel
    #: Seconds the oldest buffered flow may wait before a partial window is scored.
    max_wait: float = 60.0
    clock: Callable[[], float] = time.monotonic
    _flows: list[dict[str, Any]] = field(default_factory=list)
    _started: float = 0.0

    def add(self, payload: Mapping[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        """Buffer one scored-flow message; returns the window's messages once it is full."""
        declared = (payload.get("contract") or {}).get("features")
        if declared != FEATURE_DIM:
            raise WindowScoringError(
                f"stream declares {declared} features, this build reads the contract "
                f"with {FEATURE_DIM}; its edge features would mean something else"
            )
        try:
            flow = payload["flow"]
            # Only what the graph and the reply need, so a full window stays small.
            kept = {name: flow[name] for name in IDENTITY_FIELDS}
            kept.update({name: float(flow[name]) for name in EDGE_FEATURES})
        except (KeyError, TypeError, ValueError) as exc:
            raise MalformedFlow(f"{type(exc).__name__}: {exc}") from exc
        if not self._flows:
            self._started = self.clock()
        self._flows.append(kept)
        return self.flush() if len(self._flows) >= self.model.window_flows else []

    def due(self) -> bool:
        return bool(self._flows) and self.clock() - self._started >= self.max_wait

    def flush(self) -> list[tuple[str, dict[str, Any]]]:
        """Score whatever is buffered, full window or not."""
        flows, self._flows = self._flows, []
        if not flows:
            return []
        scores = self.model.score(flows)
        window = {"flows": len(flows), "hosts": build_graph(flows)[2]}
        return [
            (str(flow["flow_id"]), self._message(flow, float(score), window))
            for flow, score in zip(flows, scores)
        ]

    def _message(self, flow: dict[str, Any], score: float, window: dict) -> dict[str, Any]:
        model = self.model
        return {
            "flow": {name: flow[name] for name in IDENTITY_FIELDS},
            "verdict": {
                "risk_score": None,
                "threshold": model.threshold,
                "model_scores": {"tier_c": score},
                "decided_by": [],
                "shadow": True,
                "undecided": True,
                "is_alert": False,
            },
            "models": [
                {"tier": model.tier, "name": model.name, "version": model.version, "mode": "shadow"}
            ],
            "contract": {"features": FEATURE_DIM},
            "window": window,
        }


def run(
    scorer: WindowScorer,
    messages: Iterable[Mapping[str, Any] | None],
    publish: Callable[[str, dict[str, Any]], None],
    commit: Callable[[], None],
) -> dict[str, int]:
    """Consume until the stream ends. ``None`` is an idle poll, which may flush a window."""
    stats = {"flows": 0, "windows": 0, "skipped": 0}

    def emit(scored: list[tuple[str, dict[str, Any]]]) -> None:
        if not scored:
            return
        for key, message in scored:
            publish(key, message)
        # Only now: every message read so far is in this window, and it is published.
        commit()
        stats["windows"] += 1

    for payload in messages:
        if payload is not None:
            try:
                scored = scorer.add(payload)
            except MalformedFlow as exc:
                # A malformed flow fails the same way on every read; stopping on it would
                # stop Tier C for good. The flow sink dead-letters these.
                logger.error("skipping a message that is not a scored flow: %s", exc)
                stats["skipped"] += 1
                continue
            stats["flows"] += 1
            emit(scored)
        if scorer.due():
            emit(scorer.flush())
    emit(scorer.flush())
    return stats


def _bus_messages(consumer, poll_timeout: float, stopping: Callable[[], bool]):
    """Decoded payloads off the bus, and None on an idle poll."""
    while not stopping():
        message = consumer.poll(poll_timeout)
        if message is None:
            yield None
            continue
        if message.error():
            logger.error("consumer error: %s", message.error())
            continue
        try:
            yield json.loads(message.value())
        except (TypeError, ValueError) as exc:
            logger.error("skipping a message that is not valid JSON: %s", exc)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score Tier C over windows of scored flows")
    parser.add_argument("--card", required=True, help="the Tier C model_card.json")
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument("--group-id", default="netsentinel-tier-c")
    parser.add_argument(
        "--max-wait", type=float, default=60.0,
        help="seconds before a window that has not filled is scored anyway",
    )
    parser.add_argument("--replay", metavar="JSONL", help="read scored flows from a file")
    parser.add_argument("--out", metavar="JSONL", help="with --replay: where the scores go")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-5s %(name)s %(message)s"
    )
    if bool(args.replay) != bool(args.out):
        parser.error("--replay and --out go together")

    try:
        model = load_window_model(args.card)
    except ModelLoadError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    scorer = WindowScorer(model, max_wait=args.max_wait)
    logger.info("tier C %s:%s, windows of %s flows", model.name, model.version, model.window_flows)

    if args.replay:
        with open(args.replay, encoding="utf-8") as source, \
                open(args.out, "w", encoding="utf-8") as out:
            payloads = (json.loads(line) for line in source if line.strip())
            stats = run(
                scorer, payloads,
                publish=lambda _key, message: out.write(json.dumps(message) + "\n"),
                commit=lambda: None,
            )
        logger.info("finished: %s", stats)
        return 0

    try:
        from confluent_kafka import Consumer, Producer
    except ImportError:  # pragma: no cover - environment dependent
        print("refused: confluent-kafka is not installed; use --replay", file=sys.stderr)
        return 2

    consumer = Consumer(
        {"bootstrap.servers": args.brokers, "group.id": args.group_id,
         "enable.auto.commit": False, "auto.offset.reset": "latest"}
    )
    consumer.subscribe([FLOW_TOPIC])
    producer = Producer({"bootstrap.servers": args.brokers, "enable.idempotence": True})

    stopped = False

    def stop(*_: Any) -> None:
        nonlocal stopped
        stopped = True

    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), stop)

    def publish(key: str, message: dict[str, Any]) -> None:
        producer.produce(TIER_C_TOPIC, key=key.encode("utf-8"),
                         value=json.dumps(message, separators=(",", ":")).encode("utf-8"))
        producer.poll(0)

    def commit() -> None:
        # The window must be on the topic before its offsets are given up.
        if producer.flush(10):
            raise RuntimeError(f"Tier C scores could not be written to {TIER_C_TOPIC}")
        consumer.commit(asynchronous=False)

    try:
        stats = run(scorer, _bus_messages(consumer, 1.0, lambda: stopped), publish, commit)
    finally:
        consumer.close()
    logger.info("finished: %s", stats)
    return 0


if __name__ == "__main__":
    sys.exit(main())
