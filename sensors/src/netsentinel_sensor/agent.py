"""The sensor agent: packets in, scored flows out.

    python -m netsentinel_sensor.agent --interface netsentinel-lab \
        --models artefacts/tier_a/model_card.json --brokers localhost:9092

    python -m netsentinel_sensor.agent --pcap capture.pcap --dry-run

This is the component the whole feature-contract argument was for. It runs the same
``FlowTracker`` the training data was built with, and refuses to start if a model's card
declares a different contract than this build produces.

What it does not do: compute SHAP. TreeSHAP needs the tree structure, which an ONNX graph
does not carry, so the explanation is produced by the writer consuming this topic - which
can afford LightGBM. The sensor publishes the feature vector alongside the scores so that
consumer has everything it needs, and nothing has to re-derive features from packets a
second time.
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from netsentinel_core.features.contract import FEATURE_ORDER, FlowFeatures
from netsentinel_core.features.extractor import FlowTracker
from netsentinel_scoring.engine import FusionScorer
from netsentinel_scoring.registry import load_model

from netsentinel_sensor.capture import from_interface, from_pcap_file
from netsentinel_sensor.publisher import (
    CollectingPublisher,
    Publisher,
    RedpandaPublisher,
)

logger = logging.getLogger("netsentinel.sensor")

#: How often to log throughput. Silence for minutes is indistinguishable from a hang.
REPORT_EVERY_SECONDS = 30.0


@dataclass(slots=True)
class Stats:
    packets: int = 0
    flows: int = 0
    decided: int = 0
    undecided: int = 0
    alerts: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def as_dict(self) -> dict[str, float]:
        elapsed = max(time.monotonic() - self.started_at, 1e-6)
        return {
            "packets": self.packets,
            "flows": self.flows,
            "decided": self.decided,
            "undecided": self.undecided,
            "alerts": self.alerts,
            "packets_per_second": round(self.packets / elapsed, 1),
            "flows_per_second": round(self.flows / elapsed, 2),
        }


def flow_payload(features: FlowFeatures, verdict, sensor_name: str) -> dict:
    """The message published for one scored flow.

    Carries the feature vector as well as the scores. The SHAP writer downstream needs the
    exact values that produced the verdict, and re-deriving them from packets would be
    both wasteful and a second place for the contract to drift.
    """
    row = features.as_row()
    row["sensor"] = sensor_name
    row["risk_score"] = verdict.risk_score
    row["shadow"] = 1 if verdict.shadow else 0
    return {
        "flow": row,
        "verdict": {
            "risk_score": verdict.risk_score,
            "threshold": verdict.threshold,
            "model_scores": verdict.model_scores,
            "decided_by": verdict.decided_by,
            "shadow": verdict.shadow,
            "undecided": verdict.is_undecided,
            "is_alert": verdict.is_alert,
        },
        # Pinned so a consumer can refuse a message built against another contract rather
        # than misreading the vector.
        "contract": {"features": len(FEATURE_ORDER)},
    }


class SensorAgent:
    def __init__(
        self,
        scorer: FusionScorer,
        publisher: Publisher,
        sensor_name: str = "early_flow",
        tracker: FlowTracker | None = None,
    ) -> None:
        self.scorer = scorer
        self.publisher = publisher
        self.sensor_name = sensor_name
        self.tracker = tracker or FlowTracker()
        self.stats = Stats()
        self._stopping = False

    def stop(self) -> None:
        """Ask the loop to finish after the current packet."""
        self._stopping = True

    def _emit(self, flows: Iterable[FlowFeatures]) -> None:
        for features in flows:
            self.stats.flows += 1
            verdict = self.scorer.score(features)
            if verdict.is_undecided:
                self.stats.undecided += 1
            else:
                self.stats.decided += 1
            if verdict.is_alert:
                self.stats.alerts += 1
            self.publisher.publish(str(features.key), flow_payload(features, verdict, self.sensor_name))

    def run(self, packets: Iterator[tuple[float, bytes]]) -> Stats:
        """Consume a packet stream until it ends or stop() is called."""
        next_report = time.monotonic() + REPORT_EVERY_SECONDS
        try:
            for timestamp, frame in packets:
                self.stats.packets += 1
                self._emit(self.tracker.update(timestamp, frame))

                if time.monotonic() >= next_report:
                    logger.info("sensor: %s", self.stats.as_dict())
                    next_report = time.monotonic() + REPORT_EVERY_SECONDS

                if self._stopping:
                    break
        finally:
            # Flows still open at shutdown are real flows; dropping them would silently
            # lose the long-lived connections, which are the interesting ones.
            self._emit(self.tracker.flush())
            self.publisher.flush()
        return self.stats


def build_scorer(card_paths: list[str]) -> FusionScorer:
    """Load every model, letting the registry refuse mismatched ones."""
    models = [load_model(Path(path)) for path in card_paths]
    for model in models:
        logger.info(
            "loaded tier %s %s:%s in %s mode", model.tier, model.name, model.version, model.mode
        )
    if not any(model.is_active for model in models):
        # Not an error: shadow-only is the intended starting posture. It is worth saying
        # out loud, because every verdict will be undecided and that looks like a bug.
        logger.warning(
            "every model is in shadow mode, so no flow will receive a risk score. "
            "This is the D8 starting posture; promote a model to active when ready."
        )
    return FusionScorer(models)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--interface", help="interface to capture from, e.g. netsentinel-lab")
    source.add_argument("--pcap", help="read a capture file instead of a live interface")
    parser.add_argument(
        "--models",
        nargs="+",
        required=True,
        help="one or more model_card.json paths",
    )
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument("--sensor-name", default="early_flow")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="score but publish nowhere; prints a summary at the end",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    scorer = build_scorer(args.models)
    publisher: Publisher = (
        CollectingPublisher() if args.dry_run else RedpandaPublisher(args.brokers)
    )
    agent = SensorAgent(scorer, publisher, sensor_name=args.sensor_name)

    # SIGTERM is how Docker stops a container; without this the open flows are lost.
    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), lambda *_: agent.stop())

    packets = from_pcap_file(args.pcap) if args.pcap else from_interface(args.interface)
    stats = agent.run(packets)
    publisher.close()

    logger.info("finished: %s", stats.as_dict())
    if args.dry_run and isinstance(publisher, CollectingPublisher):
        print(f"dry run: {len(publisher.published)} flows scored, nothing published")
    return 0


if __name__ == "__main__":
    sys.exit(main())
