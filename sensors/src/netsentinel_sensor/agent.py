"""The sensor agent: packets in, scored flows out.

    python -m netsentinel_sensor.agent --interface netsentinel-lab \
        --models artefacts/tier_a/model_card.json --brokers localhost:9092

    python -m netsentinel_sensor.agent --pcap capture.pcap --dry-run

    python -m netsentinel_sensor.agent --pcap capture.pcap --models ... --out flows.jsonl

    NETSENTINEL_SENSOR_TOKEN=... python -m netsentinel_sensor.agent \
        --interface netsentinel-lab --models ... --registry-url http://127.0.0.1:8010

With ``--registry-url`` each model runs in the mode the API's model registry gives it,
read once at start, instead of the mode on its card: a promotion on the dashboard takes
effect on the next restart. A model the registry does not list runs in shadow, and a
registry that cannot be read stops the sensor rather than letting it guess.

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
import json
import logging
import os
import signal
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Iterator, Sequence

from netsentinel_core.features.contract import FEATURE_ORDER, FlowFeatures
from netsentinel_core.features.extractor import FlowTracker
from netsentinel_scoring.engine import FusionScorer
from netsentinel_scoring.registry import load_model

from netsentinel_sensor.capture import drop_repeats, from_interface, from_pcap_file
from netsentinel_sensor.publisher import (
    CollectingPublisher,
    FilePublisher,
    Publisher,
    RedpandaPublisher,
)

logger = logging.getLogger("netsentinel.sensor")

#: How often to log throughput. Silence for minutes is indistinguishable from a hang.
REPORT_EVERY_SECONDS = 30.0

#: Where the API serves each registered model's mode (backend ``routes/models.py``).
REGISTRY_PATH = "/api/v1/models/modes"

#: The token that endpoint takes. An environment variable rather than a flag, so it
#: stays out of the process list.
REGISTRY_TOKEN_ENV = "NETSENTINEL_SENSOR_TOKEN"

#: Pauses between attempts to read the registry: five attempts in about fifteen
#: seconds, then the sensor exits and its supervisor decides when to try again.
REGISTRY_RETRY_DELAYS: tuple[float, ...] = (1.0, 2.0, 4.0, 8.0)


class RegistryUnavailable(RuntimeError):
    """The model registry could not be read, so no model's mode is known."""


@dataclass(slots=True)
class Stats:
    packets: int = 0
    flows: int = 0
    decided: int = 0
    undecided: int = 0
    alerts: int = 0
    # Flows the sensor itself cut short, at a stop or a start: scored and published,
    # never alerted on. See SensorAgent._cut_short.
    cut_short: int = 0
    started_at: float = field(default_factory=time.monotonic)

    def as_dict(self) -> dict[str, float]:
        elapsed = max(time.monotonic() - self.started_at, 1e-6)
        return {
            "packets": self.packets,
            "flows": self.flows,
            "decided": self.decided,
            "undecided": self.undecided,
            "alerts": self.alerts,
            "cut_short": self.cut_short,
            "packets_per_second": round(self.packets / elapsed, 1),
            "flows_per_second": round(self.flows / elapsed, 2),
        }


def model_index(models: Iterable) -> list[dict[str, str]]:
    """Identify every tier that scored, shadow ones included.

    ``decided_by`` names only the models that moved the number. A shadow tier moves
    nothing by definition, so without this the writer could record what a shadow model
    said but not which model said it - and comparing a shadow tier against the analyst
    is the entire reason for running one.
    """
    return [
        {"tier": model.tier, "name": model.name, "version": model.version, "mode": model.mode}
        for model in models
    ]


def flow_payload(
    features: FlowFeatures, verdict, sensor_name: str, models: Iterable = (),
    cut_short: bool = False,
) -> dict:
    """The message published for one scored flow.

    Carries the feature vector as well as the scores. The SHAP writer downstream needs the
    exact values that produced the verdict, and re-deriving them from packets would be
    both wasteful and a second place for the contract to drift.

    ``cut_short`` marks a flow the sensor saw only part of because it was starting or
    stopping; its scores are kept, but it is not an alert.
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
            "is_alert": verdict.is_alert and not cut_short,
            "cut_short": cut_short,
        },
        # The scoring set travels with the message. The topic is retained for replay, so a
        # consumer reading it months later must not have to guess which models were loaded
        # at the time - they will have been promoted or retired since.
        "models": list(models),
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
        # Timestamp of the first packet: flows seen soon after it may have begun before.
        self._capture_start: float | None = None
        self._last_ts: float | None = None
        # Built once: the loaded set does not change while the agent runs.
        self._models = model_index(scorer.models)

    def stop(self) -> None:
        """Ask the loop to finish after the current packet."""
        self._stopping = True

    def _cut_short(self, features: FlowFeatures, stopping: bool) -> bool:
        """Whether the sensor, not the network, ended or began this flow.

        Two cases, both seen live as the only false alerts on benign traffic: a
        connection a few seconds old when the sensor was stopped, flushed as one packet,
        and a connection already under way when it started, first seen mid-stream. A
        lone packet reads to Tier A like a probe that got no reply.

        A flow older than the idle timeout at a stop is left alone: a long-lived
        connection is the one that must still alert. The start case needs TCP with no
        SYN at all, so a probe that opens a connection is never excused; a NULL, FIN or
        Xmas probe in the first seconds of capture is, and is still stored.
        """
        window = self.tracker.idle_timeout
        if stopping and self._last_ts is not None and self._last_ts - features.ts_start < window:
            return True
        return (
            self._capture_start is not None
            and features.ts_start - self._capture_start < window
            and features.scalars.get("proto") == 6
            and features.scalars.get("tcp_syn_count", 0) == 0
        )

    def _emit(self, flows: Iterable[FlowFeatures], stopping: bool = False) -> None:
        for features in flows:
            self.stats.flows += 1
            verdict = self.scorer.score(features)
            cut_short = self._cut_short(features, stopping)
            if verdict.is_undecided:
                self.stats.undecided += 1
            else:
                self.stats.decided += 1
            if cut_short:
                self.stats.cut_short += 1
            elif verdict.is_alert:
                self.stats.alerts += 1
            self.publisher.publish(
                str(features.key),
                flow_payload(features, verdict, self.sensor_name, self._models, cut_short),
            )

    def run(self, packets: Iterator[tuple[float, bytes]]) -> Stats:
        """Consume a packet stream until it ends or stop() is called."""
        next_report = time.monotonic() + REPORT_EVERY_SECONDS
        try:
            for timestamp, frame in packets:
                self.stats.packets += 1
                if self._capture_start is None:
                    self._capture_start = timestamp
                self._last_ts = timestamp
                self._emit(self.tracker.update(timestamp, frame))

                if time.monotonic() >= next_report:
                    logger.info("sensor: %s", self.stats.as_dict())
                    next_report = time.monotonic() + REPORT_EVERY_SECONDS

                if self._stopping:
                    break
        finally:
            # Flows still open at shutdown are real flows; dropping them would silently
            # lose the long-lived connections, which are the interesting ones. Only a
            # stop cuts flows short; a capture file that simply ends has shown them whole.
            self._emit(self.tracker.flush(), stopping=self._stopping)
            self.publisher.flush()
        return self.stats


def registry_fetcher(
    url: str, token: str, timeout: float = 5.0
) -> Callable[[], list[dict]]:
    """A callable that reads every registered model's mode from the API at ``url``."""
    # urlopen also follows file:// and other schemes; only HTTP reaches the API.
    if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError(f"registry URL must be http or https: {url!r}")
    request = urllib.request.Request(
        f"{url.rstrip('/')}{REGISTRY_PATH}",
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
    )

    def fetch() -> list[dict]:
        # Raises on any non-2xx. B310: the scheme is checked above.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310
            return json.loads(response.read())

    return fetch


def read_registry(
    fetch: Callable[[], list[dict]],
    delays: Sequence[float] = REGISTRY_RETRY_DELAYS,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[tuple[str, str], str]:
    """Each registered model's mode, keyed by (name, version).

    Retried a few times, because at start the API may simply not be up yet. After that
    it raises: falling back to the cards' modes, or to everything in shadow, would run
    the sensor in a posture nobody chose, and look healthy while doing it.
    """
    for attempt in range(len(delays) + 1):
        try:
            return {
                (str(row["name"]), str(row["version"])): str(row["mode"]) for row in fetch()
            }
        # OSError covers a refused connection, a timeout and an HTTP error status;
        # the rest are a reply that is not the list of models this expects.
        except (OSError, ValueError, KeyError, TypeError) as exc:
            reason = exc
            if attempt < len(delays):
                logger.warning(
                    "model registry not read (%s); retrying in %.0fs", exc, delays[attempt]
                )
                sleep(delays[attempt])
    raise RegistryUnavailable(
        f"could not read the model registry after {len(delays) + 1} attempts: {reason}. "
        f"Check that the API is up at --registry-url and that {REGISTRY_TOKEN_ENV} holds "
        "the same token as the API's."
    )


def registry_mode(model, modes: dict[tuple[str, str], str]) -> str:
    """The mode the registry gives this model, which is shadow unless it says active."""
    mode = modes.get((model.name, model.version))
    if mode is None:
        logger.warning(
            "tier %s %s:%s is not in the model registry, so it runs in shadow: an "
            "unregistered model never decides. Register it with "
            "netsentinel-register-model.",
            model.tier, model.name, model.version,
        )
        return "shadow"
    if mode not in ("active", "shadow"):
        # Retired: loaded by mistake after a promotion replaced it.
        logger.warning(
            "the model registry lists tier %s %s:%s as %s, so it runs in shadow",
            model.tier, model.name, model.version, mode,
        )
        return "shadow"
    return mode


def build_scorer(
    card_paths: list[str], modes: dict[tuple[str, str], str] | None = None
) -> FusionScorer:
    """Load every model, letting the registry refuse mismatched ones.

    With ``modes`` (see ``read_registry``) each model runs in the mode the model
    registry gives it; without, in the mode its card declares.
    """
    models = [load_model(Path(path)) for path in card_paths]
    for model in models:
        if modes is not None:
            model.mode = registry_mode(model, modes)
        logger.info(
            "loaded tier %s %s:%s in %s mode, per %s",
            model.tier, model.name, model.version, model.mode,
            "its card" if modes is None else "the model registry",
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
    parser.add_argument(
        "--registry-url",
        help=(
            "the API, e.g. http://127.0.0.1:8010: run each model in the mode its model "
            f"registry gives it rather than its card's; the token is read from "
            f"{REGISTRY_TOKEN_ENV}"
        ),
    )
    parser.add_argument("--sensor-name", default="early_flow")
    parser.add_argument(
        "--drop-repeats",
        action="store_true",
        help="drop a frame identical to one a few milliseconds earlier; for a Windows "
        "pktmon capture, which logs each packet once per stack component",
    )
    destination = parser.add_mutually_exclusive_group()
    destination.add_argument(
        "--dry-run",
        action="store_true",
        help="score but publish nowhere; prints a summary at the end",
    )
    destination.add_argument(
        "--out",
        help="write scored flows to this JSON Lines file instead of Redpanda, "
        "for netsentinel-writer --replay",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    modes = None
    if args.registry_url:
        token = os.environ.get(REGISTRY_TOKEN_ENV, "")
        if not token:
            parser.error(f"--registry-url needs the API's sensor token in {REGISTRY_TOKEN_ENV}")
        try:
            fetch = registry_fetcher(args.registry_url, token)
        except ValueError as exc:
            parser.error(str(exc))
        try:
            modes = read_registry(fetch, REGISTRY_RETRY_DELAYS)
        except RegistryUnavailable as exc:
            # Not a fallback: a sensor that cannot learn which models may decide does
            # not start. Its supervisor (compose: restart unless-stopped) tries again.
            logger.error("%s", exc)
            return 1

    scorer = build_scorer(args.models, modes)
    publisher: Publisher
    if args.dry_run:
        publisher = CollectingPublisher()
    elif args.out:
        publisher = FilePublisher(args.out)
    else:
        publisher = RedpandaPublisher(args.brokers)
    agent = SensorAgent(scorer, publisher, sensor_name=args.sensor_name)

    # SIGTERM is how Docker stops a container; without this the open flows are lost.
    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), lambda *_: agent.stop())

    packets = from_pcap_file(args.pcap) if args.pcap else from_interface(args.interface)
    if args.drop_repeats:
        packets = drop_repeats(packets)
    stats = agent.run(packets)
    publisher.close()

    logger.info("finished: %s", stats.as_dict())
    if args.dry_run and isinstance(publisher, CollectingPublisher):
        print(f"dry run: {len(publisher.published)} flows scored, nothing published")
    return 0


if __name__ == "__main__":
    sys.exit(main())
