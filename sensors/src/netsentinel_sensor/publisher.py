"""Where scored flows go.

Two publishers: Redpanda for the real path, and a collecting one for tests. Both satisfy
the same tiny protocol, so the agent has no idea which it is talking to.

Why the bus at all, when Vector writes Suricata's logs straight to ClickHouse: the scored
flow stream has a consumer that can fall behind its producer. The SHAP writer runs
LightGBM per detection and is an order of magnitude slower than the sensor, and during a
scan the sensor produces flows in bursts. Redpanda absorbs that, and lets the stream be
replayed when a model is retrained - the reason the topic is retained rather than acked
and forgotten.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from netsentinel_core.bus import FLOW_TOPIC

logger = logging.getLogger(__name__)


class Publisher(Protocol):
    """What the agent needs from a destination."""

    def publish(self, key: str, payload: dict[str, Any]) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class CollectingPublisher:
    """Keeps everything in a list. Used by the tests and by ``--dry-run``."""

    def __init__(self) -> None:
        self.published: list[tuple[str, dict[str, Any]]] = []
        self.flushed = 0
        self.closed = False

    def publish(self, key: str, payload: dict[str, Any]) -> None:
        self.published.append((key, payload))

    def flush(self) -> None:
        self.flushed += 1

    def close(self) -> None:
        self.closed = True


class RedpandaPublisher:
    """Kafka-protocol producer.

    ``confluent_kafka`` is imported lazily so the sensor package can be installed, and its
    tests run, without the client library present.
    """

    def __init__(
        self,
        brokers: str,
        topic: str = FLOW_TOPIC,
        linger_ms: int = 200,
    ) -> None:
        try:
            from confluent_kafka import Producer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "confluent-kafka is not installed; install netsentinel-sensor[bus] or "
                "run the agent with --dry-run"
            ) from exc

        self._topic = topic
        self._producer = Producer(
            {
                "bootstrap.servers": brokers,
                # A small linger batches a burst of flows into one request without
                # noticeably delaying a quiet link.
                "linger.ms": linger_ms,
                "compression.type": "lz4",
                # Block rather than drop when the local queue fills. Losing a scored flow
                # silently is worse than a moment of backpressure on the sensor.
                "queue.buffering.max.messages": 100_000,
                "enable.idempotence": True,
            }
        )
        self._failures = 0

    def _on_delivery(self, error: Any, _message: Any) -> None:
        if error is not None:
            self._failures += 1
            # Logged rather than raised: the callback runs on the producer's thread, and
            # an exception there would take the capture loop down with it.
            logger.error("failed to publish a scored flow: %s", error)

    @property
    def failures(self) -> int:
        return self._failures

    def publish(self, key: str, payload: dict[str, Any]) -> None:
        self._producer.produce(
            self._topic,
            key=key.encode("utf-8"),
            value=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            on_delivery=self._on_delivery,
        )
        # Serve delivery callbacks without blocking; otherwise they queue up unbounded.
        self._producer.poll(0)

    def flush(self) -> None:
        self._producer.flush(10)

    def close(self) -> None:
        self.flush()
