"""Where scored flows come from.

Two consumers, mirroring the sensor's two publishers: Redpanda for the real path and
a replaying one for the tests, both satisfying the same small protocol so the writer
has no idea which it is reading.

Offsets are committed by the caller, after the database transaction, never
automatically. That is the whole reason auto-commit is off: a commit before the write
turns a crash into silently lost detections, whereas a commit after it turns the same
crash into a message delivered twice. At-least-once is recoverable; at-most-once is
not, and losing a detection is losing evidence.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Iterator, Protocol

from netsentinel_core.bus import FLOW_TOPIC

logger = logging.getLogger(__name__)


class Consumer(Protocol):
    """What the writer needs from a source."""

    def messages(self) -> Iterator[dict[str, Any]]: ...

    def commit(self) -> None: ...

    def close(self) -> None: ...


class ReplayConsumer:
    """Serves a fixed list of payloads. Used by the tests and by ``--replay``."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self._payloads = list(payloads)
        self.commits = 0
        self.closed = False

    def messages(self) -> Iterator[dict[str, Any]]:
        yield from self._payloads

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


class RedpandaConsumer:
    """Kafka-protocol consumer.

    ``confluent_kafka`` is imported lazily so this package installs, and its tests
    run, without the client library present.
    """

    def __init__(
        self,
        brokers: str,
        group_id: str = "netsentinel-writer",
        topic: str = FLOW_TOPIC,
        poll_timeout: float = 1.0,
        from_beginning: bool = False,
        yield_idle: bool = False,
    ) -> None:
        try:
            from confluent_kafka import Consumer as KafkaConsumer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "confluent-kafka is not installed; install netsentinel-writer[bus]"
            ) from exc

        self._poll_timeout = poll_timeout
        # The flow sink batches, and needs to hear about a quiet poll to flush a partial
        # batch; the writer handles one message at a time and does not.
        self._yield_idle = yield_idle
        self._consumer = KafkaConsumer(
            {
                "bootstrap.servers": brokers,
                "group.id": group_id,
                # See the module docstring: the writer commits, and only once the
                # detection is in PostgreSQL.
                "enable.auto.commit": False,
                # A new group reads the retained stream from the start when asked to,
                # which is what makes a retrained model re-scorable against history.
                "auto.offset.reset": "earliest" if from_beginning else "latest",
            }
        )
        self._consumer.subscribe([topic])
        self._closed = False

    def messages(self) -> Iterator[dict[str, Any] | None]:
        """Yield decoded payloads until close() is called, and None on an idle poll
        when ``yield_idle`` is set."""
        while not self._closed:
            message = self._consumer.poll(self._poll_timeout)
            if message is None:
                if self._yield_idle:
                    yield None
                continue
            if message.error():
                # Logged rather than raised: a partition rebalance surfaces here and
                # is not a reason to take the writer down.
                logger.error("consumer error: %s", message.error())
                continue
            try:
                yield json.loads(message.value())
            except (TypeError, ValueError) as exc:
                # A message that is not JSON will never become JSON. Skipping it and
                # moving on beats blocking the partition forever.
                logger.error("skipping a message that is not valid JSON: %s", exc)

    def commit(self) -> None:
        self._consumer.commit(asynchronous=False)

    def stop(self) -> None:
        """End messages() but leave the consumer open, so a caller holding a batch can
        still commit it."""
        self._closed = True

    def close(self) -> None:
        self._closed = True
        self._consumer.close()
