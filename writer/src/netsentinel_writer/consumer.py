"""Where scored flows come from.

Consumers mirroring the sensor's publishers: Redpanda for the real path, a replaying
one for the tests, and one following the file a sensor without a bus is writing, all
satisfying the same small protocol so the writer has no idea which it is reading.

Offsets are committed by the caller, after the database transaction, never
automatically. That is the whole reason auto-commit is off: a commit before the write
turns a crash into silently lost detections, whereas a commit after it turns the same
crash into a message delivered twice. At-least-once is recoverable; at-most-once is
not, and losing a detection is losing evidence.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterator, Protocol

from netsentinel_core.bus import FLOW_TOPIC

logger = logging.getLogger(__name__)


class Consumer(Protocol):
    """What the writer needs from a source."""

    def messages(self) -> Iterator[dict[str, Any]]: ...

    def commit(self) -> None: ...

    def close(self) -> None: ...


class ReplayConsumer:
    """Serves a fixed list of payloads. Used by the tests and by ``--replay``.

    ``interval`` spaces the payloads out in seconds, so a demonstration shows alerts
    arriving one by one, as they would from a sensor, rather than all at once.
    """

    def __init__(
        self,
        payloads: list[dict[str, Any]],
        interval: float = 0.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._payloads = list(payloads)
        self._interval = interval
        self._sleep = sleep
        self.commits = 0
        self.closed = False

    def messages(self) -> Iterator[dict[str, Any]]:
        for index, payload in enumerate(self._payloads):
            if index and self._interval > 0:
                self._sleep(self._interval)
            yield payload

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


class FollowConsumer:
    """Follows a JSON Lines file that a running sensor is still appending to.

    For the laptop that watches its own traffic without Redpanda: the sensor writes
    each scored flow as a line and flushes it, and this yields the line as soon as it
    is whole, so the alert reaches the dashboard within a poll of being scored.

    A line without its newline is still being written and is held until the rest
    arrives. A line that is not JSON is logged and skipped: a sensor that crashed
    mid-line leaves one, and every line after it is still good. A file shorter than
    what was already read means the sensor restarted and rewrote it, so reading starts
    over from the top.

    The stream ends on stop(), or once ``<path>.done`` exists and the file has been
    read to its end: the launcher creates that marker only after the sensor exited,
    because on Windows it cannot send the writer a Ctrl+C. The marker is left for the
    launcher to clear.

    There is no offset to commit, so commit() only counts, as ReplayConsumer's does.
    A restarted writer reads the file from the top and stores its flows again, which
    is at-least-once, not loss; restart the sensor with it to start a fresh file.
    """

    def __init__(
        self,
        path: str | Path,
        poll_seconds: float = 0.5,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._path = Path(path)
        self._done = self._path.with_name(self._path.name + ".done")
        self._poll_seconds = poll_seconds
        self._sleep = sleep
        self._stopped = False
        self.commits = 0
        self.undecodable = 0
        self.closed = False

    def messages(self) -> Iterator[dict[str, Any]]:
        handle = self._wait_for_file()
        if handle is None:
            return
        with handle:
            pending = b""
            # Set once the marker is seen; the file is then read once more to its end,
            # because lines may have landed between the last read and the check.
            done = False
            while not self._stopped:
                line = handle.readline()
                if line.endswith(b"\n"):
                    line, pending = pending + line, b""
                    if line.strip():
                        try:
                            yield json.loads(line)
                        except ValueError as exc:
                            logger.error("skipping a line that is not valid JSON: %s", exc)
                            self.undecodable += 1
                    continue
                pending += line
                if done:
                    if pending.strip():
                        logger.error("dropping an unfinished last line: %r", pending[:200])
                    return
                if os.fstat(handle.fileno()).st_size < handle.tell():
                    handle.seek(0)
                    pending = b""
                    continue
                if self._done.exists():
                    done = True
                    continue
                self._sleep(self._poll_seconds)

    def _wait_for_file(self) -> BinaryIO | None:
        """The writer may start before the sensor has written anything."""
        while not self._stopped:
            try:
                # Binary, so a read that stops inside a multi-byte character is held
                # with the rest of its line rather than failing to decode.
                return open(self._path, "rb")
            except FileNotFoundError:
                if self._done.exists():
                    return None  # the sensor exited without writing a flow
                self._sleep(self._poll_seconds)
        return None

    def commit(self) -> None:
        self.commits += 1

    def stop(self) -> None:
        """End messages() after the message in flight."""
        self._stopped = True

    def close(self) -> None:
        self._stopped = True
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
        dead_letter: Callable[[bytes, str], None] | None = None,
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
        # Where a message that is not JSON goes, rather than only into the log.
        self._dead_letter = dead_letter
        self.undecodable = 0
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
                self.undecodable += 1
                if self._dead_letter is not None:
                    self._dead_letter(message.value(), f"not valid JSON: {exc}")

    def commit(self) -> None:
        self._consumer.commit(asynchronous=False)

    def stop(self) -> None:
        """End messages() but leave the consumer open, so a caller holding a batch can
        still commit it."""
        self._closed = True

    def close(self) -> None:
        self._closed = True
        self._consumer.close()
