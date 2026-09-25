"""Every scored flow off the bus, features and verdict, into ClickHouse ``network_flows``.

The detection writer keeps only the flows at or above the threshold, and a detection
row carries the flow id but not the feature values that produced its score. This sink
is what makes a verdict traceable back to its inputs: it reads the same topic in its
own consumer group, so it neither slows the writer down nor moves its offsets, and
writes every flow to the table generated from the feature contract.

Python rather than a Vector Kafka source: the row is built from the same column list
as the DDL and the contract is checked the way the writer checks it, so a drift fails
a test here instead of surfacing as rejected inserts in a container log.

Inserts are batched, because ClickHouse wants few large inserts rather than one per
flow, and the offset is committed only after an insert succeeds. A failed insert
raises, and the uncommitted batch is read again on restart: at-least-once, like the
writer. A flow stored twice is a duplicate row; a flow never stored is a verdict
nobody can explain.

A message that cannot become a row - not JSON, missing a column, the wrong shape -
fails the same way on every read, so raising on it would stop ingestion for good.
It is published with the reason to the dead-letter topic, logged and counted, and
its offset is committed like any other. A different feature contract is not a bad
message but the wrong pipeline, and still stops the sink; see ``ContractMismatch``.
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
from typing import Any, Callable, Mapping

from netsentinel_core.bus import FLOW_TOPIC
from netsentinel_core.features.clickhouse import network_flows_columns
from netsentinel_core.features.contract import FEATURE_DIM

from netsentinel_writer.consumer import Consumer, RedpandaConsumer, ReplayConsumer
from netsentinel_writer.writer import ContractMismatch

logger = logging.getLogger("netsentinel.flow_sink")

COLUMNS: tuple[str, ...] = tuple(name for name, _ in network_flows_columns())

#: Messages the sink could not store, each with the reason, for an operator to read.
DEAD_LETTER_TOPIC = f"{FLOW_TOPIC}.deadletter"

#: What ``flow_row`` raises on a malformed message, as opposed to a contract mismatch.
_POISON = (KeyError, TypeError, ValueError, AttributeError)


def flow_row(payload: Mapping[str, Any]) -> dict[str, Any]:
    """The network_flows row for one scored-flow message."""
    declared = (payload.get("contract") or {}).get("features")
    if declared != FEATURE_DIM:
        raise ContractMismatch(
            f"stream declares {declared} features, this build produces {FEATURE_DIM}"
        )
    flow = payload["flow"]
    # Indexed rather than .get(): a column the message lacks is a producer out of
    # step with the table, and storing a default would hide it.
    row = {name: flow[name] for name in COLUMNS}
    # Always a decimal: ClickHouse reads a whole number into DateTime64(3) as
    # milliseconds, not seconds.
    row["ts"] = float(row["ts"])
    return row


class ClickHouseInserter:
    """INSERT ... FORMAT JSONEachRow over the HTTP interface. Stdlib only."""

    def __init__(
        self, url: str, user: str, password: str, table: str = "netsentinel.network_flows"
    ) -> None:
        query = urllib.parse.urlencode({"query": f"INSERT INTO {table} FORMAT JSONEachRow"})
        self._url = f"{url.rstrip('/')}/?{query}"
        self._headers = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}

    def insert(self, rows: list[dict[str, Any]]) -> None:
        body = "\n".join(json.dumps(row, separators=(",", ":")) for row in rows)
        request = urllib.request.Request(
            self._url, data=body.encode("utf-8"), headers=self._headers, method="POST"
        )
        # Raises on any non-2xx, which is what keeps the offset uncommitted.
        with urllib.request.urlopen(request, timeout=30):
            pass


class DeadLetterProducer:
    """Publishes a message the sink cannot store, with the reason, to the dead-letter
    topic. ``confluent_kafka`` is imported lazily, as in the consumer."""

    def __init__(self, brokers: str, topic: str = DEAD_LETTER_TOPIC) -> None:
        try:
            from confluent_kafka import Producer
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError(
                "confluent-kafka is not installed; install netsentinel-writer[bus]"
            ) from exc
        self._topic = topic
        self._producer = Producer({"bootstrap.servers": brokers})

    def __call__(self, value: Any, error: str) -> None:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        record = json.dumps({"error": error, "payload": value}, separators=(",", ":"))
        self._producer.produce(self._topic, value=record.encode("utf-8"))
        # Waited for, because the offset is committed after this returns: a message
        # the topic never received would then be lost rather than parked.
        if self._producer.flush(10):
            raise RuntimeError(
                f"a message could not be written to the dead-letter topic {self._topic}"
            )


class FlowSink:
    """Batches rows and commits the bus offset after each successful insert.

    ``row`` turns one message into one row; the Tier C sink passes its own.
    """

    def __init__(
        self,
        insert: Callable[[list[dict[str, Any]]], None],
        batch_size: int = 1000,
        max_wait: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
        dead_letter: Callable[[Any, str], None] | None = None,
        row: Callable[[Mapping[str, Any]], dict[str, Any]] = flow_row,
    ) -> None:
        self._insert = insert
        self._row = row
        self._dead_letter = dead_letter
        self._batch_size = batch_size
        self._max_wait = max_wait
        self._clock = clock
        self.rows = 0
        self.inserts = 0
        self.dead_lettered = 0

    def run(self, consumer: Consumer) -> None:
        batch: list[dict[str, Any]] = []
        started = 0.0
        for payload in consumer.messages():
            # None is an idle poll: nothing arrived, but a partial batch may be due.
            if payload is not None:
                try:
                    row = self._row(payload)
                except _POISON as exc:
                    self._reject(payload, f"{type(exc).__name__}: {exc}")
                    if not batch:
                        # No batch will carry this offset, so it is committed now,
                        # or a restart reads the same poison again.
                        consumer.commit()
                else:
                    if not batch:
                        started = self._clock()
                    batch.append(row)
            if batch and (
                len(batch) >= self._batch_size or self._clock() - started >= self._max_wait
            ):
                self._flush(batch, consumer)
                batch = []
        if batch:
            self._flush(batch, consumer)

    def _reject(self, payload: Any, error: str) -> None:
        logger.error("dead-lettering a flow message that cannot be stored: %s", error)
        if self._dead_letter is not None:
            self._dead_letter(payload, error)
        self.dead_lettered += 1

    def _flush(self, batch: list[dict[str, Any]], consumer: Consumer) -> None:
        self._insert(batch)
        # Only now. See the module docstring on at-least-once delivery.
        consumer.commit()
        self.rows += len(batch)
        self.inserts += 1


def main(
    argv: list[str] | None = None,
    *,
    description: str = "Write every scored flow to ClickHouse",
    group_id: str = "netsentinel-flow-sink",
    topic: str = FLOW_TOPIC,
    table: str = "netsentinel.network_flows",
    row: Callable[[Mapping[str, Any]], dict[str, Any]] = flow_row,
    dead_letter_topic: str = DEAD_LETTER_TOPIC,
) -> int:
    """Run the sink. The keywords are what the Tier C sink changes; see tier_c_sink."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument("--group-id", default=group_id)
    parser.add_argument("--clickhouse", default="http://localhost:8123")
    parser.add_argument(
        "--from-beginning",
        action="store_true",
        help="read the retained topic from the start, for a new consumer group",
    )
    parser.add_argument(
        "--replay", metavar="JSONL", help="read scored flows from a file instead of the bus"
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)-5s %(name)s %(message)s"
    )

    password = os.environ.get("CLICKHOUSE_PASSWORD")
    if not password:
        print("refused: set CLICKHOUSE_PASSWORD", file=sys.stderr)
        return 2
    inserter = ClickHouseInserter(
        args.clickhouse, os.environ.get("CLICKHOUSE_USER", "netsentinel"), password, table
    )

    if args.replay:
        with open(args.replay, encoding="utf-8") as handle:
            payloads = [json.loads(line) for line in handle if line.strip()]
        consumer: Consumer = ReplayConsumer(payloads)
        dead_letter = None
    else:
        dead_letter = DeadLetterProducer(args.brokers, dead_letter_topic)
        consumer = RedpandaConsumer(
            args.brokers,
            group_id=args.group_id,
            topic=topic,
            from_beginning=args.from_beginning,
            yield_idle=True,
            dead_letter=dead_letter,
        )
        # Stopped rather than closed: the partial batch is inserted and its offset
        # committed after the loop ends, and a closed consumer cannot commit.
        for signal_name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, signal_name):
                signal.signal(getattr(signal, signal_name), lambda *_: consumer.stop())

    sink = FlowSink(inserter.insert, dead_letter=dead_letter, row=row)
    try:
        sink.run(consumer)
    finally:
        consumer.close()
    logger.info(
        "finished: %s rows in %s inserts, %s dead-lettered, %s not JSON",
        sink.rows,
        sink.inserts,
        sink.dead_lettered,
        getattr(consumer, "undecodable", 0),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
