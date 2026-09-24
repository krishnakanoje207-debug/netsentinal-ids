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

from netsentinel_core.features.clickhouse import network_flows_columns
from netsentinel_core.features.contract import FEATURE_DIM

from netsentinel_writer.consumer import Consumer, RedpandaConsumer, ReplayConsumer
from netsentinel_writer.writer import ContractMismatch

logger = logging.getLogger("netsentinel.flow_sink")

COLUMNS: tuple[str, ...] = tuple(name for name, _ in network_flows_columns())


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


class FlowSink:
    """Batches rows and commits the bus offset after each successful insert."""

    def __init__(
        self,
        insert: Callable[[list[dict[str, Any]]], None],
        batch_size: int = 1000,
        max_wait: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._insert = insert
        self._batch_size = batch_size
        self._max_wait = max_wait
        self._clock = clock
        self.rows = 0
        self.inserts = 0

    def run(self, consumer: Consumer) -> None:
        batch: list[dict[str, Any]] = []
        started = 0.0
        for payload in consumer.messages():
            # None is an idle poll: nothing arrived, but a partial batch may be due.
            if payload is not None:
                if not batch:
                    started = self._clock()
                batch.append(flow_row(payload))
            if batch and (
                len(batch) >= self._batch_size or self._clock() - started >= self._max_wait
            ):
                self._flush(batch, consumer)
                batch = []
        if batch:
            self._flush(batch, consumer)

    def _flush(self, batch: list[dict[str, Any]], consumer: Consumer) -> None:
        self._insert(batch)
        # Only now. See the module docstring on at-least-once delivery.
        consumer.commit()
        self.rows += len(batch)
        self.inserts += 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write every scored flow to ClickHouse")
    parser.add_argument("--brokers", default="localhost:9092")
    parser.add_argument("--group-id", default="netsentinel-flow-sink")
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
        args.clickhouse, os.environ.get("CLICKHOUSE_USER", "netsentinel"), password
    )

    if args.replay:
        with open(args.replay, encoding="utf-8") as handle:
            payloads = [json.loads(line) for line in handle if line.strip()]
        consumer: Consumer = ReplayConsumer(payloads)
    else:
        consumer = RedpandaConsumer(
            args.brokers,
            group_id=args.group_id,
            from_beginning=args.from_beginning,
            yield_idle=True,
        )

    for signal_name in ("SIGINT", "SIGTERM"):
        if hasattr(signal, signal_name):
            signal.signal(getattr(signal, signal_name), lambda *_: consumer.close())

    sink = FlowSink(inserter.insert)
    sink.run(consumer)
    logger.info("finished: %s rows in %s inserts", sink.rows, sink.inserts)
    return 0


if __name__ == "__main__":
    sys.exit(main())
