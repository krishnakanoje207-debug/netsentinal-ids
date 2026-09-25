"""The Tier C sink: window scores off TIER_C_TOPIC into ClickHouse ``tier_c_scores``.

The batching, commit-after-insert and dead-letter behaviour is the flow sink's and is
tested there; this pins the row, and that the sink is wired to its own topic and table.
"""

from __future__ import annotations

import json
import signal
import sys
import types

import numpy as np
import pytest

from netsentinel_core.bus import TIER_C_TOPIC
from netsentinel_core.features.clickhouse import tier_c_scores_ddl
from netsentinel_core.features.contract import SCALAR_FIELDS, SPLT_N, FlowFeatures, FlowKey
from netsentinel_scoring.engine import Verdict
from netsentinel_scoring.window import WindowScorer
from netsentinel_sensor.agent import flow_payload
from netsentinel_writer import flow_sink, tier_c_sink
from netsentinel_writer.consumer import ReplayConsumer
from netsentinel_writer.flow_sink import FlowSink
from netsentinel_writer.tier_c_sink import COLUMNS, DEAD_LETTER_TOPIC, tier_c_row


class StubModel:
    """A WindowModel as the scorer uses it, scoring every flow 0.9."""

    name, tier, version, threshold, window_flows = "egraphsage", "C", "1.2.0", 0.7, 2

    def score(self, flows):
        return np.full(len(flows), 0.9)


def _messages() -> list[dict]:
    """Built by the scorer's own code from the sensor's own message."""
    scorer = WindowScorer(StubModel())
    out: list[tuple[str, dict]] = []
    for index in range(2):
        features = FlowFeatures(
            key=FlowKey("10.0.0.5", f"10.0.0.{9 + index}", 40000 + index, 80, 6),
            ts_start=1_700_000_000.0 + index,
            ts_last=1_700_000_001.0 + index,
            scalars={name: float(index) for name in SCALAR_FIELDS},
            splt_len=[-60] * SPLT_N,
            splt_iat=[0.5] * SPLT_N,
        )
        verdict = Verdict(flow_id=str(features.key), risk_score=0.2, threshold=0.5, shadow=False)
        out += scorer.add(flow_payload(features, verdict, "early_flow"))
    return [message for _key, message in out]


def test_columns_are_the_ddl_columns_clickhouse_does_not_fill():
    ddl = tier_c_scores_ddl()
    body = ddl[ddl.index("(\n") + 2 : ddl.index("\n)")]
    declared = tuple(line.split()[0] for line in body.split(",\n"))
    assert COLUMNS == tuple(name for name in declared if name != "ingested_at")


def test_the_window_message_fills_every_column():
    row = tier_c_row(_messages()[1])
    assert tuple(row) == COLUMNS
    assert row["ts"] == 1_700_000_001.0
    assert row["dst_ip"] == "10.0.0.10"
    assert row["sensor"] == "early_flow"
    assert (row["model_name"], row["model_version"]) == ("egraphsage", "1.2.0")
    assert (row["probability"], row["threshold"]) == (0.9, 0.7)
    assert (row["window_flows"], row["window_hosts"]) == (2, 3)


def test_a_message_without_a_tier_c_score_is_dead_lettered():
    message = _messages()[0]
    del message["verdict"]["model_scores"]["tier_c"]
    inserted: list[list[dict]] = []
    dead: list[tuple[object, str]] = []
    sink = FlowSink(inserted.append, row=tier_c_row,
                    dead_letter=lambda value, error: dead.append((value, error)))
    sink.run(ReplayConsumer([message, _messages()[1]]))
    assert len(dead) == 1 and "tier_c" in dead[0][1]
    assert [row["dst_ip"] for row in inserted[0]] == ["10.0.0.10"]


class FakeKafka:
    """One message on subscribe, then SIGTERM during the next poll."""

    def __init__(self, payload, handlers, seen) -> None:
        self._payload = payload
        self._handlers = handlers
        self._seen = seen
        self._polls = 0

    def subscribe(self, topics) -> None:
        self._seen["topics"] = topics

    def poll(self, _timeout):
        self._polls += 1
        if self._polls == 1:
            value = json.dumps(self._payload).encode("utf-8")
            return types.SimpleNamespace(error=lambda: None, value=lambda: value)
        self._handlers[signal.SIGTERM](signal.SIGTERM, None)
        return None

    def commit(self, asynchronous: bool = True) -> None:
        pass

    def close(self) -> None:
        pass


def test_main_reads_the_tier_c_topic_into_its_own_table(monkeypatch):
    handlers: dict = {}
    seen: dict = {}
    monkeypatch.setattr(
        flow_sink.signal, "signal", lambda signum, handler: handlers.__setitem__(signum, handler)
    )

    class Producer:
        def __init__(self, config) -> None:
            pass

    monkeypatch.setitem(
        sys.modules,
        "confluent_kafka",
        types.SimpleNamespace(
            Consumer=lambda config: FakeKafka(_messages()[0], handlers, seen),
            Producer=Producer,
        ),
    )

    def insert(self, rows):
        seen["url"] = self._url
        seen["rows"] = rows

    monkeypatch.setattr(flow_sink.ClickHouseInserter, "insert", insert)
    dead_letter_init = flow_sink.DeadLetterProducer.__init__

    def record_dead_letter_topic(self, brokers, topic=flow_sink.DEAD_LETTER_TOPIC):
        seen["dead_letter"] = topic
        dead_letter_init(self, brokers, topic)

    monkeypatch.setattr(flow_sink.DeadLetterProducer, "__init__", record_dead_letter_topic)
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "test")

    assert tier_c_sink.main([]) == 0
    assert seen["topics"] == [TIER_C_TOPIC]
    assert "netsentinel.tier_c_scores" in seen["url"]
    assert seen["dead_letter"] == DEAD_LETTER_TOPIC == f"{TIER_C_TOPIC}.deadletter"
    assert seen["rows"][0]["probability"] == 0.9


@pytest.mark.parametrize("field", ["flow", "verdict", "models", "window"])
def test_each_part_of_the_message_is_required(field):
    message = _messages()[0]
    del message[field]
    with pytest.raises(KeyError):
        tier_c_row(message)
