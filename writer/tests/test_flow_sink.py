"""The flow sink: every scored flow into ClickHouse, offsets committed after the insert.

ClickHouse is faked. What matters here is which rows are built, when a batch is
inserted, and that an offset is never committed for rows that did not land.
"""

from __future__ import annotations

import json
import signal
import sys
import types

import pytest

from netsentinel_core.features.clickhouse import network_flows_ddl
from netsentinel_core.features.contract import (
    FEATURE_DIM,
    SCALAR_FIELDS,
    SPLT_N,
    FlowFeatures,
    FlowKey,
)
from netsentinel_scoring.engine import Verdict
from netsentinel_sensor.agent import flow_payload
from netsentinel_writer import flow_sink
from netsentinel_writer.consumer import RedpandaConsumer, ReplayConsumer
from netsentinel_writer.flow_sink import (
    COLUMNS,
    DEAD_LETTER_TOPIC,
    DeadLetterProducer,
    FlowSink,
    flow_row,
)
from netsentinel_writer.writer import ContractMismatch


def _payload(index: int = 0, risk_score: float | None = 0.2) -> dict:
    """Built by the sensor's own function, so the test follows the real message."""
    features = FlowFeatures(
        key=FlowKey("10.0.0.5", "10.0.0.9", 40000 + index, 80, 6),
        ts_start=1_700_000_000.0 + index,
        ts_last=1_700_000_001.0 + index,
        scalars={name: float(index) for name in SCALAR_FIELDS},
        splt_len=[-60] * SPLT_N,
        splt_iat=[0.5] * SPLT_N,
    )
    verdict = Verdict(
        flow_id=str(features.key), risk_score=risk_score, threshold=0.5, shadow=False
    )
    return flow_payload(features, verdict, "early_flow")


class FakeClickHouse:
    def __init__(self, fail: bool = False) -> None:
        self.batches: list[list[dict]] = []
        self.fail = fail

    def insert(self, rows: list[dict]) -> None:
        if self.fail:
            raise OSError("clickhouse is down")
        self.batches.append(list(rows))


class RecordingConsumer(ReplayConsumer):
    """Notes how many rows had been inserted each time an offset was committed."""

    def __init__(self, payloads, clickhouse: FakeClickHouse) -> None:
        super().__init__(payloads)
        self._clickhouse = clickhouse
        self.committed_after: list[int] = []

    def commit(self) -> None:
        super().commit()
        self.committed_after.append(sum(len(b) for b in self._clickhouse.batches))


def test_columns_are_the_ddl_columns():
    """The row and the table come from one list; this pins it to the DDL text."""
    ddl = network_flows_ddl()
    body = ddl[ddl.index("(\n") + 2 : ddl.index("\n)")]
    declared = tuple(line.split()[0] for line in body.split(",\n"))
    assert COLUMNS == declared


def test_the_sensor_message_fills_every_column():
    row = flow_row(_payload())
    assert tuple(row) == COLUMNS
    assert row["sensor"] == "early_flow"
    assert row["risk_score"] == 0.2
    assert row["shadow"] == 0
    assert row["splt_len_0"] == -60


def test_an_undecided_flow_is_stored_as_null_not_zero():
    assert flow_row(_payload(risk_score=None))["risk_score"] is None


def test_ts_is_always_a_decimal():
    payload = _payload()
    payload["flow"]["ts"] = 1_700_000_000
    ts = flow_row(payload)["ts"]
    assert isinstance(ts, float) and ts == 1_700_000_000.0


def test_a_missing_column_fails_rather_than_defaulting():
    payload = _payload()
    del payload["flow"]["splt_iat_3"]
    with pytest.raises(KeyError):
        flow_row(payload)


def test_a_different_contract_is_refused():
    payload = _payload()
    payload["contract"] = {"features": FEATURE_DIM + 1}
    with pytest.raises(ContractMismatch):
        flow_row(payload)


def test_rows_are_batched_and_committed_after_each_insert():
    clickhouse = FakeClickHouse()
    consumer = RecordingConsumer([_payload(i) for i in range(5)], clickhouse)
    sink = FlowSink(clickhouse.insert, batch_size=2)
    sink.run(consumer)

    assert [len(b) for b in clickhouse.batches] == [2, 2, 1]
    # Every commit came after the rows it covers were inserted.
    assert consumer.committed_after == [2, 4, 5]
    assert sink.rows == 5 and sink.inserts == 3


def test_every_flow_is_written_whatever_its_score():
    """Unlike the detection writer, nothing below the threshold is dropped."""
    clickhouse = FakeClickHouse()
    payloads = [_payload(0, 0.01), _payload(1, None), _payload(2, 0.99)]
    FlowSink(clickhouse.insert).run(ReplayConsumer(payloads))
    assert [row["risk_score"] for row in clickhouse.batches[0]] == [0.01, None, 0.99]


def test_a_failed_insert_commits_nothing():
    clickhouse = FakeClickHouse(fail=True)
    consumer = ReplayConsumer([_payload(i) for i in range(3)])
    with pytest.raises(OSError):
        FlowSink(clickhouse.insert, batch_size=2).run(consumer)
    assert consumer.commits == 0


# --- poison messages ----------------------------------------------------------

def _malformed() -> dict:
    payload = _payload(9)
    del payload["flow"]["splt_iat_3"]
    return payload


class DeadLetters:
    def __init__(self) -> None:
        self.sent: list[tuple[object, str]] = []

    def __call__(self, value, error: str) -> None:
        self.sent.append((value, error))


def test_a_malformed_message_is_dead_lettered_and_ingestion_continues():
    """One bad message must not stop every good one behind it."""
    clickhouse = FakeClickHouse()
    dead = DeadLetters()
    consumer = RecordingConsumer([_payload(0), _malformed(), _payload(1)], clickhouse)
    sink = FlowSink(clickhouse.insert, dead_letter=dead)
    sink.run(consumer)

    assert [row["src_port"] for row in clickhouse.batches[0]] == [40000, 40001]
    assert len(dead.sent) == 1
    assert dead.sent[0][0] == _malformed()
    assert "splt_iat_3" in dead.sent[0][1]
    assert sink.dead_lettered == 1
    # The poison offset is covered by the commit after the good rows landed.
    assert consumer.committed_after == [2]


@pytest.mark.parametrize(
    "poison",
    [
        "not an object",
        {"contract": {"features": FEATURE_DIM}, "flow": "not a mapping"},
        {"contract": {"features": FEATURE_DIM}},
    ],
)
def test_other_shapes_of_poison_are_dead_lettered_too(poison):
    clickhouse = FakeClickHouse()
    dead = DeadLetters()
    sink = FlowSink(clickhouse.insert, dead_letter=dead)
    sink.run(ReplayConsumer([poison, _payload(0)]))
    assert len(dead.sent) == 1
    assert sum(len(b) for b in clickhouse.batches) == 1


def test_a_poison_message_alone_is_committed_past():
    """With nothing batched there is no later commit to carry its offset, so it is
    committed straight after it is dead-lettered; a restart does not read it again."""
    clickhouse = FakeClickHouse()
    consumer = RecordingConsumer([_malformed()], clickhouse)
    sink = FlowSink(clickhouse.insert, dead_letter=DeadLetters())
    sink.run(consumer)
    assert clickhouse.batches == []
    assert consumer.committed_after == [0]


def test_without_a_dead_letter_topic_the_poison_is_still_counted_and_skipped(caplog):
    """Replay mode has no bus to publish to; the message is logged instead."""
    clickhouse = FakeClickHouse()
    sink = FlowSink(clickhouse.insert)
    with caplog.at_level("ERROR", logger="netsentinel.flow_sink"):
        sink.run(ReplayConsumer([_malformed(), _payload(0)]))
    assert sink.dead_lettered == 1
    assert sum(len(b) for b in clickhouse.batches) == 1
    assert "dead-letter" in caplog.text


def test_a_different_contract_still_stops_the_sink():
    """Not a bad message but the wrong pipeline: every message after it is the same,
    and dead-lettering the whole stream would hide that behind a green process."""
    payload = _payload()
    payload["contract"] = {"features": FEATURE_DIM + 1}
    dead = DeadLetters()
    with pytest.raises(ContractMismatch):
        FlowSink(FakeClickHouse().insert, dead_letter=dead).run(ReplayConsumer([payload]))
    assert dead.sent == []


class FakeProducer:
    def __init__(self, config, undelivered: int = 0) -> None:
        self.config = config
        self.produced: list[tuple[str, bytes]] = []
        self._undelivered = undelivered

    def produce(self, topic, value=None, **_kwargs) -> None:
        self.produced.append((topic, value))

    def flush(self, _timeout=None) -> int:
        return self._undelivered


def _producer(monkeypatch, undelivered: int = 0) -> list[FakeProducer]:
    made: list[FakeProducer] = []

    def factory(config):
        made.append(FakeProducer(config, undelivered))
        return made[-1]

    monkeypatch.setitem(sys.modules, "confluent_kafka", types.SimpleNamespace(Producer=factory))
    return made


def test_the_dead_letter_producer_publishes_the_message_and_the_reason(monkeypatch):
    made = _producer(monkeypatch)
    dead = DeadLetterProducer("broker:9092")
    dead({"flow": {}}, "KeyError: 'ts'")
    dead(b"\xff not json", "not valid JSON")

    (topic, first), (_, second) = made[0].produced
    assert topic == DEAD_LETTER_TOPIC
    assert json.loads(first) == {"error": "KeyError: 'ts'", "payload": {"flow": {}}}
    assert json.loads(second)["payload"] == "� not json"


def test_an_undelivered_dead_letter_raises_before_the_offset_moves(monkeypatch):
    """Committing past a message the dead-letter topic never received loses it."""
    _producer(monkeypatch, undelivered=1)
    with pytest.raises(RuntimeError, match="dead-letter"):
        DeadLetterProducer("broker:9092")({"flow": {}}, "bad")


class BadBytesKafka:
    def __init__(self, _config, consumer_ref) -> None:
        self._consumer_ref = consumer_ref

    def subscribe(self, _topics) -> None:
        pass

    def poll(self, _timeout):
        self._consumer_ref[0].stop()
        return types.SimpleNamespace(error=lambda: None, value=lambda: b"{truncated")

    def close(self) -> None:
        pass


def test_a_message_that_is_not_json_goes_to_the_dead_letter_topic(monkeypatch):
    ref: list = []
    monkeypatch.setitem(
        sys.modules,
        "confluent_kafka",
        types.SimpleNamespace(Consumer=lambda config: BadBytesKafka(config, ref)),
    )
    dead = DeadLetters()
    consumer = RedpandaConsumer("broker:9092", dead_letter=dead)
    ref.append(consumer)
    assert list(consumer.messages()) == []
    assert dead.sent[0][0] == b"{truncated"
    assert consumer.undecodable == 1


class ScriptedConsumer(ReplayConsumer):
    """Yields a fixed script, None standing for an idle poll, advancing a fake clock
    three seconds per step."""

    def __init__(self, script, now: list[float]) -> None:
        super().__init__([])
        self._script = script
        self._now = now

    def messages(self):
        for item in self._script:
            yield item
            self._now[0] += 3.0


def test_a_partial_batch_is_flushed_on_an_idle_poll_once_it_is_old_enough():
    now = [0.0]
    clickhouse = FakeClickHouse()
    sink = FlowSink(clickhouse.insert, batch_size=100, max_wait=5.0, clock=lambda: now[0])
    # t=0 a flow, t=3 idle (too young), t=6 idle (flush), t=9 another flow.
    consumer = ScriptedConsumer([_payload(0), None, None, _payload(1)], now)
    sink.run(consumer)

    # Two batches, not one: the first went out on the idle poll, before the second
    # flow arrived. The second is the tail flushed when the source ends.
    assert [len(b) for b in clickhouse.batches] == [1, 1]
    assert consumer.commits == 2


class FakeKafka:
    """confluent_kafka.Consumer as the sink sees it: one message, then SIGTERM
    arrives during the next poll. Committing on a closed consumer raises, as the real
    client does."""

    def __init__(self, _config, payload, handlers, events) -> None:
        self._payload = payload
        self._handlers = handlers
        self.events = events
        self._polls = 0
        self._closed = False

    def subscribe(self, _topics) -> None:
        pass

    def poll(self, _timeout):
        self._polls += 1
        if self._polls == 1:
            return FakeMessage(self._payload)
        self._handlers[signal.SIGTERM](signal.SIGTERM, None)
        return None

    def commit(self, asynchronous: bool = True) -> None:
        if self._closed:
            raise RuntimeError("Consumer closed")
        self.events.append("commit")

    def close(self) -> None:
        self._closed = True
        self.events.append("close")


class FakeMessage:
    def __init__(self, payload) -> None:
        self._value = json.dumps(payload).encode("utf-8")

    def error(self):
        return None

    def value(self):
        return self._value


def test_sigterm_commits_the_partial_batch_before_closing(monkeypatch):
    """A stop request must not close the consumer under the tail flush, or its offset
    commit fails and the batch is written again on restart."""
    handlers: dict = {}
    events: list[str] = []
    payload = _payload()
    monkeypatch.setattr(
        flow_sink.signal, "signal", lambda signum, handler: handlers.__setitem__(signum, handler)
    )
    monkeypatch.setitem(
        sys.modules,
        "confluent_kafka",
        types.SimpleNamespace(
            Consumer=lambda config: FakeKafka(config, payload, handlers, events),
            Producer=lambda config: FakeProducer(config),
        ),
    )
    monkeypatch.setattr(
        flow_sink.ClickHouseInserter, "insert", lambda _self, rows: events.append("insert")
    )
    monkeypatch.setenv("CLICKHOUSE_PASSWORD", "test")

    assert flow_sink.main([]) == 0
    assert events == ["insert", "commit", "close"]
