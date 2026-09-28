"""What the writer decides to store, and what it refuses to.

The decisions under test are the ones a reviewer would argue about: which flows earn
a row, whether a shadow verdict can raise an alert, and what happens when the stream
stops matching the build.
"""

from __future__ import annotations

import contextlib
import signal
import sys
import types

import pytest

from netsentinel_api.db.models import (
    Alert,
    AlertIoC,
    AlertStatus,
    Detection,
    IoC,
    IoCType,
    Severity,
)
from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_writer.consumer import ReplayConsumer
from netsentinel_writer.writer import (
    ContractMismatch,
    DetectionWriter,
    WriterError,
    severity_for,
)

SENSOR_ID, MODEL_ID = 3, 7


@pytest.fixture
def writer(explainer, session):
    return DetectionWriter(lambda: session, explainer, SENSOR_ID, MODEL_ID)


def _rows(session, kind):
    return [row for row in session.added if isinstance(row, kind)]


# --- severity --------------------------------------------------------------

@pytest.mark.parametrize(
    "risk, technique, expected",
    [
        # harmful: exploitation, denial of service
        (0.99, "T1190", Severity.critical),
        (0.95, "T1499", Severity.critical),
        (0.90, "T1190", Severity.high),
        (0.72, "T1499", Severity.medium),
        # kind not known
        (0.99, None, Severity.high),
        (0.90, None, Severity.medium),
        (0.72, None, Severity.low),
        # a scan
        (0.99, "T1046", Severity.medium),
        (0.90, "T1046", Severity.low),
        (0.72, "T1046", Severity.low),
        (0.51, "T1190", Severity.low),
    ],
)
def test_severity_is_how_sure_and_how_harmful(risk, technique, expected):
    assert severity_for(risk, technique) is expected


def test_critical_needs_a_harmful_attack_not_only_certainty():
    assert severity_for(0.9999) is not Severity.critical
    assert severity_for(0.9999, "T1190") is Severity.critical


def test_an_unknown_attack_never_ranks_below_a_known_scan():
    """Undecided is not benign: not knowing the kind must not reassure."""
    ladder = [Severity.low, Severity.medium, Severity.high, Severity.critical]
    for risk in (0.72, 0.9, 0.99):
        assert ladder.index(severity_for(risk)) >= ladder.index(severity_for(risk, "T1046"))


# --- the ordinary path -----------------------------------------------------

def test_a_decided_flow_becomes_an_explained_detection(writer, session, make_payload):
    detection = writer.handle(session, make_payload())

    assert isinstance(detection, Detection)
    assert detection.sensor_id == SENSOR_ID
    assert detection.model_id == MODEL_ID
    assert detection.risk_score == pytest.approx(0.9)
    assert detection.shadow is False
    assert set(detection.shap_values) == set(TIER_A_FEATURES)
    assert writer.stats.detections == 1


def test_an_alerting_verdict_raises_an_alert(writer, session, make_payload):
    writer.handle(session, make_payload(risk_score=0.97))

    alert = _rows(session, Alert)[0]
    # Sure, but with no family model the kind of attack is not known.
    assert alert.severity is Severity.high
    assert alert.status is AlertStatus.new
    assert alert.src_ip == "10.0.0.5"
    assert alert.dst_ip == "10.0.0.9"
    assert alert.source == "early_flow"
    assert writer.stats.alerts == 1


def test_the_alert_points_at_its_detection(writer, session, make_payload):
    """Without the flush the alert would reference nothing."""
    detection = writer.handle(session, make_payload())
    assert _rows(session, Alert)[0].detection_id == detection.detection_id
    assert detection.detection_id is not None


def test_a_detection_below_the_alert_threshold_is_still_stored(writer, session, make_payload):
    """Above the threshold but not flagged: the analyst can still go looking."""
    writer.handle(session, make_payload(risk_score=0.6, is_alert=False))
    assert len(_rows(session, Detection)) == 1
    assert _rows(session, Alert) == []


# --- what does not get stored ----------------------------------------------

def test_a_flow_under_the_threshold_is_counted_not_stored(writer, session, make_payload):
    """ClickHouse has every flow; PostgreSQL is for the ones that mean something."""
    assert writer.handle(session, make_payload(risk_score=0.2, is_alert=False)) is None
    assert session.added == []
    assert writer.stats.below_threshold == 1
    assert writer.stats.detections == 0


# --- shadow mode -----------------------------------------------------------

def test_an_undecided_verdict_is_recorded_against_the_shadow_tier(
    writer, session, make_payload
):
    """Otherwise a shadow period could never be evaluated afterwards."""
    detection = writer.handle(
        session,
        make_payload(risk_score=None, threshold=None, shadow=True, is_alert=False,
                     model_scores={"tier_a": 0.88}),
    )

    assert detection.risk_score == pytest.approx(0.88)
    assert detection.shadow is True
    assert writer.stats.shadow == 1


def test_a_shadow_verdict_never_alerts(writer, session, make_payload):
    """A model nobody promoted must not page anyone, whatever it claims."""
    writer.handle(
        session,
        make_payload(risk_score=None, threshold=None, shadow=True, is_alert=True,
                     model_scores={"tier_a": 0.99}),
    )
    assert _rows(session, Alert) == []
    assert writer.stats.alerts == 0


def test_a_quiet_shadow_flow_is_judged_by_the_cards_threshold(writer, session, make_payload):
    """With no fused threshold to use, the tier's own is the only honest one."""
    assert (
        writer.handle(
            session,
            make_payload(risk_score=None, threshold=None, shadow=True, is_alert=False,
                         model_scores={"tier_a": 0.1}),
        )
        is None
    )
    assert writer.stats.below_threshold == 1


def test_a_shadow_verdict_without_its_tiers_score_is_refused(writer, session, make_payload):
    with pytest.raises(WriterError, match="tier_a"):
        writer.handle(
            session,
            make_payload(risk_score=None, threshold=None, shadow=True,
                         model_scores={"tier_d": 0.4}),
        )


# --- refusals --------------------------------------------------------------

def test_a_stream_on_another_contract_stops_the_writer(writer, session, make_payload):
    """Not a bad message - the wrong pipeline. Every one after it is wrong too."""
    with pytest.raises(ContractMismatch, match="features"):
        writer.handle(session, make_payload(features=12))
    assert session.added == []


def test_a_flow_the_explaining_tier_did_not_score_is_refused(writer, session, make_payload):
    """shap_values is NOT NULL: an unexplained detection must be unrepresentable."""
    with pytest.raises(WriterError, match="did not score"):
        writer.handle(
            session,
            make_payload(models=[{"tier": "D", "name": "tier_d_iforest",
                                  "version": "0.1.0", "mode": "active"}]),
        )
    assert session.added == []


# --- threat intelligence ---------------------------------------------------

def test_an_alert_is_linked_to_the_indicator_it_touched(writer, session, make_payload):
    session.iocs = [IoC(ioc_id=9, value="198.51.100.7", type=IoCType.ip, threat_level=3)]
    writer.handle(session, make_payload())

    link = _rows(session, AlertIoC)[0]
    assert link.ioc_id == 9
    assert link.alert_id == _rows(session, Alert)[0].alert_id
    assert writer.stats.enriched == 1


def test_a_high_threat_indicator_raises_the_severity(writer, session, make_payload):
    session.iocs = [IoC(ioc_id=9, value="198.51.100.7", type=IoCType.ip, threat_level=1)]
    writer.handle(session, make_payload(risk_score=0.90))

    # medium on the score alone, high once intelligence backs it.
    assert _rows(session, Alert)[0].severity is Severity.high


def test_an_alert_matching_nothing_is_stored_unenriched(writer, session, make_payload):
    writer.handle(session, make_payload())
    assert _rows(session, AlertIoC) == []
    assert writer.stats.enriched == 0


def test_a_detection_without_an_alert_is_not_enriched(writer, session, make_payload):
    """Enrichment describes an alert; a detection nobody was told about has none."""
    session.iocs = [IoC(ioc_id=9, value="198.51.100.7", type=IoCType.ip, threat_level=1)]
    writer.handle(session, make_payload(risk_score=0.6, is_alert=False))
    assert _rows(session, AlertIoC) == []


# --- the SOAR hand-off -----------------------------------------------------

class RecordingForwarder:
    def __init__(self, fails: bool = False) -> None:
        self.sent: list = []
        self.fails = fails

    def send(self, alert, iocs):
        if self.fails:
            raise RuntimeError("Keep is down")
        self.sent.append((alert, list(iocs)))


def test_an_alert_is_forwarded_after_the_transaction(explainer, session, make_payload):
    """Never inside it: a network round trip must not hold a row lock."""
    forwarder = RecordingForwarder()
    writer = DetectionWriter(lambda: session, explainer, SENSOR_ID, MODEL_ID, forwarder)

    writer.run(ReplayConsumer([make_payload()]))
    assert len(forwarder.sent) == 1
    assert forwarder.sent[0][0] is _rows(session, Alert)[0]


def test_a_stored_detection_without_an_alert_forwards_nothing(
    explainer, session, make_payload
):
    forwarder = RecordingForwarder()
    writer = DetectionWriter(lambda: session, explainer, SENSOR_ID, MODEL_ID, forwarder)

    writer.run(ReplayConsumer([make_payload(risk_score=0.6, is_alert=False)]))
    assert forwarder.sent == []


def test_a_soar_outage_does_not_stop_the_writer(explainer, session, make_payload):
    """The database is the evidence; Keep is the notification."""
    writer = DetectionWriter(
        lambda: session, explainer, SENSOR_ID, MODEL_ID, RecordingForwarder(fails=True)
    )

    stats = writer.run(ReplayConsumer([make_payload(), make_payload()]))
    assert stats.alerts == 2
    assert len(_rows(session, Alert)) == 2


def test_an_alert_is_forwarded_once(explainer, session, make_payload):
    """The queue is drained, not appended to, or every message resends the backlog."""
    forwarder = RecordingForwarder()
    writer = DetectionWriter(lambda: session, explainer, SENSOR_ID, MODEL_ID, forwarder)

    writer.run(ReplayConsumer([make_payload(), make_payload()]))
    assert len(forwarder.sent) == 2


# --- the loop --------------------------------------------------------------

def test_the_offset_is_committed_after_the_database(writer, session, make_payload):
    """The other order turns a crash into evidence that was never collected."""
    consumer = ReplayConsumer([make_payload(), make_payload(risk_score=0.1, is_alert=False)])
    stats = writer.run(consumer)

    assert stats.messages == 2
    assert stats.detections == 1
    assert session.commits == 2
    assert consumer.commits == 2


def test_a_refusal_leaves_the_offset_uncommitted(writer, session, make_payload):
    """A message that was not written must be redelivered, not skipped."""
    consumer = ReplayConsumer([make_payload(features=12)])
    with pytest.raises(ContractMismatch):
        writer.run(consumer)
    assert consumer.commits == 0


class _KafkaStoppedMidMessage:
    """confluent_kafka.Consumer whose one message is in flight when SIGTERM arrives.
    Committing on a closed consumer raises, as the real client does."""

    def __init__(self, handlers, events) -> None:
        self._handlers, self.events, self._closed = handlers, events, False

    def subscribe(self, _topics) -> None:
        pass

    def poll(self, _timeout):
        return types.SimpleNamespace(error=lambda: None, value=lambda: b"{}")

    def commit(self, asynchronous: bool = True) -> None:
        if self._closed:
            raise RuntimeError("Consumer closed")
        self.events.append("commit")

    def close(self) -> None:
        self._closed = True
        self.events.append("close")


def test_sigterm_mid_message_still_commits_its_offset(monkeypatch):
    """Closing the consumer from the signal handler made the in-flight message's
    offset commit raise, so the message was written again on restart."""
    from netsentinel_writer import main as entry

    handlers: dict = {}
    events: list[str] = []
    kafka = _KafkaStoppedMidMessage(handlers, events)
    monkeypatch.setattr(entry.signal, "signal", lambda signum, h: handlers.__setitem__(signum, h))
    monkeypatch.setitem(
        sys.modules, "confluent_kafka", types.SimpleNamespace(Consumer=lambda _config: kafka)
    )
    monkeypatch.setattr(entry, "load_explainer", lambda *_: types.SimpleNamespace(
        name="m", version="1", tier="A", identity="m:1"))
    monkeypatch.setattr(entry, "get_sessionmaker", lambda: contextlib.nullcontext)
    monkeypatch.setattr(entry, "resolve_model_id", lambda *_: 1)
    monkeypatch.setattr(entry, "resolve_sensor_id", lambda _s, sensor_id: sensor_id)
    monkeypatch.setattr(entry, "get_settings", lambda: None)
    monkeypatch.setattr(entry, "forwarder_from", lambda _settings: None)

    class Writer:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def run(self, consumer):
            for _message in consumer.messages():
                handlers[signal.SIGTERM](signal.SIGTERM, None)  # while it is handled
                consumer.commit()
            return types.SimpleNamespace(as_dict=dict)

    monkeypatch.setattr(entry, "DetectionWriter", Writer)

    assert entry.main(["--card", "card.json", "--sensor-id", "1"]) == 0
    assert events == ["commit", "close"]


def test_a_paced_replay_waits_between_flows_but_not_before_the_first():
    """--replay-interval: a demonstration shows alerts arriving one at a time."""
    waits: list[float] = []
    consumer = ReplayConsumer([{"n": 1}, {"n": 2}, {"n": 3}], interval=2.5, sleep=waits.append)

    assert [payload["n"] for payload in consumer.messages()] == [1, 2, 3]
    assert waits == [2.5, 2.5]


def test_an_unpaced_replay_never_sleeps():
    waits: list[float] = []
    consumer = ReplayConsumer([{"n": 1}, {"n": 2}], sleep=waits.append)

    assert len(list(consumer.messages())) == 2
    assert waits == []


def test_a_revoked_sensor_is_refused_at_startup():
    """An administrator revoking a sensor on the Admin page stops its ingest."""
    from netsentinel_api.db.models import Sensor
    from netsentinel_writer.main import StartupError, resolve_sensor_id

    rows = {1: Sensor(sensor_id=1, revoked=False), 2: Sensor(sensor_id=2, revoked=True)}
    session = types.SimpleNamespace(get=lambda _model, key: rows.get(key))

    assert resolve_sensor_id(session, 1) == 1
    with pytest.raises(StartupError, match="revoked"):
        resolve_sensor_id(session, 2)
    with pytest.raises(StartupError, match="no sensor"):
        resolve_sensor_id(session, 3)
