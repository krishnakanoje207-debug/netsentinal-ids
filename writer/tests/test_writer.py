"""What the writer decides to store, and what it refuses to.

The decisions under test are the ones a reviewer would argue about: which flows earn
a row, whether a shadow verdict can raise an alert, and what happens when the stream
stops matching the build.
"""

from __future__ import annotations

import pytest

from netsentinel_api.db.models import Alert, AlertStatus, Detection, Severity
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
    "risk, expected",
    [
        (0.99, Severity.critical),
        (0.95, Severity.critical),
        (0.90, Severity.high),
        (0.72, Severity.medium),
        (0.51, Severity.low),
    ],
)
def test_severity_follows_the_calibrated_score(risk, expected):
    assert severity_for(risk) is expected


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
    assert alert.severity is Severity.critical
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
