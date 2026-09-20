"""Threat intelligence: the MISP mapping, the upsert, and what a match does.

No MISP instance and no database. The parts worth testing are the mapping and the
rules; that httpx can post is not one of them.
"""

from __future__ import annotations

import pytest

from netsentinel_api.db.models import Alert, AlertIoC, IoC, IoCType, Severity
from netsentinel_api.services.intel import (
    MAX_VALUE_LENGTH,
    IntelError,
    Indicator,
    escalate,
    link,
    lookup_keys,
    match_statement,
    parse_attributes,
    sync,
)


class RecordingSession:
    def __init__(self) -> None:
        self.added: list = []

    def add(self, instance, /) -> None:
        self.added.append(instance)


@pytest.fixture
def session() -> RecordingSession:
    return RecordingSession()


def _response(*attributes) -> dict:
    return {"response": {"Attribute": list(attributes)}}


def _attribute(**overrides) -> dict:
    attribute = {
        "id": "1",
        "event_id": "42",
        "type": "ip-dst",
        "value": "198.51.100.7",
        "to_ids": True,
        "Event": {"threat_level_id": "1"},
    }
    attribute.update(overrides)
    return attribute


# --- parsing ---------------------------------------------------------------

def test_an_address_attribute_becomes_an_indicator():
    indicator = parse_attributes(_response(_attribute()))[0]
    assert indicator.value == "198.51.100.7"
    assert indicator.type is IoCType.ip
    assert indicator.event_id == 42
    assert indicator.threat_level == 1


@pytest.mark.parametrize(
    "misp_type, expected",
    [
        ("ip-src", IoCType.ip),
        ("domain", IoCType.domain),
        ("hostname", IoCType.domain),
        ("url", IoCType.url),
        ("sha256", IoCType.sha256),
        ("ja4", IoCType.ja4),
    ],
)
def test_every_mapped_type_lands_on_its_ioc_type(misp_type, expected):
    parsed = parse_attributes(_response(_attribute(type=misp_type, value="x")))
    assert parsed[0].type is expected


def test_an_unmapped_type_is_dropped_rather_than_guessed():
    """A wrongly typed indicator never matches, which is a silent miss."""
    assert parse_attributes(_response(_attribute(type="btc"))) == []


def test_a_composite_value_keeps_the_half_a_flow_can_match():
    parsed = parse_attributes(
        _response(_attribute(type="ip-dst|port", value="198.51.100.7|443"))
    )
    assert parsed[0].value == "198.51.100.7"


def test_an_oversized_value_is_dropped():
    """iocs.value is VARCHAR(500); a truncated indicator matches nothing."""
    long_url = "http://example.test/" + "a" * MAX_VALUE_LENGTH
    assert parse_attributes(_response(_attribute(type="url", value=long_url))) == []


def test_an_empty_value_is_dropped():
    assert parse_attributes(_response(_attribute(value="   "))) == []


def test_a_missing_threat_level_is_not_invented():
    parsed = parse_attributes(_response(_attribute(Event={})))
    assert parsed[0].threat_level is None


def test_a_response_without_attributes_is_refused():
    with pytest.raises(IntelError, match="no response.Attribute"):
        parse_attributes({"response": {}})


def test_a_non_object_response_is_refused():
    with pytest.raises(IntelError, match="expected an object"):
        parse_attributes([])


# --- sync ------------------------------------------------------------------

def _indicator(value="198.51.100.7", event_id=42, threat_level=1) -> Indicator:
    return Indicator(value=value, type=IoCType.ip, event_id=event_id, threat_level=threat_level)


def test_a_new_indicator_becomes_a_row(session):
    stats = sync(session, [_indicator()], existing=[])
    assert stats.added == 1
    assert session.added[0].value == "198.51.100.7"
    assert session.added[0].type is IoCType.ip


def test_an_unchanged_indicator_is_left_alone(session):
    existing = IoC(ioc_id=1, value="198.51.100.7", type=IoCType.ip, misp_event_id=42, threat_level=1)
    stats = sync(session, [_indicator()], existing=[existing])
    assert (stats.added, stats.updated, stats.skipped) == (0, 0, 1)
    assert session.added == []


def test_an_indicator_that_moved_event_is_updated_in_place(session):
    """A second row would violate uq_ioc_value_type and orphan every alert_iocs link."""
    existing = IoC(ioc_id=1, value="198.51.100.7", type=IoCType.ip, misp_event_id=42, threat_level=3)
    stats = sync(session, [_indicator(event_id=99, threat_level=1)], existing=[existing])

    assert stats.updated == 1
    assert session.added == []
    assert (existing.misp_event_id, existing.threat_level) == (99, 1)


def test_a_duplicate_within_one_feed_collapses_onto_one_row(session):
    """The unique constraint would reject the second insert and fail the whole sync."""
    stats = sync(session, [_indicator(), _indicator()], existing=[])
    assert stats.added == 1
    assert len([row for row in session.added if isinstance(row, IoC)]) == 1


def test_the_same_value_under_two_types_is_two_rows(session):
    """uq_ioc_value_type is on the pair, and a hostname is not an address."""
    both = [
        Indicator(value="evil.test", type=IoCType.domain),
        Indicator(value="evil.test", type=IoCType.url),
    ]
    assert sync(session, both, existing=[]).added == 2


# --- enrichment ------------------------------------------------------------

def test_both_addresses_of_an_alert_are_looked_up():
    alert = Alert(alert_id=1, source="early_flow", severity=Severity.medium,
                  src_ip="10.0.0.5", dst_ip="198.51.100.7")
    assert lookup_keys(alert) == [("10.0.0.5", IoCType.ip), ("198.51.100.7", IoCType.ip)]


def test_an_alert_without_addresses_looks_nothing_up():
    alert = Alert(alert_id=1, source="wazuh", severity=Severity.low)
    assert lookup_keys(alert) == []


def test_a_match_is_recorded_against_the_alert(session):
    alert = Alert(alert_id=5, source="early_flow", severity=Severity.medium)
    ioc = IoC(ioc_id=9, value="198.51.100.7", type=IoCType.ip, threat_level=3)

    assert link(session, alert, [ioc]) == [ioc]
    join = session.added[0]
    assert isinstance(join, AlertIoC)
    assert (join.alert_id, join.ioc_id) == (5, 9)


def test_a_high_threat_match_raises_the_severity_one_band(session):
    alert = Alert(alert_id=5, source="early_flow", severity=Severity.medium)
    link(session, alert, [IoC(ioc_id=9, value="x", type=IoCType.ip, threat_level=1)])
    assert alert.severity is Severity.high


def test_a_low_threat_match_links_without_escalating(session):
    alert = Alert(alert_id=5, source="early_flow", severity=Severity.medium)
    link(session, alert, [IoC(ioc_id=9, value="x", type=IoCType.ip, threat_level=3)])
    assert alert.severity is Severity.medium


def test_several_high_threat_matches_still_raise_only_one_band(session):
    """Four members of one botnet are not four times as urgent as one."""
    alert = Alert(alert_id=5, source="early_flow", severity=Severity.low)
    matches = [
        IoC(ioc_id=index, value=f"198.51.100.{index}", type=IoCType.ip, threat_level=1)
        for index in range(1, 5)
    ]
    link(session, alert, matches)
    assert alert.severity is Severity.medium


def test_no_match_changes_nothing(session):
    alert = Alert(alert_id=5, source="early_flow", severity=Severity.medium)
    assert link(session, alert, []) == []
    assert session.added == []
    assert alert.severity is Severity.medium


def test_escalation_stops_at_critical():
    assert escalate(Severity.critical) is Severity.critical


def test_the_lookup_compiles_for_postgres():
    """The fake session in the writer's tests answers without running this."""
    from sqlalchemy.dialects import postgresql

    alert = Alert(alert_id=1, source="early_flow", severity=Severity.low,
                  src_ip="10.0.0.5", dst_ip="198.51.100.7")
    sql = str(match_statement(lookup_keys(alert)).compile(dialect=postgresql.dialect()))

    # The pair, not the value alone: a hostname and an address can share a string.
    assert "(iocs.value, iocs.type) IN" in sql
