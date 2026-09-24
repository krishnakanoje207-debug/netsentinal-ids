"""Importing Suricata alerts from eve.json.

What matters is what becomes a row and that a second import of the same file adds
nothing. The eve record below is trimmed from a real run of the lab's web-attack
capture - trimmed, not invented, because the eve schema is the thing a fixture gets
wrong.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from netsentinel_api.db.models import Alert, AuditLog, Severity
from netsentinel_api.services.signatures import EveError, parse_eve, sync
from netsentinel_api.sync_suricata import run

AT = datetime(2026, 9, 24, 4, 20, 43, 130707, tzinfo=timezone.utc)


def _eve(event_type: str = "alert", severity: int = 1,
         metadata: dict | None = None, **overrides) -> str:
    event = {
        "timestamp": "2026-09-24T04:20:43.130707+0000",
        "flow_id": 1103377847043785,
        "event_type": event_type,
        "src_ip": "172.30.0.3",
        "src_port": 48342,
        "dest_ip": "172.30.0.10",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2010963,
            "rev": 7,
            "signature": "ET WEB_SERVER SELECT USER SQL Injection Attempt in URI",
            "category": "Web Application Attack",
            "severity": severity,
            "metadata": metadata if metadata is not None else {
                "mitre_tactic_id": ["TA0001"],
                "mitre_technique_id": ["T1190"],
                "signature_severity": ["Major"],
            },
        },
    }
    event.update(overrides)
    return json.dumps(event)


class StubSession:
    def __init__(self, existing: list[Alert] | None = None) -> None:
        self.added: list[object] = []
        self.existing = existing or []

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def scalars(self, _statement) -> list[Alert]:
        return self.existing


# --- what eve.json says ----------------------------------------------------

def test_an_alert_record_carries_when_who_how_bad_and_the_technique():
    match, = parse_eve([_eve()])
    assert match.at == AT
    assert (match.src_ip, match.dst_ip) == ("172.30.0.3", "172.30.0.10")
    assert match.severity is Severity.high
    assert match.technique == "T1190"


def test_only_alert_records_are_alerts():
    """flow, http and stats records share the file and are not alerts."""
    lines = [_eve(event_type="flow"), "", _eve(), _eve(event_type="stats")]
    assert len(parse_eve(lines)) == 1


@pytest.mark.parametrize(
    ("severity", "expected"),
    [(1, Severity.high), (2, Severity.medium), (3, Severity.low), (4, Severity.info)],
)
def test_suricata_severity_maps_onto_ours(severity, expected):
    match, = parse_eve([_eve(severity=severity)])
    assert match.severity is expected


def test_a_rule_without_a_technique_leaves_the_column_empty():
    assert parse_eve([_eve(metadata={})])[0].technique is None
    assert parse_eve([_eve(metadata={"mitre_technique_id": ["nonsense"]})])[0].technique is None


def test_a_line_that_is_not_json_is_refused_by_number():
    with pytest.raises(EveError, match="line 2"):
        parse_eve([_eve(), "{truncated"])


# --- the insert ------------------------------------------------------------

def test_a_new_match_becomes_a_suricata_alert_with_no_detection():
    session = StubSession()
    assert sync(session, parse_eve([_eve()]), []) == 1

    row, = session.added
    assert (row.source, row.severity, row.mitre_technique) == ("suricata", Severity.high, "T1190")
    assert row.detection_id is None
    assert row.created_at == AT


def test_importing_the_same_file_twice_adds_nothing():
    found = parse_eve([_eve(), _eve()])
    first = StubSession()
    sync(first, found, [])

    second = StubSession()
    assert sync(second, found, first.added) == 0
    assert second.added == []


def test_identical_matches_are_counted_not_collapsed():
    """Two rules can fire on one packet with the same timestamp and addresses."""
    found = parse_eve([_eve(), _eve(), _eve()])
    first = StubSession()
    sync(first, found[:2], [])

    second = StubSession()
    assert sync(second, found, first.added) == 1


def test_a_model_alert_with_the_same_shape_does_not_hide_a_signature_alert():
    model_alert = Alert(source="ml", severity=Severity.high, src_ip="172.30.0.3",
                        dst_ip="172.30.0.10", mitre_technique="T1190", created_at=AT)
    assert sync(StubSession(), parse_eve([_eve()]), [model_alert]) == 1


def test_the_import_is_audited(tmp_path):
    eve = tmp_path / "eve.json"
    eve.write_text(_eve() + "\n" + _eve(event_type="flow") + "\n", encoding="utf-8")
    session = StubSession()

    assert run(session, eve) == {"alerts": 1, "added": 1}
    audit, = [row for row in session.added if isinstance(row, AuditLog)]
    assert audit.action == "alerts.imported"
    assert audit.details == {"alerts": 1, "added": 1}
