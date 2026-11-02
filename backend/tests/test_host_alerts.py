"""Host evidence keeps provenance without copying private event payloads."""
import json
from datetime import datetime, timezone

import pytest
from sqlalchemy.dialects import postgresql

from netsentinel_api.services.host_alerts import import_alert, parse_alert
from netsentinel_api.sync_wazuh import ingest


@pytest.fixture
def event():
    return {
        "id": "1793620000.123", "timestamp": "2026-11-02T16:00:02Z",
        "agent": {"id": "001", "name": "local-host", "ip": "127.0.0.1"},
        "manager": {"name": "wazuh.manager"},
        "rule": {"id": "92052", "level": 6, "description": "Review process", "mitre": {"id": ["T1059.001"]}},
        "data": {"win": {"system": {"systemTime": "2026-11-02T16:00:00Z", "eventID": "1"},
                         "eventdata": {"image": r"C:\Users\Private\powershell.exe", "processId": "42",
                                       "commandLine": "private-password", "parentImage": r"C:\private.exe"}}},
        "full_log": "private full event",
    }


def test_event_time_and_explicit_evidence_only(event):
    parsed = parse_alert(json.dumps(event))
    assert parsed.at == datetime(2026, 11, 2, 16, tzinfo=timezone.utc)
    assert parsed.src_ip is None and parsed.dst_ip is None
    assert parsed.details["process_image"] == "powershell.exe"
    assert parsed.details["rule_id"] == "92052"
    assert parsed.technique == "T1059.001"
    assert "private" not in json.dumps(parsed.details).lower()
    assert parsed.severity.value == "low"


@pytest.mark.parametrize("level,expected", [(2, None), (3, "low"), (7, "medium"), (11, "high"), (16, "critical")])
def test_level_mapping_retains_original_level(event, level, expected):
    event["rule"]["level"] = level
    parsed = parse_alert(json.dumps(event))
    assert (parsed.severity.value if parsed else None) == expected
    if parsed:
        assert parsed.details["rule_level"] == level


@pytest.mark.parametrize("field,value", [("id", "bad"), ("timestamp", "2026-11-02T16:00:00")])
def test_malformed_identity_and_naive_time_rejected(event, field, value):
    event[field] = value
    with pytest.raises(ValueError):
        parse_alert(json.dumps(event))


def test_atomic_deduplication_and_no_ml_score(event):
    class Capture:
        def scalar(self, statement):
            self.statement = statement
            return 12
    session = Capture()
    assert import_alert(session, parse_alert(json.dumps(event)), asset_id=3) == 12
    compiled = session.statement.compile(dialect=postgresql.dialect())
    assert "ON CONFLICT ON CONSTRAINT uq_alert_source_event DO NOTHING" in str(compiled)
    assert compiled.params["asset_id"] == 3
    assert "detection_id" not in compiled.params


def test_ingest_skips_other_hosts_and_malformed_rows(event, monkeypatch):
    calls = []
    monkeypatch.setattr("netsentinel_api.sync_wazuh.import_alert", lambda *a, **k: calls.append(k) or 1)
    class Session:
        def add(self, _): pass
    other = {**event, "agent": {"id": "002"}}
    stats = ingest(Session(), ["bad", json.dumps(other), json.dumps(event)], agent_id="001", asset_id=4)
    assert stats == {"added": 1, "duplicates": 0, "skipped": 1, "malformed": 1}
    assert calls == [{"asset_id": 4}]
