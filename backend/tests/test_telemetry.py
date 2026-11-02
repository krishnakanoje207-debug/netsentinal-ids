"""Cloud credential isolation, whitelist enforcement and retry-safe export."""
import json

import httpx
import pytest
from pydantic import SecretStr, ValidationError

from netsentinel_api.services.telemetry import TelemetryBatch, export_alert
from netsentinel_api.sync_telemetry import sync_once

TOKEN = "telemetry-test-credential-" + "x" * 32
HOST = "host_" + "a" * 24


def payload():
    return {"host_id": HOST, "alerts": [{"local_alert_id": 1, "occurred_at": "2026-11-02T16:00:00Z",
                                          "severity": "low", "source": "wazuh", "rule_id": "92052"}]}


def test_disabled_by_default(client):
    assert client.post("/api/v1/telemetry/alerts", json=payload()).status_code == 503


def test_write_credential_cannot_read_dashboard(client, settings):
    settings.telemetry_token = SecretStr(TOKEN)
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/api/v1/alerts", headers=headers).status_code == 401


def test_dashboard_jwt_and_wrong_token_cannot_ingest(client, settings, auth_header):
    settings.telemetry_token = SecretStr(TOKEN)
    for headers in [{}, auth_header, {"Authorization": "Bearer wrong"}]:
        assert client.post("/api/v1/telemetry/alerts", json=payload(), headers=headers).status_code == 401


@pytest.mark.parametrize("field", ["commandLine", "src_ip", "hostname", "browser_history", "source_details"])
def test_extra_fields_refused_at_http_boundary(client, settings, field):
    settings.telemetry_token = SecretStr(TOKEN)
    data = payload()
    data["alerts"][0][field] = "private"
    response = client.post("/api/v1/telemetry/alerts", json=data, headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 422


def test_valid_batch_acknowledged_only_after_commit(client, settings, session, monkeypatch):
    settings.telemetry_token = SecretStr(TOKEN)
    monkeypatch.setattr("netsentinel_api.routes.telemetry.receive", lambda s, batch: 0)
    response = client.post("/api/v1/telemetry/alerts", json=payload(), headers={"Authorization": f"Bearer {TOKEN}"})
    assert response.json() == {"accepted": 1, "added": 0}
    assert session.committed


def test_strict_host_time_and_batch_limits():
    for change in [{"host_id": "real-hostname"}, {"alerts": []}, {"alerts": payload()["alerts"] * 101}]:
        with pytest.raises(ValidationError):
            TelemetryBatch.model_validate({**payload(), **change})
    data = payload()
    data["alerts"][0]["occurred_at"] = "2026-11-02T16:00:00"
    with pytest.raises(ValidationError):
        TelemetryBatch.model_validate(data)


def test_export_drops_every_private_field(alert):
    alert.source_details = {"rule_id": "92052", "commandLine": "private", "agent_name": "private"}
    data = export_alert(alert).model_dump(mode="json")
    assert set(data) == {"local_alert_id", "occurred_at", "severity", "source", "rule_id", "model_id"}
    assert data["source"] == "ml"  # The writer's early_flow name is not sent.
    assert "private" not in json.dumps(data)


def test_failed_send_retains_cursor_and_retry_uses_same_identity(alert):
    class Session:
        def scalars(self, _): return [alert]
    sent, saved = [], []
    def handler(request):
        sent.append(json.loads(request.content))
        return httpx.Response(503 if len(sent) == 1 else 200, json={"accepted": 1})
    state = {"host_id": HOST, "cursor": 0}
    with httpx.Client(base_url="https://cloud.example", transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.HTTPStatusError):
            sync_once(Session(), client, state, saved.append)
        assert state["cursor"] == 0 and saved == []
        assert sync_once(Session(), client, state, saved.append) == 1
    assert sent[0] == sent[1]
    assert state["cursor"] == alert.alert_id
