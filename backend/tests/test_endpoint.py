"""Local host evidence must be authenticated and missing evidence must stay unknown."""
import json
from datetime import datetime, timedelta, timezone

from netsentinel_api.routes import endpoint


def test_endpoint_requires_auth(client):
    assert client.get('/api/v1/endpoint/status').status_code == 401


def test_missing_snapshot_is_not_healthy(client, auth_header, monkeypatch, tmp_path):
    monkeypatch.setattr(endpoint, 'LOCAL_OUT', tmp_path)
    data = client.get('/api/v1/endpoint/status', headers=auth_header).json()
    assert data['freshness'] == 'unavailable'
    assert data['defender']['available'] is False
    assert data['monitoring']['state'] == 'unknown'
    assert data['scans']['downloads']['state'] == 'not_run'


def test_old_running_monitor_is_stale(client, auth_header, monkeypatch, tmp_path):
    monkeypatch.setattr(endpoint, 'LOCAL_OUT', tmp_path)
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    (tmp_path / 'live').mkdir()
    (tmp_path / 'live' / 'status.json').write_text(json.dumps({'state': 'running', 'updated_at': old}))
    (tmp_path / 'endpoint.json').write_text(json.dumps({'collected_at': old,
        'scans': {'quick': {'state': 'failed', 'error': 'access denied'}}}))
    data = client.get('/api/v1/endpoint/status', headers=auth_header).json()
    assert data['freshness'] == 'stale'
    assert data['monitoring']['freshness'] == 'stale'
    assert data['scans']['quick']['state'] == 'failed'


def test_malformed_snapshot_does_not_fake_success(client, auth_header, monkeypatch, tmp_path):
    monkeypatch.setattr(endpoint, 'LOCAL_OUT', tmp_path)
    (tmp_path / 'endpoint.json').write_text('{partial')
    data = client.get('/api/v1/endpoint/status', headers=auth_header).json()
    assert data['freshness'] == 'unavailable'


def test_sensor_freshness_uses_real_output_files(client, auth_header, monkeypatch, tmp_path):
    monkeypatch.setattr(endpoint, 'LOCAL_OUT', tmp_path)
    run = '20261101-120000-123'
    run_dir = tmp_path / 'live' / run
    (run_dir / 'windows').mkdir(parents=True)
    (run_dir / 'windows' / '0001.pcapng').write_bytes(b'capture')
    (run_dir / 'flows.jsonl').write_text('{"flow_id":"one"}\n')
    (tmp_path / 'live' / 'status.json').write_text(json.dumps({'run': run, 'state': 'running',
        'updated_at': datetime.now(timezone.utc).isoformat()}))
    response = client.get('/api/v1/endpoint/status', headers=auth_header)
    data = response.json()['monitoring']
    assert response.headers['cache-control'] == 'no-store'
    assert data['freshness'] == 'fresh'
    assert data['latest_capture_at'] is not None
    assert data['latest_scored_flow_at'] is not None
