"""Display only local labels tied to alerts readable by the caller."""


def test_endpoint_labels_require_authentication(client):
    assert client.get('/api/v1/alerts/endpoint-labels').status_code == 401


def test_viewer_sees_alert_labels_without_inventory_access(client, viewer_header, settings, alert):
    settings.endpoint_labels = {
        str(alert.src_ip): 'This computer', str(alert.dst_ip): 'Network gateway',
        '10.0.0.250': 'Unrelated private setting', 'invalid': 'Invalid address',
    }
    response = client.get('/api/v1/alerts/endpoint-labels', headers=viewer_header)
    assert response.status_code == 200
    assert response.json() == {str(alert.src_ip): 'This computer', str(alert.dst_ip): 'Network gateway'}
    assert client.get('/api/v1/assets', headers=viewer_header).status_code == 403


def test_endpoint_labels_require_alert_permission(client, engineer_header, session):
    session.user.role.permissions = {'granted': []}
    assert client.get('/api/v1/alerts/endpoint-labels', headers=engineer_header).status_code == 403
