"""HTTP behaviour: authentication, authorisation, and the approval endpoint."""

from __future__ import annotations

from netsentinel_api.db.models import ActionStatus, AlertStatus
from netsentinel_core.features.contract import FEATURE_DIM

V1 = "/api/v1"


# --- health ----------------------------------------------------------------

def test_health_reports_the_feature_dimension(client):
    response = client.get(f"{V1}/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    # A sensor or model built against a different contract is what this catches.
    assert body["feature_dim"] == FEATURE_DIM


# --- login -----------------------------------------------------------------

def test_login_returns_a_usable_token(client, analyst, analyst_password):
    response = client.post(
        f"{V1}/auth/token",
        data={"username": analyst.username, "password": analyst_password},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0

    me = client.get(f"{V1}/auth/me",
                    headers={"Authorization": f"Bearer {body['access_token']}"})
    assert me.status_code == 200
    assert me.json()["username"] == analyst.username


def test_me_reports_the_callers_permissions(client, auth_header):
    """The dashboard needs these to avoid offering a button that only ever 403s."""
    response = client.get(f"{V1}/auth/me", headers=auth_header)
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "soc_analyst"
    assert "approvals:decide" in body["permissions"]
    assert "models:deploy" not in body["permissions"]


def test_me_permissions_match_the_role_not_the_token(client, engineer_header):
    response = client.get(f"{V1}/auth/me", headers=engineer_header)
    body = response.json()
    assert body["role"] == "ml_engineer"
    assert "models:deploy" in body["permissions"]
    assert "approvals:decide" not in body["permissions"]


def test_login_never_returns_the_password_hash(client, analyst, analyst_password):
    response = client.post(
        f"{V1}/auth/token",
        data={"username": analyst.username, "password": analyst_password},
    )
    token = response.json()["access_token"]
    me = client.get(f"{V1}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert "password_hash" not in me.json()
    assert "password" not in me.json()


def test_wrong_password_is_rejected_and_recorded(client, analyst, session):
    response = client.post(
        f"{V1}/auth/token", data={"username": analyst.username, "password": "wrong"}
    )
    assert response.status_code == 401
    entries = session.audit_entries()
    assert [e.action for e in entries] == ["auth.login_failed"]
    # The attempted password must never reach the log.
    assert "wrong" not in str(entries[0].details)


def test_unknown_user_gets_the_same_message_as_a_wrong_password(client, analyst):
    unknown = client.post(
        f"{V1}/auth/token", data={"username": "nobody", "password": "x"}
    )
    wrong = client.post(
        f"{V1}/auth/token", data={"username": analyst.username, "password": "x"}
    )
    assert unknown.status_code == wrong.status_code == 401
    # Identical, so username enumeration learns nothing.
    assert unknown.json() == wrong.json()


def test_deactivated_account_cannot_log_in(client, analyst, session, analyst_password):
    analyst.is_active = False
    response = client.post(
        f"{V1}/auth/token",
        data={"username": analyst.username, "password": analyst_password},
    )
    assert response.status_code == 401
    assert session.audit_entries()[0].details["reason"] == "inactive_account"


def test_a_valid_token_for_a_deactivated_user_stops_working(client, analyst, auth_header):
    """Revocation is immediate because the user is loaded per request."""
    assert client.get(f"{V1}/alerts", headers=auth_header).status_code == 200
    analyst.is_active = False
    assert client.get(f"{V1}/alerts", headers=auth_header).status_code == 401


# --- authentication on protected routes ------------------------------------

def test_alerts_require_a_token(client):
    response = client.get(f"{V1}/alerts")
    assert response.status_code == 401


def test_a_garbage_token_is_rejected(client):
    response = client.get(f"{V1}/alerts", headers={"Authorization": "Bearer nonsense"})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


# --- alerts ---------------------------------------------------------------

def test_list_alerts(client, auth_header):
    response = client.get(f"{V1}/alerts", headers=auth_header)
    assert response.status_code == 200
    assert [row["alert_id"] for row in response.json()] == [100]


def test_alerts_can_be_filtered_by_status(client, auth_header):
    assert client.get(f"{V1}/alerts?status=new", headers=auth_header).json() != []
    assert client.get(f"{V1}/alerts?status=escalated", headers=auth_header).json() == []


def test_page_size_is_capped(client, auth_header):
    assert client.get(f"{V1}/alerts?limit=500", headers=auth_header).status_code == 422


def test_alert_detail_ranks_features_by_absolute_contribution(client, auth_header):
    response = client.get(f"{V1}/alerts/100", headers=auth_header)
    assert response.status_code == 200
    explanation = response.json()["explanation"]

    assert explanation["risk_score"] == 0.93
    # pkt_rate 0.42, duration_ms -0.11, in_bytes 0.05: a negative contribution is
    # still a strong one.
    assert explanation["top_features"] == ["pkt_rate", "duration_ms", "in_bytes"]
    assert explanation["shadow"] is False


def test_alert_detail_includes_linked_iocs(client, auth_header):
    response = client.get(f"{V1}/alerts/100", headers=auth_header)
    assert response.json()["ioc_values"] == ["203.0.113.9"]


def test_missing_alert_is_a_404(client, auth_header):
    assert client.get(f"{V1}/alerts/999", headers=auth_header).status_code == 404


def test_triage_updates_status_and_is_audited(client, auth_header, session, alert):
    response = client.patch(
        f"{V1}/alerts/100/status", json={"status": "closed_false_positive"}, headers=auth_header
    )
    assert response.status_code == 200
    assert alert.status is AlertStatus.closed_false_positive

    entry = session.audit_entries()[-1]
    assert entry.action == "alert.status_changed"
    assert entry.details == {"from": "new", "to": "closed_false_positive"}


def test_an_ml_engineer_cannot_triage(client, engineer_header):
    """Read access does not imply the right to close an alert."""
    response = client.patch(
        f"{V1}/alerts/100/status", json={"status": "closed_false_positive"},
        headers=engineer_header,
    )
    assert response.status_code == 403
    assert "alerts:triage" in response.json()["detail"]


# --- the approval endpoint ------------------------------------------------

def test_pending_queue_lists_the_action(client, auth_header):
    response = client.get(f"{V1}/actions/pending", headers=auth_header)
    assert response.status_code == 200
    assert [row["action_id"] for row in response.json()] == [500]


def test_approving_moves_the_action_to_approved(client, auth_header, action, session):
    response = client.post(
        f"{V1}/actions/500/decision",
        json={"decision": "approved", "comment": "confirmed scan"},
        headers=auth_header,
    )
    assert response.status_code == 200
    assert action.status is ActionStatus.approved
    # Not executed by the API: an executor does that and calls mark_executed.
    assert action.executed_at is None
    assert response.json()["status"] == "approved"
    assert [e.action for e in session.audit_entries()] == ["response.approved"]


def test_rejecting_requires_a_comment(client, auth_header, action):
    response = client.post(
        f"{V1}/actions/500/decision", json={"decision": "rejected"}, headers=auth_header
    )
    assert response.status_code == 422
    assert "comment" in response.json()["detail"]
    assert action.status is ActionStatus.pending_approval


def test_rejecting_with_a_comment_is_accepted(client, auth_header, action):
    response = client.post(
        f"{V1}/actions/500/decision",
        json={"decision": "rejected", "comment": "known scanner"},
        headers=auth_header,
    )
    assert response.status_code == 200
    assert action.status is ActionStatus.rejected


def test_deciding_twice_is_a_conflict(client, auth_header):
    first = client.post(
        f"{V1}/actions/500/decision", json={"decision": "approved"}, headers=auth_header
    )
    assert first.status_code == 200
    second = client.post(
        f"{V1}/actions/500/decision", json={"decision": "approved"}, headers=auth_header
    )
    assert second.status_code == 409


def test_an_ml_engineer_cannot_approve_a_response(client, engineer_header, action):
    """Separation of duties, enforced at the endpoint."""
    response = client.post(
        f"{V1}/actions/500/decision", json={"decision": "approved"}, headers=engineer_header
    )
    assert response.status_code == 403
    assert "approvals:decide" in response.json()["detail"]
    assert action.status is ActionStatus.pending_approval


def test_deciding_on_a_missing_action_is_a_404(client, auth_header):
    response = client.post(
        f"{V1}/actions/999/decision", json={"decision": "approved"}, headers=auth_header
    )
    assert response.status_code == 404
