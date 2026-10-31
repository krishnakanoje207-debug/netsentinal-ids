"""Google sign-in preserves locally assigned access and fails closed."""

import pytest
from google.auth.exceptions import GoogleAuthError, TransportError

from netsentinel_api.routes import auth
from netsentinel_api.google_auth import verify_google_credential

URL = "/api/v1/auth/google"


def enable(settings, username="admin"):
    settings.google_client_id = "console.apps.googleusercontent.com"
    settings.google_accounts = {"google-subject": username}


def test_unconfigured_google_does_not_disable_local_login(client, analyst, analyst_password):
    assert client.get(f"{URL}/config").json() == {"client_id": None}
    assert client.post(URL, json={"credential": "token"}).status_code == 503
    assert client.post("/api/v1/auth/token", data={
        "username": analyst.username, "password": analyst_password,
    }).status_code == 200


def test_google_returns_local_role_not_browser_role(client, settings, administrator, session, monkeypatch):
    enable(settings)
    monkeypatch.setattr(auth, "verify_google_credential", lambda *_: {
        "sub": "google-subject", "email_verified": True, "role": "viewer",
    })
    result = client.post(URL, json={"credential": "token"})
    assert result.status_code == 200
    session.user = administrator
    me = client.get("/api/v1/auth/me", headers={
        "Authorization": f"Bearer {result.json()['access_token']}",
    }).json()
    assert me["role"] == "administrator"
    assert "users:manage" in me["permissions"]
    assert session.audit_entries()[0].details["provider"] == "google"


@pytest.mark.parametrize("claims", [
    {"sub": "stranger", "email": "other@gmail.com"},
    {"sub": "stranger", "email": "admin@example.test"},
])
def test_unknown_identity_is_rejected_and_audited(client, settings, session, monkeypatch, claims):
    enable(settings)
    monkeypatch.setattr(auth, "verify_google_credential", lambda *_: claims)
    assert client.post(URL, json={"credential": "token"}).status_code == 401
    assert session.committed
    assert session.audit_entries()[0].action == "auth.login_failed"


def test_gmail_allowlist_and_disabled_local_account(client, settings, administrator, monkeypatch):
    enable(settings)
    settings.google_gmail_accounts = {"owner@gmail.com": "admin"}
    monkeypatch.setattr(auth, "verify_google_credential", lambda *_: {
        "sub": "gmail-subject", "email": "owner@gmail.com",
    })
    assert client.post(URL, json={"credential": "token"}).status_code == 200
    administrator.is_active = False
    assert client.post(URL, json={"credential": "token"}).status_code == 401


def test_invalid_google_token_is_rejected(client, settings, monkeypatch):
    enable(settings)
    def invalid(*_):
        raise ValueError("invalid signature or audience")
    monkeypatch.setattr(auth, "verify_google_credential", invalid)
    assert client.post(URL, json={"credential": "token"}).status_code == 401


@pytest.mark.parametrize("error, status", [(GoogleAuthError("wrong issuer"), 401), (
    TransportError("certificates unavailable"), 503,
)])
def test_google_failure_status(client, settings, monkeypatch, error, status):
    enable(settings)
    def fail(*_):
        raise error
    monkeypatch.setattr(auth, "verify_google_credential", fail)
    assert client.post(URL, json={"credential": "token"}).status_code == status


def test_installed_google_verifier_rejects_malformed_token(client, settings, monkeypatch):
    enable(settings)
    # Keep signature/claim verification real, replacing only the network fetch.
    monkeypatch.setattr("netsentinel_api.google_auth.id_token._fetch_certs", lambda *_: {})
    assert client.post(URL, json={"credential": "malformed-token"}).status_code == 401


@pytest.mark.parametrize("claims", [{"sub": "id"}, {"email_verified": True}, {
    "sub": "id", "email_verified": "true",
}])
def test_verifier_requires_verified_email_and_subject(monkeypatch, claims):
    monkeypatch.setattr("netsentinel_api.google_auth.id_token.verify_oauth2_token", lambda *_args, **_kw: claims)
    with pytest.raises(ValueError):
        verify_google_credential("token", "client")
