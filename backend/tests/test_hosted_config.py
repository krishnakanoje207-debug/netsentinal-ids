"""Hosted deployments keep origin access explicit and use the installed DB driver."""
import pytest
from fastapi.testclient import TestClient

from netsentinel_api.app import create_app
from netsentinel_api.config import Settings, cors_origins, database_url


@pytest.mark.parametrize("scheme", ["postgres", "postgresql", "postgresql+psycopg"])
def test_render_database_url_selects_psycopg(monkeypatch, scheme):
    source = f"{scheme}://user:password@db:5432/netsentinel?sslmode=require"
    expected = "postgresql+psycopg://user:password@db:5432/netsentinel?sslmode=require"
    monkeypatch.setenv("NETSENTINEL_DATABASE_URL", source)
    assert database_url() == expected
    settings = Settings(jwt_secret="3nMx57ZqvR8wP2kLdY9cA6sB4hFgTuE1")
    assert settings.database_url == expected


def test_hosted_cors_allows_only_configured_dashboard(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_CORS_ORIGINS", '["https://netsentinel.vercel.app"]')
    with TestClient(create_app(listen_for_alerts=False)) as client:
        headers = {"Origin": "https://netsentinel.vercel.app",
                   "Access-Control-Request-Method": "POST",
                   "Access-Control-Request-Headers": "authorization,content-type"}
        response = client.options("/api/v1/auth/token", headers=headers)
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == headers["Origin"]
        headers["Origin"] = "https://untrusted.example"
        response = client.options("/api/v1/auth/token", headers=headers)
        assert response.status_code == 400
        assert "access-control-allow-origin" not in response.headers


def test_local_default_does_not_enable_cors(monkeypatch):
    monkeypatch.delenv("NETSENTINEL_CORS_ORIGINS", raising=False)
    assert cors_origins() == []


@pytest.mark.parametrize("value", ['"*"', '["*"]', '["https://dashboard.example/path"]', '[null]'])
def test_cors_rejects_wildcards_and_non_origins(monkeypatch, value):
    monkeypatch.setenv("NETSENTINEL_CORS_ORIGINS", value)
    with pytest.raises(ValueError):
        cors_origins()
