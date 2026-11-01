"""Cloud calls are opt-in, minimized, authenticated server-side and fail closed."""

import json

import httpx
import pytest
from netsentinel_api.db.models import IoC, IoCType

from netsentinel_copilot.client import CopilotError, GeminiClient
from netsentinel_copilot.main import main
from netsentinel_copilot.summarise import summarise
from test_summarise import StubClient, _alert, _detection


def test_no_key_or_opt_in_means_no_http(monkeypatch):
    monkeypatch.setattr(httpx, "post", lambda *_a, **_k: pytest.fail("unexpected cloud call"))
    with pytest.raises(CopilotError, match="disabled"):
        GeminiClient("secret")
    with pytest.raises(CopilotError, match="GEMINI_API_KEY"):
        GeminiClient("", allow_cloud=True)


def test_cli_without_opt_in_does_not_open_database(monkeypatch):
    monkeypatch.delenv("NETSENTINEL_COPILOT_ALLOW_CLOUD", raising=False)
    monkeypatch.setattr("netsentinel_copilot.main.get_sessionmaker", lambda: pytest.fail("unexpected database access"))
    assert main(["--latest", "10"]) == 2


def test_cli_opted_in_without_key_does_not_open_database(monkeypatch):
    monkeypatch.setenv("NETSENTINEL_COPILOT_ALLOW_CLOUD", "true")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr("netsentinel_copilot.main.get_sessionmaker", lambda: pytest.fail("unexpected database access"))
    assert main(["--latest", "10"]) == 2


def test_gemini_request_uses_header_and_schema(monkeypatch):
    captured = {}
    def post(url, **kwargs):
        captured.update(url=url, **kwargs)
        return httpx.Response(200, request=httpx.Request("POST", url), json={
            "candidates": [{"finishReason": "STOP", "content": {"parts": [{"text": '{"headline":"ok"}'}]}}],
        })
    monkeypatch.setattr(httpx, "post", post)
    client = GeminiClient("secret-key", allow_cloud=True)
    assert client.complete("instructions", "evidence", {"type": "object"}) == {"headline": "ok"}
    assert captured["headers"] == {"x-goog-api-key": "secret-key"}
    assert "secret-key" not in captured["url"]
    assert captured["url"].endswith("/models/gemini-3.5-flash-lite:generateContent")
    config = captured["json"]["generationConfig"]
    assert config["responseFormat"]["text"] == {
        "mimeType": "APPLICATION_JSON", "schema": {"type": "object"},
    }
    assert "temperature" not in config
    assert "tools" not in captured["json"]


@pytest.mark.parametrize("status", [400, 401, 403, 429, 500])
def test_http_failures_do_not_expose_key_or_body(monkeypatch, status):
    monkeypatch.setattr(httpx, "post", lambda url, **_: httpx.Response(
        status, request=httpx.Request("POST", url), text="secret-key",
    ))
    with pytest.raises(CopilotError, match=f"HTTP {status}") as error:
        GeminiClient("secret-key", allow_cloud=True).complete("", "", {})
    assert "secret-key" not in str(error.value)


def test_transport_error_does_not_expose_key(monkeypatch):
    def fail(*_a, **_kw):
        raise httpx.ReadTimeout("secret-key")
    monkeypatch.setattr(httpx, "post", fail)
    with pytest.raises(CopilotError, match="could not be reached") as error:
        GeminiClient("secret-key", allow_cloud=True).complete("", "", {})
    assert "secret-key" not in str(error.value)


@pytest.mark.parametrize("candidate", [{}, {"finishReason": "MAX_TOKENS"}, {
    "finishReason": "STOP", "content": {"parts": []},
}])
def test_incomplete_or_blocked_replies_are_not_summaries(monkeypatch, candidate):
    monkeypatch.setattr(httpx, "post", lambda url, **_: httpx.Response(
        200, request=httpx.Request("POST", url), json={"candidates": [candidate]},
    ))
    with pytest.raises(CopilotError):
        GeminiClient("key", allow_cloud=True).complete("", "", {})


@pytest.mark.parametrize("payload", [[], {"candidates": "bad"}, {
    "candidates": [{"finishReason": "STOP", "content": {"parts": "bad"}}],
}])
def test_malformed_provider_response_fails_closed(monkeypatch, payload):
    monkeypatch.setattr(httpx, "post", lambda url, **_: httpx.Response(
        200, request=httpx.Request("POST", url), json=payload,
    ))
    with pytest.raises(CopilotError):
        GeminiClient("key", allow_cloud=True).complete("", "", {})


def test_cloud_prompt_omits_identity_and_restores_aliases_locally():
    client = StubClient(reply={
        "headline": "SOURCE_ENDPOINT contacted DESTINATION_ENDPOINT",
        "what_happened": "SOURCE_ENDPOINT connected to DESTINATION_ENDPOINT with 93% risk.",
        "why_it_scored": "Packets per second pushed toward attack.",
        "assessment": "needs_investigation", "next_steps": ["Check SOURCE_ENDPOINT"],
    })
    client.cloud = True
    alert = _alert(source="private-hostname", mitre_technique="private-domain.test",
                   detection=_detection(shap_values={"secret-host": 1, "pkt_rate": 0.5}))
    iocs = [IoC(ioc_id=1, type=IoCType.domain, value="private-indicator.test")]
    payload, summary = summarise(client, alert, iocs)
    assert summary is not None
    transmitted = json.dumps(client.calls)
    for private in ["203.0.113.9", "10.0.0.9", "private-hostname", "private-domain.test", "private-indicator.test", "secret-host", "alert id"]:
        assert private not in transmitted
    assert "203.0.113.9" in payload["headline"]
    assert "10.0.0.9" in payload["headline"]


def test_cloud_summary_retains_direction_rejection():
    client = StubClient(reply={
        "headline": "DESTINATION_ENDPOINT connected to SOURCE_ENDPOINT",
        "what_happened": "Investigate the connection.",
        "why_it_scored": "Packet rate pushed toward attack.",
        "assessment": "needs_investigation", "next_steps": ["Check source"],
    })
    client.cloud = True
    assert summarise(client, _alert())[1] is None
