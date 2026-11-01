"""Opt-in, server-side Gemini summaries over the official REST endpoint.

Only the minimized evidence assembled by summarise.py is sent. The API key stays
in the worker's environment and request header; it is never sent to the browser.
"""

from __future__ import annotations

import re

DEFAULT_MODEL = "gemini-3.5-flash-lite"
REQUEST_TIMEOUT_SECONDS = 120.0


class CopilotError(RuntimeError):
    """The model could not be reached, or did not return usable JSON."""


class GeminiClient:
    cloud = True

    def __init__(self, api_key: str, model: str = DEFAULT_MODEL,
                 timeout: float = REQUEST_TIMEOUT_SECONDS, *, allow_cloud: bool = False) -> None:
        if not allow_cloud:
            raise CopilotError("Cloud summaries are disabled; set NETSENTINEL_COPILOT_ALLOW_CLOUD=true to send minimized alert evidence to Google")
        if not api_key.strip():
            raise CopilotError("GEMINI_API_KEY is required for cloud summaries")
        if not re.fullmatch(r"[a-zA-Z0-9._-]+", model):
            raise CopilotError("invalid Gemini model name")
        self._api_key = api_key
        self.model = model
        self._timeout = timeout

    def complete(self, system: str, user: str, schema: dict) -> dict:
        import httpx

        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": {
                "responseFormat": {
                    "text": {"mimeType": "APPLICATION_JSON", "schema": schema},
                },
                "maxOutputTokens": 2048,
            },
        }
        try:
            response = httpx.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent",
                headers={"x-goog-api-key": self._api_key},
                json=body, timeout=self._timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPStatusError as exc:
            # Do not log the body, headers or exception: they may echo a secret.
            raise CopilotError(f"Gemini returned HTTP {exc.response.status_code}") from None
        except httpx.HTTPError:
            raise CopilotError("Gemini could not be reached") from None
        except ValueError:
            raise CopilotError("Gemini returned a body that is not JSON") from None

        if not isinstance(payload, dict):
            raise CopilotError("Gemini returned an invalid response")
        candidates = payload.get("candidates") or []
        if not isinstance(candidates, list):
            raise CopilotError("Gemini returned invalid candidates")
        candidate = candidates[0] if candidates else {}
        if not isinstance(candidate, dict) or candidate.get("finishReason") != "STOP":
            raise CopilotError("Gemini did not return a complete summary")
        reply = candidate.get("content") or {}
        if not isinstance(reply, dict) or not isinstance(reply.get("parts", []), list):
            raise CopilotError("Gemini returned invalid content")
        parts = reply.get("parts") or []
        content = "".join(part.get("text", "") for part in parts
                          if isinstance(part, dict) and isinstance(part.get("text"), str)
                          and not part.get("thought"))
        if not content:
            raise CopilotError("Gemini returned an empty reply")
        return parse_content(content)


def parse_content(content: str) -> dict:
    """The assistant message, as an object.

    Raises rather than repairing. A reply that needs repairing before it parses is
    one the schema is about to reject anyway, and the interesting fact - that this
    model produced unusable output - is worth recording rather than patching over.
    """
    import json

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError as exc:
        raise CopilotError(f"the model did not return JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise CopilotError(
            f"the model returned {type(parsed).__name__}, expected an object"
        )
    return parsed
