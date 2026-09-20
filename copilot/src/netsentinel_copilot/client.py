"""Talking to the local model.

Ollama on the laptop, not a hosted API. The reason is in the risk register rather
than the budget: the prompt contains an alert, which is an attacker's traffic
described in detail against named hosts on a real estate. That is not something to
post to a third party, and a SOC assistant that only works with an internet
connection is one that stops working during exactly the incident it was built for.

Two settings do most of the work here. ``format`` carries the JSON Schema of the
reply, so the server constrains generation to that shape rather than the prompt
asking politely. ``temperature`` is zero, because the same alert summarised
differently on two refreshes reads as though the system is unsure, and there is
nothing creative to be gained from paraphrasing evidence.

The reply is still validated afterwards. A served model is another system, and "it
was asked for that shape" is not a guarantee, only an improvement of the odds.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("netsentinel.copilot")

DEFAULT_URL = "http://localhost:11434"

#: 3B on a 4 GB GPU. Larger models do summarise better and do not fit next to the
#: rest of the stack; the schema is what makes a small model usable here.
DEFAULT_MODEL = "llama3.2:3b"

#: A local 3B model on a laptop GPU is not fast, and a summary is not on anybody's
#: critical path.
REQUEST_TIMEOUT_SECONDS = 120.0


class CopilotError(RuntimeError):
    """The model could not be reached, or did not return usable JSON."""


class OllamaClient:
    def __init__(
        self,
        url: str = DEFAULT_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._url = url.rstrip("/")
        self.model = model
        self._timeout = timeout

    def complete(self, system: str, user: str, schema: dict) -> dict:
        """One completion, constrained to ``schema``. Returns the parsed object."""
        import httpx

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # The schema, not the string "json": the server then cannot emit a
            # well-formed object of the wrong shape.
            "format": schema,
            "stream": False,
            "options": {"temperature": 0},
        }

        try:
            response = httpx.post(
                f"{self._url}/api/chat", json=body, timeout=self._timeout
            )
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise CopilotError(f"the model could not be reached: {exc}") from exc
        except ValueError as exc:
            raise CopilotError(f"Ollama returned a body that is not JSON: {exc}") from exc

        content = (payload.get("message") or {}).get("content")
        if not content:
            raise CopilotError("the model returned an empty reply")

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
