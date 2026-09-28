"""Forwarding alerts to Keep, the SOAR layer.

Keep does the de-duplication, correlation and notification workflows this system has
no business reimplementing. What it needs from us is a stable fingerprint: two alerts
carrying the same one are the same alert recurring, and Keep groups them instead of
paging somebody twice.

The fingerprint is the part worth arguing about. It covers the source, the two
addresses and the technique - what an analyst would call "the same thing happening
again" - and deliberately excludes severity, the score and the time. A scan that
resumes an hour later with a slightly higher risk score is the same finding; if
severity were in the key, every re-score would open a new one.

The writer delivers at-least-once, so a redelivered message can produce a second
identical alert row. That is the other reason this fingerprint matters: the duplicate
lands on the same Keep alert rather than in front of an analyst.

Forwarding is best effort by design. Keep being unreachable must never stop a
detection being recorded, because the database is the evidence and Keep is the
notification.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Iterable, Protocol

from netsentinel_api.config import Settings
from netsentinel_api.db.models import Alert, IoC, Severity

logger = logging.getLogger("netsentinel.soar")

#: Our severities in Keep's vocabulary. Keep has no "medium", and "warning" is where
#: its own providers put that band.
KEEP_SEVERITY: dict[Severity, str] = {
    Severity.critical: "critical",
    Severity.high: "high",
    Severity.medium: "warning",
    Severity.low: "low",
    Severity.info: "info",
}

#: The webhook provider name this system posts as, which is how Keep attributes the
#: alert and how a workflow selects it.
PROVIDER = "netsentinel"

REQUEST_TIMEOUT_SECONDS = 10.0


class Forwarder(Protocol):
    """What the writer needs from a SOAR destination."""

    def send(self, alert: Alert, iocs: Iterable[IoC]) -> None: ...


def fingerprint(alert: Alert) -> str:
    """The de-duplication key: the same finding recurring, not the same row."""
    parts = (
        alert.source or "",
        str(alert.src_ip or ""),
        str(alert.dst_ip or ""),
        alert.mitre_technique or "",
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def alert_event(alert: Alert, iocs: Iterable[IoC] = ()) -> dict:
    """The body Keep's generic webhook accepts."""
    matched = list(iocs)
    name = f"{alert.source} {alert.severity.value} {alert.src_ip or 'unknown'}"
    if matched:
        name += f" ({len(matched)} IoC match{'es' if len(matched) > 1 else ''})"

    return {
        "name": name,
        "status": "firing",
        "severity": KEEP_SEVERITY[alert.severity],
        "lastReceived": (alert.created_at or datetime.now(timezone.utc)).isoformat(),
        "source": [PROVIDER],
        "fingerprint": fingerprint(alert),
        "description": (
            f"alert {alert.alert_id} from {alert.source}: "
            f"{alert.src_ip or '?'} -> {alert.dst_ip or '?'}"
        ),
        # Keep renders these as labels, which is what an analyst filters on. The
        # alert_id is here so a Keep entry leads back to this system's row.
        "labels": {
            "alert_id": str(alert.alert_id),
            "mitre_technique": alert.mitre_technique or "",
            "iocs": ",".join(str(ioc.value) for ioc in matched),
        },
    }


class KeepForwarder:
    """Posts to Keep's generic webhook.

    ``httpx`` is imported lazily so a deployment with no SOAR never constructs a
    client, and the tests exercise the body without one.
    """

    def __init__(self, url: str, api_key: str, timeout: float = REQUEST_TIMEOUT_SECONDS) -> None:
        # The generic webhook. Keep reads the segment after /alerts/event/ as one of
        # its own provider types and answers 400 "Provider netsentinel not found";
        # the event's own ``source`` is what attributes it to this system.
        self._url = url.rstrip("/") + "/alerts/event"
        self._api_key = api_key
        self._timeout = timeout

    def send(self, alert: Alert, iocs: Iterable[IoC] = ()) -> None:
        import httpx

        try:
            response = httpx.post(
                self._url,
                headers={"x-api-key": self._api_key, "Accept": "application/json"},
                json=alert_event(alert, iocs),
                timeout=self._timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # Logged, never raised. See the module docstring: the database is the
            # evidence and Keep is the notification.
            logger.error("could not forward alert %s to Keep: %s", alert.alert_id, exc)


def forwarder_from(settings: Settings) -> Forwarder | None:
    """A forwarder if Keep is configured, otherwise nothing.

    Nothing is a valid answer: the pipeline detects, stores and shows alerts without a
    SOAR, so an unconfigured Keep is a feature that is off rather than a broken
    deployment.
    """
    if not settings.keep_url or not settings.keep_api_key:
        return None
    return KeepForwarder(settings.keep_url, settings.keep_api_key.get_secret_value())
