"""Forwarding to Keep.

The fingerprint carries the weight here: it is what stops a redelivered message, or a
scan that resumes an hour later, from paging somebody a second time. So the tests are
mostly about what it does and does not depend on.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx
import pytest

from netsentinel_api.config import Settings
from netsentinel_api.db.models import Alert, IoC, IoCType, Severity
from netsentinel_api.services.soar import (
    KEEP_SEVERITY,
    PROVIDER,
    KeepForwarder,
    alert_event,
    fingerprint,
    forwarder_from,
)

SECRET = "K7vQp2xR9mLt4wZn6bYc3sEdJf8hGa1uNqXrVoWiTyBk5Pz0"
NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


def _alert(**overrides) -> Alert:
    fields = {
        "alert_id": 11,
        "source": "early_flow",
        "severity": Severity.high,
        "src_ip": "10.0.0.5",
        "dst_ip": "198.51.100.7",
        "mitre_technique": "T1046",
        "created_at": NOW,
    }
    fields.update(overrides)
    return Alert(**fields)


# --- the de-duplication key ------------------------------------------------

def test_the_same_finding_fingerprints_the_same():
    assert fingerprint(_alert()) == fingerprint(_alert())


def test_severity_is_not_part_of_the_key():
    """A re-scored scan is the same finding, not a new one."""
    assert fingerprint(_alert()) == fingerprint(_alert(severity=Severity.critical))


def test_time_is_not_part_of_the_key():
    later = datetime(2026, 9, 20, 18, 0, tzinfo=timezone.utc)
    assert fingerprint(_alert()) == fingerprint(_alert(created_at=later))


def test_the_alert_id_is_not_part_of_the_key():
    """At-least-once delivery can write the same alert twice; Keep must group them."""
    assert fingerprint(_alert()) == fingerprint(_alert(alert_id=12))


@pytest.mark.parametrize(
    "change",
    [{"src_ip": "10.0.0.6"}, {"dst_ip": "203.0.113.9"}, {"source": "suricata"},
     {"mitre_technique": "T1110"}],
)
def test_a_different_finding_fingerprints_differently(change):
    assert fingerprint(_alert()) != fingerprint(_alert(**change))


def test_an_alert_without_addresses_still_fingerprints():
    assert len(fingerprint(_alert(src_ip=None, dst_ip=None, mitre_technique=None))) == 64


# --- the event body --------------------------------------------------------

def test_the_event_carries_what_keep_needs():
    event = alert_event(_alert())
    assert event["status"] == "firing"
    assert event["severity"] == "high"
    assert event["source"] == [PROVIDER]
    assert event["fingerprint"] == fingerprint(_alert())
    assert event["lastReceived"] == NOW.isoformat()


@pytest.mark.parametrize("severity", list(Severity))
def test_every_severity_has_a_keep_equivalent(severity):
    assert alert_event(_alert(severity=severity))["severity"] == KEEP_SEVERITY[severity]


def test_matched_indicators_reach_the_labels():
    iocs = [IoC(ioc_id=1, value="198.51.100.7", type=IoCType.ip)]
    event = alert_event(_alert(), iocs)
    assert event["labels"]["iocs"] == "198.51.100.7"
    assert "1 IoC match" in event["name"]


def test_the_alert_id_leads_back_to_this_system():
    assert alert_event(_alert())["labels"]["alert_id"] == "11"


def test_an_alert_with_no_creation_time_still_has_one():
    """created_at is a server default, so it is None until the row is flushed."""
    assert alert_event(_alert(created_at=None))["lastReceived"]


# --- configuration ---------------------------------------------------------

def test_no_keep_configured_means_no_forwarder():
    """The pipeline detects, stores and shows alerts without a SOAR."""
    assert forwarder_from(Settings(jwt_secret=SECRET)) is None


def test_a_half_configured_keep_is_still_no_forwarder():
    settings = Settings(jwt_secret=SECRET, keep_url="http://keep.local")
    assert forwarder_from(settings) is None


def test_a_configured_keep_produces_a_forwarder():
    settings = Settings(jwt_secret=SECRET, keep_url="http://keep.local/", keep_api_key="k")
    forwarder = forwarder_from(settings)
    assert isinstance(forwarder, KeepForwarder)
    assert forwarder._url == "http://keep.local/alerts/event"


# --- sending ---------------------------------------------------------------

def test_keep_being_down_is_logged_and_never_raised(monkeypatch, caplog):
    """The alert is already in the database; a notification failing must not undo that."""
    def refused(url, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", refused)
    forwarder = KeepForwarder("http://keep.local", "k")

    with caplog.at_level(logging.ERROR, logger="netsentinel.soar"):
        forwarder.send(_alert())

    assert "could not forward alert 11 to Keep" in caplog.text


def test_a_keep_refusal_is_logged_too(monkeypatch, caplog):
    """A 4xx is as much a lost notification as a closed port."""
    request = httpx.Request("POST", "http://keep.local")
    monkeypatch.setattr(
        httpx, "post", lambda url, **kwargs: httpx.Response(401, request=request)
    )

    with caplog.at_level(logging.ERROR, logger="netsentinel.soar"):
        KeepForwarder("http://keep.local", "k").send(_alert())

    assert "could not forward alert 11" in caplog.text
