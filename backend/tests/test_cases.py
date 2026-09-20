"""Opening a DFIR-IRIS case.

The description carries the weight here: it is what decides whether the case an
analyst opens tomorrow argues for itself or points back at a dashboard. So most of
these tests are about what reaches it, and what is left out when there is nothing to
say.
"""

from __future__ import annotations

from datetime import datetime, timezone

from netsentinel_api.config import Settings
from netsentinel_api.db.models import Alert, Detection, IoC, IoCType, Severity
from netsentinel_api.services.cases import (
    SOC_ID_PREFIX,
    TOP_FEATURE_COUNT,
    IrisClient,
    case_body,
    case_description,
    case_title,
    client_from,
)

SECRET = "K7vQp2xR9mLt4wZn6bYc3sEdJf8hGa1uNqXrVoWiTyBk5Pz0"
NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


def _detection(**overrides) -> Detection:
    fields = {
        "detection_id": 10,
        "flow_id": "10.0.0.5:44321-10.0.0.9:80-6",
        "sensor_id": 1,
        "model_id": 1,
        "risk_score": 0.93,
        "model_scores": {"tier_a": 0.93},
        "shap_values": {"duration_ms": -0.44, "pkt_rate": 0.42, "in_bytes": 0.05},
        "shadow": False,
    }
    fields.update(overrides)
    return Detection(**fields)


def _alert(**overrides) -> Alert:
    fields = {
        "alert_id": 100,
        "source": "early_flow",
        "severity": Severity.high,
        "src_ip": "203.0.113.9",
        "dst_ip": "10.0.0.9",
        "mitre_technique": "T1046",
        "created_at": NOW,
        "detection": _detection(),
    }
    fields.update(overrides)
    return Alert(**fields)


# --- the title -------------------------------------------------------------

def test_the_title_leads_with_what_the_case_list_is_scanned_for():
    title = case_title(_alert())
    assert title.startswith("high early_flow T1046")
    assert "203.0.113.9 -> 10.0.0.9" in title
    assert "alert 100" in title


def test_an_alert_without_a_technique_still_has_a_title():
    assert "T1046" not in case_title(_alert(mitre_technique=None))


def test_an_alert_without_addresses_still_has_a_title():
    title = case_title(_alert(src_ip=None, dst_ip=None))
    assert "? -> ?" in title
    assert "alert 100" in title


def test_the_title_fits_the_incidents_title_column():
    """incidents.title is VARCHAR(255); a truncated case name helps nobody."""
    assert len(case_title(_alert())) <= 255


# --- the description -------------------------------------------------------

def test_the_description_carries_the_facts_of_the_alert():
    body = case_description(_alert())
    assert "Escalated from NetSentinel alert 100." in body
    assert "Source: early_flow" in body
    assert "Severity: high" in body
    assert "Traffic: 203.0.113.9 -> 10.0.0.9" in body
    assert "MITRE technique: T1046" in body


def test_the_description_opens_with_the_model_evidence():
    """A case that only points back at the dashboard gets closed unread."""
    body = case_description(_alert())
    assert "Risk score: 0.93" in body
    # duration_ms -0.44 outranks pkt_rate +0.42: the ranking is by absolute value,
    # and the sign is printed so the direction survives.
    features = body.split("Top contributing features: ")[1]
    assert features.startswith("duration_ms -0.440, pkt_rate +0.420")


def test_only_the_strongest_contributors_are_listed():
    shap = {f"feature_{i}": 0.5 - i / 100 for i in range(20)}
    body = case_description(_alert(detection=_detection(shap_values=shap)))
    features = body.split("Top contributing features: ")[1]
    assert len(features.split(", ")) == TOP_FEATURE_COUNT


def test_an_alert_with_no_detection_describes_what_it_has():
    """Suricata and Wazuh alerts have no model behind them; that is not an error."""
    body = case_description(_alert(detection=None))
    assert "Source: early_flow" in body
    assert "Risk score" not in body


def test_an_alert_with_no_addresses_omits_the_traffic_line():
    body = case_description(_alert(src_ip=None, dst_ip=None, mitre_technique=None))
    assert "Traffic:" not in body
    assert "MITRE technique:" not in body
    assert "Severity: high" in body


def test_matched_indicators_reach_the_description():
    iocs = [
        IoC(ioc_id=1, value="203.0.113.9", type=IoCType.ip),
        IoC(ioc_id=2, value="198.51.100.4", type=IoCType.ip),
    ]
    body = case_description(_alert(), iocs)
    assert "Matched indicators: 203.0.113.9, 198.51.100.4" in body


def test_no_indicators_means_no_indicator_line():
    assert "Matched indicators" not in case_description(_alert())


def test_the_analysts_summary_comes_first():
    body = case_description(_alert(), (), "Second host on the same subnet this week.")
    assert body.startswith("Second host on the same subnet this week.")
    assert "Escalated from NetSentinel alert 100." in body


def test_a_blank_summary_is_not_a_blank_first_line():
    assert case_description(_alert(), (), "   ") == case_description(_alert())


# --- the request body ------------------------------------------------------

def test_the_body_carries_every_field_iris_requires():
    body = case_body(_alert(), "a title", "a description", customer_id=3)
    assert body == {
        "case_name": "a title",
        "case_description": "a description",
        "case_customer": 3,
        "case_soc_id": f"{SOC_ID_PREFIX}100",
    }


def test_the_soc_id_leads_back_to_this_system():
    """Given a case in IRIS, "which alert is this" must be answerable there."""
    assert case_body(_alert(), "t", "d", 1)["case_soc_id"].endswith("100")


# --- configuration ---------------------------------------------------------

def test_no_iris_configured_means_no_client():
    """Escalation still records an incident; it simply opens no case."""
    assert client_from(Settings(jwt_secret=SECRET)) is None


def test_a_half_configured_iris_is_still_no_client():
    settings = Settings(jwt_secret=SECRET, iris_url="https://iris.local")
    assert client_from(settings) is None


def test_a_configured_iris_produces_a_client():
    settings = Settings(
        jwt_secret=SECRET,
        iris_url="https://iris.local/",
        iris_api_key="k",
        iris_customer_id=7,
    )
    client = client_from(settings)
    assert isinstance(client, IrisClient)
    assert client._url == "https://iris.local"
    assert client._customer_id == 7


def test_certificate_checking_is_on_unless_it_is_turned_off():
    base = {"jwt_secret": SECRET, "iris_url": "https://iris.local", "iris_api_key": "k"}
    assert client_from(Settings(**base))._verify_tls is True
    assert client_from(Settings(**base, iris_verify_tls=False))._verify_tls is False
