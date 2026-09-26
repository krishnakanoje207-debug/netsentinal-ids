"""Addresses as the database actually returns them.

Every other API test in this suite goes through a fake repository holding Python
strings, so none of them can see what psycopg 3 does with an ``INET`` column: it
returns an ``ipaddress`` object. Pydantic will not turn one of those into a ``str``
on its own, so before this was handled the whole alert feed answered 500 against a
real PostgreSQL while the suite stayed green.

These tests drive the schemas directly with the driver's own types, which is the
only place that gap can be closed without a database.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone

from netsentinel_api.db.models import AlertStatus, Criticality, Severity
from netsentinel_api.schemas import AlertOut, AssetOut

NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


def alert_row(**overrides):
    row = {
        "alert_id": 1,
        "source": "early_flow",
        "severity": Severity.high,
        "status": AlertStatus.new,
        "src_ip": ipaddress.IPv4Address("203.0.113.9"),
        "dst_ip": ipaddress.IPv4Address("172.30.0.10"),
        "mitre_technique": "T1046",
        "created_at": NOW,
        "detection_id": 10,
    }
    row.update(overrides)
    return row


def test_an_ipv4_address_from_the_driver_becomes_text():
    out = AlertOut.model_validate(alert_row())

    assert out.src_ip == "203.0.113.9"
    assert out.dst_ip == "172.30.0.10"


def test_an_ipv6_address_from_the_driver_becomes_text():
    out = AlertOut.model_validate(
        alert_row(src_ip=ipaddress.IPv6Address("2001:db8::1"), dst_ip=None)
    )

    assert out.src_ip == "2001:db8::1"


def test_a_string_is_still_accepted():
    # The fakes, the writer and the e2e suite all pass strings. Both paths have to
    # work, or fixing the driver's type would break every test that caught nothing.
    out = AlertOut.model_validate(alert_row(src_ip="198.51.100.4"))

    assert out.src_ip == "198.51.100.4"


def test_a_missing_address_stays_missing():
    # Suricata and Wazuh alerts can arrive without one, and None must not become
    # the string "None".
    out = AlertOut.model_validate(alert_row(src_ip=None, dst_ip=None))

    assert out.src_ip is None
    assert out.dst_ip is None


def test_the_address_is_serialised_as_a_json_string():
    payload = AlertOut.model_validate(alert_row()).model_dump(mode="json")

    assert payload["src_ip"] == "203.0.113.9"
    assert isinstance(payload["src_ip"], str)


def test_an_asset_address_is_text_too():
    asset = AssetOut.model_validate(
        {
            "asset_id": 1,
            "hostname": "victim-web",
            "ip_address": ipaddress.IPv4Address("172.30.0.10"),
            "os": "alpine",
            "criticality": Criticality.high,
            "last_scanned_at": None,
        }
    )

    assert asset.ip_address == "172.30.0.10"
