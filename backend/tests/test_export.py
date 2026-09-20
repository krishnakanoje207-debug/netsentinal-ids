"""The CSV export, and the two things it must not do.

It must not hand a spreadsheet a formula written by whoever sent the traffic, and
it must not produce a partial file that looks complete. Everything else here is
ordinary: the right columns, the feed's own filters, and a row in the audit log
saying the estate's alerts left in a file.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone

import pytest

from netsentinel_api.services.export import COLUMNS, alerts_csv, filename, neutralise

NOW = datetime(2026, 9, 20, 10, 0, tzinfo=timezone.utc)


def parse(body: str) -> list[dict]:
    return list(csv.DictReader(io.StringIO(body)))


# --- the spreadsheet is an interpreter -------------------------------------

@pytest.mark.parametrize("payload", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"])
def test_a_field_that_would_execute_is_made_text(payload):
    # Excel and LibreOffice treat each of these as the start of a formula, and
    # almost everything interesting in an alert was written by whoever sent the
    # traffic.
    assert neutralise(payload) == f"'{payload}"


def test_a_formula_in_an_address_does_not_survive_into_the_file():
    body = alerts_csv([{"alert_id": 1, "src_ip": '=HYPERLINK("http://evil","click")'}])

    row = parse(body)[0]
    assert row["src_ip"].startswith("'=HYPERLINK")


def test_neutralising_prefixes_rather_than_strips():
    # An indicator whose leading character was removed is evidence that has been
    # quietly altered, which is worse than a file with an apostrophe in it.
    assert neutralise("-192.168.0.1")[1:] == "-192.168.0.1"


def test_ordinary_text_is_left_alone():
    assert neutralise("203.0.113.9") == "203.0.113.9"
    assert neutralise("T1046") == "T1046"


# --- what a cell means -----------------------------------------------------

def test_a_missing_value_is_an_empty_cell_rather_than_a_dash():
    body = alerts_csv([{"alert_id": 1, "risk_score": None, "mitre_technique": None}])

    row = parse(body)[0]
    # "--" reads as a string to every tool that opens this, and "None" is worse.
    assert row["risk_score"] == ""
    assert row["mitre_technique"] == ""


def test_a_score_of_zero_is_not_a_missing_score():
    body = alerts_csv([{"alert_id": 1, "risk_score": 0.0}])

    assert parse(body)[0]["risk_score"] == "0.0000"


def test_a_time_is_written_in_utc_so_it_lines_up_with_the_sensor():
    body = alerts_csv([{"alert_id": 1, "created_at": NOW}])

    assert parse(body)[0]["created_at"] == "2026-09-20T10:00:00+00:00"


def test_the_header_is_the_column_order():
    body = alerts_csv([])

    assert body.splitlines()[0].split(",") == list(COLUMNS)


def test_rows_are_written_in_the_declared_order_whatever_the_dict_order():
    body = alerts_csv([{"model": "tier-a-lgbm 1.0.0", "alert_id": 7, "severity": "high"}])

    row = parse(body)[0]
    assert row["alert_id"] == "7"
    assert row["severity"] == "high"
    assert row["model"] == "tier-a-lgbm 1.0.0"


def test_a_truncated_export_says_so_in_its_name():
    # The header is gone by the time somebody opens this file next week; the name
    # is not.
    assert filename(NOW, truncated=True).endswith("-truncated.csv")
    assert filename(NOW, truncated=False).endswith("20260920-100000.csv")


# --- over HTTP -------------------------------------------------------------

def test_the_export_is_a_csv_attachment(client, auth_header):
    response = client.get("/api/v1/alerts/export", headers=auth_header)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/csv")
    assert "attachment" in response.headers["content-disposition"]
    assert "netsentinel-alerts-" in response.headers["content-disposition"]


def test_export_is_not_read_as_an_alert_id(client, auth_header):
    # "/alerts/export" would otherwise match "/alerts/{alert_id}" and come back as
    # a failure to parse "export" as an integer.
    assert client.get("/api/v1/alerts/export", headers=auth_header).status_code == 200


def test_the_file_carries_the_score_and_the_model_that_produced_it(client, auth_header):
    body = client.get("/api/v1/alerts/export", headers=auth_header).text

    row = parse(body)[0]
    assert row["alert_id"] == "100"
    assert row["risk_score"] == "0.9300"
    assert row["model"] == "tier-a-lgbm 1.0.0"
    assert row["mitre_technique"] == "T1046"


def test_the_export_honours_the_feed_filters(client, auth_header):
    # An export that silently differs from the screen it was taken from is evidence
    # nobody can reproduce.
    matching = client.get("/api/v1/alerts/export?severity=high", headers=auth_header)
    assert len(parse(matching.text)) == 1

    other = client.get("/api/v1/alerts/export?severity=low", headers=auth_header)
    assert parse(other.text) == []


def test_a_full_export_does_not_claim_to_be_truncated(client, auth_header):
    response = client.get("/api/v1/alerts/export", headers=auth_header)

    assert response.headers["x-export-truncated"] == "false"
    assert "truncated" not in response.headers["content-disposition"]


def test_an_export_that_hit_the_cap_says_so(client, auth_header, alerts, alert):
    alerts.append(alert)

    response = client.get("/api/v1/alerts/export?limit=1", headers=auth_header)

    # One row in the file, and every way of finding out says the rest is missing.
    assert len(parse(response.text)) == 1
    assert response.headers["x-export-truncated"] == "true"
    assert "-truncated.csv" in response.headers["content-disposition"]


def test_an_export_that_exactly_fills_the_cap_is_not_called_truncated(
    client, auth_header
):
    # One alert and a cap of one. The repository fetches one row more than the cap
    # so this boundary can be told apart from a real truncation; claiming otherwise
    # would cry wolf on every small export.
    response = client.get("/api/v1/alerts/export?limit=1", headers=auth_header)

    assert len(parse(response.text)) == 1
    assert response.headers["x-export-truncated"] == "false"


def test_a_truncated_export_is_recorded_as_truncated(client, auth_header, session,
                                                    alerts, alert):
    alerts.append(alert)

    client.get("/api/v1/alerts/export?limit=1", headers=auth_header)

    entry = next(e for e in session.audit_entries() if e.action == "alerts.exported")
    assert entry.details["truncated"] is True
    assert entry.details["rows"] == 1


def test_the_read_is_recorded(client, auth_header, session, analyst):
    client.get("/api/v1/alerts/export?severity=high", headers=auth_header)

    entry = next(e for e in session.audit_entries() if e.action == "alerts.exported")
    assert entry.user_id == analyst.user_id
    assert entry.entity == "alerts"
    assert entry.details == {
        "rows": 1,
        "truncated": False,
        "status": None,
        "severity": "high",
    }


def test_exporting_needs_permission_to_read_alerts(client):
    assert client.get("/api/v1/alerts/export").status_code == 401
