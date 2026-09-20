"""The search box: what it understands, and what it refuses to guess at.

The interesting half is the SQL, which no other test in this suite executes - the
repositories are faked so the API needs no PostgreSQL. So the clause is compiled
against the PostgreSQL dialect here and read, which catches the operator being wrong
or the literal being compared as text without needing a server to catch it.
"""

from __future__ import annotations

import ipaddress

import pytest
from sqlalchemy import select
from sqlalchemy.dialects import postgresql

from netsentinel_api.db.models import Alert
from netsentinel_api.db.repositories import _matching
from netsentinel_api.services.search import (
    AddressQuery,
    TechniqueQuery,
    Unsearchable,
    parse,
)


def compiled(search) -> str:
    statement = _matching(select(Alert), search)
    return str(statement.compile(dialect=postgresql.dialect(),
                                 compile_kwargs={"literal_binds": True}))


# --- what was typed --------------------------------------------------------

def test_an_address_is_read_as_a_single_host_network():
    # One query shape rather than two: a bare address is a /32.
    assert parse("203.0.113.9") == AddressQuery(ipaddress.ip_network("203.0.113.9/32"))


def test_a_network_is_read_as_itself():
    assert parse("203.0.113.0/24") == AddressQuery(ipaddress.ip_network("203.0.113.0/24"))


def test_an_ipv6_address_is_understood():
    assert parse("2001:db8::1") == AddressQuery(ipaddress.ip_network("2001:db8::1/128"))


def test_host_bits_are_read_as_the_network_they_name():
    # Somebody typing 203.0.113.9/24 means that network. Refusing it would be
    # pedantry at the moment they are trying to find something.
    assert parse("203.0.113.9/24") == AddressQuery(ipaddress.ip_network("203.0.113.0/24"))


@pytest.mark.parametrize("text", ["T1046", "t1046", "T1071.001"])
def test_a_technique_is_recognised_whatever_the_case(text):
    assert parse(text) == TechniqueQuery(text.upper())


def test_surrounding_space_is_not_a_different_search():
    assert parse("  203.0.113.9  ") == parse("203.0.113.9")


@pytest.mark.parametrize("text", ["", "   ", "victim-web", "203.0.113", "T10", "drop table"])
def test_anything_else_is_refused_rather_than_matched_loosely(text):
    with pytest.raises(Unsearchable):
        parse(text)


def test_the_refusal_says_what_would_have_worked():
    # A search box that silently returns nothing teaches an analyst that there is
    # nothing there.
    with pytest.raises(Unsearchable) as raised:
        parse("victim-web")

    message = str(raised.value)
    assert "203.0.113.0/24" in message
    assert "T1046" in message


# --- the clause it becomes -------------------------------------------------

def test_an_address_is_matched_by_containment_not_as_text():
    sql = compiled(parse("203.0.113.9"))

    # <<= is "contained within or equal to" on an INET column. A LIKE here would
    # make the network case impossible and the host case quietly wrong.
    assert "<<=" in sql
    assert "CAST('203.0.113.9/32' AS INET)" in sql


def test_a_network_matches_every_host_on_it():
    sql = compiled(parse("203.0.113.0/24"))

    assert "CAST('203.0.113.0/24' AS INET)" in sql


def test_either_end_of_the_alert_can_match():
    sql = compiled(parse("203.0.113.9"))

    # Which column the address landed in is an accident of who opened the
    # connection, and an analyst chasing a host wants both directions.
    assert "alerts.src_ip <<=" in sql
    assert "alerts.dst_ip <<=" in sql
    assert " OR " in sql


def test_a_technique_is_matched_exactly():
    sql = compiled(parse("T1046"))

    assert "alerts.mitre_technique = 'T1046'" in sql
    assert "<<=" not in sql


def test_no_search_narrows_nothing():
    assert "WHERE" not in compiled(None)


# --- over HTTP -------------------------------------------------------------

def test_the_feed_can_be_searched_by_address(client, auth_header):
    found = client.get("/api/v1/alerts?q=203.0.113.9", headers=auth_header)

    assert [row["alert_id"] for row in found.json()] == [100]


def test_the_feed_can_be_searched_by_the_network_an_address_is_on(client, auth_header):
    found = client.get("/api/v1/alerts?q=203.0.113.0/24", headers=auth_header)

    assert len(found.json()) == 1


def test_an_address_on_another_network_finds_nothing(client, auth_header):
    found = client.get("/api/v1/alerts?q=198.51.100.0/24", headers=auth_header)

    assert found.json() == []


def test_the_destination_matches_as_well_as_the_source(client, auth_header):
    # The fixture alert runs 203.0.113.9 -> 10.0.0.9.
    found = client.get("/api/v1/alerts?q=10.0.0.9", headers=auth_header)

    assert [row["alert_id"] for row in found.json()] == [100]


def test_the_feed_can_be_searched_by_technique(client, auth_header):
    assert len(client.get("/api/v1/alerts?q=T1046", headers=auth_header).json()) == 1
    assert client.get("/api/v1/alerts?q=T1110", headers=auth_header).json() == []


def test_a_search_nobody_can_read_is_refused_with_a_sentence(client, auth_header):
    response = client.get("/api/v1/alerts?q=victim-web", headers=auth_header)

    assert response.status_code == 422
    assert "203.0.113.0/24" in response.json()["detail"]


def test_an_empty_search_box_is_the_unfiltered_feed(client, auth_header):
    # What the dashboard sends when the analyst clears the field.
    assert len(client.get("/api/v1/alerts?q=", headers=auth_header).json()) == 1
    assert len(client.get("/api/v1/alerts?q=%20%20", headers=auth_header).json()) == 1


def test_search_composes_with_the_other_filters(client, auth_header):
    both = client.get("/api/v1/alerts?q=203.0.113.9&severity=high", headers=auth_header)
    assert len(both.json()) == 1

    mismatched = client.get("/api/v1/alerts?q=203.0.113.9&severity=low", headers=auth_header)
    assert mismatched.json() == []


# --- and the export, which claims to be the same screen --------------------

def test_the_export_honours_the_search(client, auth_header):
    import csv
    import io

    found = client.get("/api/v1/alerts/export?q=203.0.113.9", headers=auth_header)
    assert len(list(csv.DictReader(io.StringIO(found.text)))) == 1

    missed = client.get("/api/v1/alerts/export?q=198.51.100.7", headers=auth_header)
    assert list(csv.DictReader(io.StringIO(missed.text))) == []


def test_an_unreadable_search_refuses_the_export_too(client, auth_header):
    response = client.get("/api/v1/alerts/export?q=victim-web", headers=auth_header)

    # Refusing the feed and quietly exporting everything would be the worst of both.
    assert response.status_code == 422


def test_the_audit_row_says_which_alerts_left(client, auth_header, session):
    client.get("/api/v1/alerts/export?q=203.0.113.0/24", headers=auth_header)

    entry = next(e for e in session.audit_entries() if e.action == "alerts.exported")
    # "1,412 rows" answers nothing on its own.
    assert entry.details["search"] == "203.0.113.0/24"
