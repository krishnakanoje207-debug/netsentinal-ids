"""Importing a Greenbone report.

Two things decide whether this table is worth opening: what is let in, and whether a
second scan produces a second set of rows. Those are what these tests are about. The
XML is a trimmed real ``get_reports`` response - trimmed, not invented, because the
shape of that document is exactly the thing a fixture is easy to get wrong about.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from netsentinel_api.db.models import Asset, Criticality, Vulnerability
from netsentinel_api.services.vulns import (
    MIN_QOD,
    Finding,
    ScanError,
    normalise_ip,
    parse_report,
    parse_scanned_hosts,
    sync,
)

SCAN_END = datetime(2026, 9, 20, 3, 30, tzinfo=timezone.utc)


def _report(results: str, scan_end: str = "2026-09-20T03:30:00+00:00",
            hosts: str = "") -> str:
    return f"""<get_reports_response status="200" status_text="OK">
  <report id="1a2b">
    <report id="1a2b">
      <scan_start>2026-09-20T03:00:00+00:00</scan_start>
      <scan_end>{scan_end}</scan_end>
      <results max="100" start="1">
        {results}
      </results>
      {hosts}
    </report>
  </report>
</get_reports_response>"""


def _result(
    host: str = "172.30.0.10",
    cves: str = '<ref type="cve" id="CVE-2021-44228"/>',
    severity: str = "10.0",
    qod: int = 98,
    port: str = "443/tcp",
) -> str:
    return f"""<result id="r1">
          <name>A vulnerable thing</name>
          <host>{host}<hostname>victim-web</hostname></host>
          <port>{port}</port>
          <nvt oid="1.3.6.1.4.1.25623.1.0.117842">
            <name>A vulnerable thing</name>
            <family>Web application abuses</family>
            <refs>{cves}<ref type="url" id="https://example.test"/></refs>
          </nvt>
          <threat>High</threat>
          <severity>{severity}</severity>
          <qod><value>{qod}</value><type>remote_banner</type></qod>
        </result>"""


def _asset(asset_id: int = 1, ip: str = "172.30.0.10") -> Asset:
    return Asset(asset_id=asset_id, hostname="victim-web", ip_address=ip,
                 os="alpine", criticality=Criticality.medium)


# --- what the report says --------------------------------------------------

def test_a_finding_carries_its_host_cve_and_score():
    finding, = parse_report(_report(_result()))
    assert finding.host == "172.30.0.10"
    assert finding.cve_id == "CVE-2021-44228"
    assert finding.cvss == 10.0


def test_the_hostname_does_not_contaminate_the_address():
    """<host> holds the address as text and the name as a child element."""
    finding, = parse_report(_report(_result()))
    assert finding.host == "172.30.0.10"


def test_a_finding_is_dated_by_the_scan_not_the_import():
    finding, = parse_report(_report(_result()))
    assert finding.detected_at == SCAN_END


def test_one_result_with_two_cves_becomes_two_findings():
    cves = ('<ref type="cve" id="CVE-2021-44228"/>'
            '<ref type="cve" id="CVE-2021-45046"/>')
    findings = parse_report(_report(_result(cves=cves)))
    assert {f.cve_id for f in findings} == {"CVE-2021-44228", "CVE-2021-45046"}


def test_the_same_cve_on_two_ports_is_one_finding():
    """The table's grain is asset and CVE; two rows differing in nothing is noise."""
    both = _result(port="443/tcp") + _result(port="8443/tcp")
    assert len(parse_report(_report(both))) == 1


def test_a_finding_with_no_cve_is_not_a_vulnerability():
    """An open port or a banner is inventory. cve_id is NOT NULL for that reason."""
    assert parse_report(_report(_result(cves='<ref type="url" id="x"/>'))) == []


def test_the_legacy_cve_element_is_still_read():
    """A report from an older gvmd is still a report somebody wants imported."""
    legacy = """<result id="r1">
          <host>172.30.0.10</host>
          <nvt oid="1.2.3"><cve>CVE-2019-0708, CVE-2019-1181</cve></nvt>
          <severity>9.8</severity>
        </result>"""
    assert {f.cve_id for f in parse_report(_report(legacy))} == {
        "CVE-2019-0708", "CVE-2019-1181"
    }


# --- what is kept out ------------------------------------------------------

@pytest.mark.parametrize("qod", [30, 50, MIN_QOD - 1])
def test_a_guess_is_not_imported(qod):
    """Greenbone reports what it is unsure about; a table of guesses goes unread."""
    assert parse_report(_report(_result(qod=qod))) == []


def test_the_quality_threshold_can_be_lowered_deliberately():
    assert len(parse_report(_report(_result(qod=50)), min_qod=50)) == 1


def test_a_result_with_no_qod_is_trusted():
    """The field is optional in older formats; dropping those empties the table."""
    older = """<result id="r1">
          <host>172.30.0.10</host>
          <nvt oid="1.2.3"><refs><ref type="cve" id="CVE-2019-0708"/></refs></nvt>
          <severity>9.8</severity>
        </result>"""
    assert len(parse_report(_report(older))) == 1


def test_a_withdrawn_severity_leaves_the_score_empty():
    """-1.0 is Greenbone's marker for a result it no longer counts, and the CHECK
    on the column would reject it."""
    finding, = parse_report(_report(_result(severity="-1.0")))
    assert finding.cvss is None


def test_a_report_that_is_not_xml_is_refused():
    with pytest.raises(ScanError, match="not valid XML"):
        parse_report("<get_reports_response><report>")


def test_an_entity_bomb_is_refused_not_expanded():
    """A file cannot be vouched for, so XML entities are refused before they expand."""
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaaaaaaaa">'
        '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]><report>&b;</report>'
    )
    with pytest.raises(ScanError, match="refusing it"):
        parse_report(bomb)


def test_an_empty_report_is_not_an_error():
    """A scan that found nothing is a result, and a good one."""
    assert parse_report(_report("")) == []


@pytest.mark.parametrize(
    ("written", "expected"),
    [("2001:0db8:0000::0:1", "2001:db8::1"), ("::FFFF:0:1", "::ffff:0.0.0.1"),
     # Not an address, and not this function's business to reject: the caller
     # compares it with the inventory, where it will simply not match.
     ("victim-web", "victim-web"),
     # Rejected by the standard library as ambiguous octal, so it stays as written
     # and matches nothing - which is the safe direction for an address nobody can
     # agree on.
     ("172.30.0.010", "172.30.0.010")],
)
def test_addresses_have_one_spelling(written, expected):
    assert normalise_ip(written) == expected


# --- the upsert ------------------------------------------------------------

def _finding(cve_id: str = "CVE-2021-44228", cvss: float | None = 10.0,
             host: str = "172.30.0.10") -> Finding:
    return Finding(host=host, cve_id=cve_id, cvss=cvss, detected_at=SCAN_END)


class StubSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, instance: object, /) -> None:
        self.added.append(instance)


def test_a_new_finding_becomes_a_row_against_its_asset():
    session = StubSession()
    stats = sync(session, [_finding()], [_asset()], [])

    row, = session.added
    assert (row.asset_id, row.cve_id, row.cvss) == (1, "CVE-2021-44228", 10.0)
    assert row.detected_at == SCAN_END
    assert stats.as_dict() == {"fetched": 1, "added": 1, "updated": 0,
                               "unknown_hosts": 0, "hosts_scanned": 1}


def test_rescanning_updates_the_row_it_already_has():
    """Without this, every scan doubles every count on the dashboard."""
    existing = Vulnerability(vuln_id=5, asset_id=1, cve_id="CVE-2021-44228", cvss=7.5)
    session = StubSession()

    stats = sync(session, [_finding(cvss=10.0)], [_asset()], [existing])

    assert session.added == []
    assert existing.cvss == 10.0 and existing.detected_at == SCAN_END
    assert stats.as_dict()["updated"] == 1


def test_a_finding_on_an_unknown_host_is_counted_not_invented():
    """A vulnerability belongs to something; a scan outside the inventory is news."""
    session = StubSession()
    stats = sync(session, [_finding(host="10.9.9.9")], [_asset()], [])

    assert session.added == []
    assert stats.as_dict()["unknown_hosts"] == 1


def test_an_asset_written_differently_still_matches():
    """Greenbone and the inventory disagree about how to write an IPv6 address."""
    session = StubSession()
    sync(session, [_finding(host="2001:db8::1")], [_asset(ip="2001:0db8:0000::1")], [])
    assert len(session.added) == 1


def test_two_assets_with_the_same_cve_are_two_rows():
    session = StubSession()
    findings = [_finding(host="172.30.0.10"), _finding(host="172.30.0.11")]
    sync(session, findings, [_asset(1, "172.30.0.10"), _asset(2, "172.30.0.11")], [])
    assert {row.asset_id for row in session.added} == {1, 2}


# --- which hosts the scan covered ------------------------------------------

def _scanned_host(ip: str, end: str = "2026-09-20T03:20:00+00:00") -> str:
    return f"""<host><ip>{ip}</ip><asset asset_id="a1"/>
        <start>2026-09-20T03:01:00+00:00</start><end>{end}</end>
        <detail><name>hostname</name><value>victim</value></detail></host>"""


HOST_END = datetime(2026, 9, 20, 3, 20, tzinfo=timezone.utc)


def test_a_host_with_nothing_found_is_still_listed_as_scanned():
    """The clean host is the one whose coverage has to be recorded."""
    xml = _report("", hosts=_scanned_host("172.30.0.11"))
    assert parse_scanned_hosts(xml) == {"172.30.0.11": HOST_END}


def test_the_host_inside_a_result_is_not_the_host_list():
    """<result><host> names a finding's address, not a scanned host with a time."""
    assert parse_scanned_hosts(_report(_result())) == {}


def test_a_host_with_no_end_time_takes_the_scan_end():
    xml = _report("", hosts="<host><ip>172.30.0.11</ip></host>")
    assert parse_scanned_hosts(xml) == {"172.30.0.11": SCAN_END}


def test_a_time_without_an_offset_is_read_as_utc():
    xml = _report("", hosts=_scanned_host("172.30.0.11", end="2026-09-20T03:20:00"))
    assert parse_scanned_hosts(xml)["172.30.0.11"] == HOST_END


def test_a_clean_host_on_the_list_is_marked_scanned():
    asset = _asset()
    stats = sync(StubSession(), [], [asset], [], scanned={"172.30.0.10": HOST_END})
    assert asset.last_scanned_at == HOST_END
    assert stats.hosts_scanned == 1


def test_a_host_with_a_finding_is_marked_scanned_without_a_host_list():
    """Older reports may carry no host list; a finding still proves coverage."""
    asset = _asset()
    sync(StubSession(), [_finding()], [asset], [])
    assert asset.last_scanned_at == SCAN_END


def test_a_host_the_scan_did_not_cover_stays_unscanned():
    covered, missed = _asset(1, "172.30.0.10"), _asset(2, "172.30.0.11")
    sync(StubSession(), [], [covered, missed], [], scanned={"172.30.0.10": HOST_END})
    assert missed.last_scanned_at is None


def test_an_older_report_does_not_move_the_scan_time_back():
    asset = _asset()
    asset.last_scanned_at = HOST_END
    earlier = datetime(2026, 9, 1, tzinfo=timezone.utc)
    stats = sync(StubSession(), [], [asset], [], scanned={"172.30.0.10": earlier})
    assert asset.last_scanned_at == HOST_END
    assert stats.hosts_scanned == 0
