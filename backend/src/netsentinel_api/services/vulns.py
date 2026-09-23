"""Greenbone scan results into the ``vulnerabilities`` table.

A scan tells you what an attacker would find on the estate; an alert tells you what
one is doing. They answer different questions, and the reason the results are
imported here rather than read from Greenbone on demand is the same reason MISP
indicators are copied into ``iocs``: the scanner runs in a window and is stopped the
rest of the time, and triage cannot depend on a service that is off.

The import is deliberately file-based. gvmd speaks GMP over a local socket rather
than HTTP, so there is no REST client to write; its own ``gvm-cli`` produces the
report XML, and this module turns that into rows. Nothing here needs Greenbone
running, which also means the whole path is testable without a nine-container
scanner.

Two filters are applied on the way in, and both exist to keep the table worth
reading:

* **Quality of detection.** Greenbone reports what it is unsure about, with a QoD
  percentage attached. A 30% result is a guess, and a vulnerability list full of
  guesses is one an analyst stops opening.
* **A CVE is required.** ``vulnerabilities.cve_id`` is NOT NULL, and a finding with
  no CVE - an open port, a banner, a log entry - is inventory rather than a
  vulnerability. It belongs in the asset record, not here.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable
from xml.etree import ElementTree

import defusedxml.ElementTree as SafeElementTree
from defusedxml import DefusedXmlException

from netsentinel_api.db.models import Asset, Vulnerability

logger = logging.getLogger("netsentinel.vulns")

#: Below this quality of detection, Greenbone is guessing. 70 is its own default
#: filter, and agreeing with it means the table matches what the Greenbone UI shows.
MIN_QOD = 70

#: The CVSS range the schema allows. Greenbone reports -1.0 for a result it has
#: since decided is not a finding at all, which must not become a row.
MAX_CVSS = 10.0


class ScanError(Exception):
    """The report could not be read."""


@dataclass(frozen=True)
class Finding:
    """One CVE on one host, as the report states it."""

    host: str
    cve_id: str
    cvss: float | None
    detected_at: datetime | None

    @property
    def key(self) -> tuple[str, str]:
        return (self.host, self.cve_id)


@dataclass
class ScanStats:
    fetched: int = 0
    added: int = 0
    updated: int = 0
    #: Findings on an address that is not in ``assets``. Counted rather than
    #: inserted: a vulnerability has to belong to something, and a scan that
    #: wandered outside the inventory is worth noticing.
    unknown_hosts: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "fetched": self.fetched,
            "added": self.added,
            "updated": self.updated,
            "unknown_hosts": self.unknown_hosts,
        }


# --- parsing ---------------------------------------------------------------

def parse_report(xml: str, min_qod: int = MIN_QOD) -> list[Finding]:
    """Turn a ``get_reports`` response into findings, one per CVE per host.

    Parsed with ``defusedxml``: the importer takes a file path, so it cannot know the
    file came from our own gvmd, and the findings inside quote banners and service
    names the scanned hosts chose. Entity expansion and external references are
    refused rather than resolved.
    """
    try:
        root = SafeElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise ScanError(f"the report is not valid XML: {exc}") from exc
    except DefusedXmlException as exc:
        raise ScanError(
            f"the report uses XML entities or external references, which no gvmd report "
            f"needs; refusing it rather than expanding them ({type(exc).__name__})"
        ) from exc

    scanned_at = _report_time(root)

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for result in root.iter("result"):
        host = _host(result)
        if not host:
            continue
        if _qod(result) < min_qod:
            continue

        cvss = _cvss(result)
        detected_at = _time(result.findtext("modification_time")) or scanned_at
        for cve_id in _cves(result):
            # The same CVE on the same host appears once per port it was found on.
            # The table's grain is asset and CVE, so the repeats collapse here
            # rather than becoming rows that differ in nothing.
            if (host, cve_id) in seen:
                continue
            seen.add((host, cve_id))
            findings.append(Finding(host=host, cve_id=cve_id, cvss=cvss,
                                    detected_at=detected_at))

    return findings


def _host(result: ElementTree.Element) -> str | None:
    """The address the finding is on.

    ``<host>`` carries the address as text and the hostname as a child element, so
    only the element's own text is taken.
    """
    element = result.find("host")
    if element is None or not element.text:
        return None
    return normalise_ip(element.text.strip())


def _qod(result: ElementTree.Element) -> int:
    """Greenbone's confidence in the finding, as a percentage.

    A result with no QoD at all is treated as fully trusted: the field is optional
    in older report formats, and dropping those silently would empty the table
    against an older scanner.
    """
    value = result.findtext("qod/value")
    if value is None:
        return 100
    try:
        return int(value)
    except ValueError:
        return 100


def _cvss(result: ElementTree.Element) -> float | None:
    """The severity score, or nothing if the report does not carry a usable one."""
    for path in ("severity", "nvt/severity", "nvt/cvss_base"):
        text = result.findtext(path)
        if not text:
            continue
        try:
            score = float(text)
        except ValueError:
            continue
        # -1.0 is Greenbone's marker for a result it no longer counts as a finding;
        # the CHECK on the column would reject it anyway, and doing so here means a
        # whole import does not fail on one row.
        if 0.0 <= score <= MAX_CVSS:
            return score
    return None


def _cves(result: ElementTree.Element) -> list[str]:
    """Every CVE the finding references.

    Current reports carry them as ``<ref type="cve" id="CVE-...">``; the older
    ``<nvt><cve>`` form is a comma-separated list. Both are read, because a report
    exported from an older gvmd is still a report somebody wants imported.
    """
    ids = [
        ref.get("id", "").strip()
        for ref in result.iterfind("nvt/refs/ref")
        if ref.get("type") == "cve"
    ]
    if not ids:
        legacy = result.findtext("nvt/cve") or ""
        ids = [part.strip() for part in legacy.split(",")]

    return [value for value in ids if value.upper().startswith("CVE-")]


def _report_time(root: ElementTree.Element) -> datetime | None:
    """When the scan finished, which is when its findings were true."""
    for path in (".//scan_end", ".//scan_start"):
        moment = _time(root.findtext(path))
        if moment is not None:
            return moment
    return None


def _time(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.strip())
    except ValueError:
        return None


def normalise_ip(value: str) -> str:
    """One spelling per address, so a report and the asset table can be compared.

    Anything that is not an address is returned unchanged rather than dropped: the
    caller compares it with the inventory, where it will simply not match.
    """
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value


# --- the upsert ------------------------------------------------------------

def sync(
    session,
    findings: Iterable[Finding],
    assets: Iterable[Asset],
    existing: Iterable[Vulnerability],
) -> ScanStats:
    """Add or refresh the ``vulnerabilities`` rows for one report.

    ``assets`` and ``existing`` are passed in rather than queried, as in
    ``services.intel``, so which finding is new and which one moved is decided
    without a database.

    A finding that is already recorded updates its score and its date instead of
    inserting a second row. Two rows for one CVE on one host would double every
    count on the dashboard after each scan, and the table has no unique constraint
    to stop it - this is that constraint, in the one place that writes here.
    """
    stats = ScanStats()
    by_ip = {
        normalise_ip(str(asset.ip_address)): asset
        for asset in assets
        if asset.ip_address
    }
    by_key: dict[tuple[int, str], Vulnerability] = {
        (row.asset_id, row.cve_id): row for row in existing
    }

    for finding in findings:
        stats.fetched += 1
        asset = by_ip.get(finding.host)
        if asset is None:
            stats.unknown_hosts += 1
            continue

        key = (asset.asset_id, finding.cve_id)
        row = by_key.get(key)
        if row is None:
            row = Vulnerability(
                asset_id=asset.asset_id,
                cve_id=finding.cve_id,
                cvss=finding.cvss,
            )
            if finding.detected_at is not None:
                # When the scan saw it, not when the file was imported. A row dated
                # by the import says the estate was vulnerable at a time nobody
                # measured.
                row.detected_at = finding.detected_at
            session.add(row)
            by_key[key] = row
            stats.added += 1
            continue

        row.cvss = finding.cvss
        if finding.detected_at is not None:
            row.detected_at = finding.detected_at
        stats.updated += 1

    if stats.unknown_hosts:
        logger.warning(
            "%s finding(s) are on addresses that are not in assets",
            stats.unknown_hosts,
        )
    return stats
