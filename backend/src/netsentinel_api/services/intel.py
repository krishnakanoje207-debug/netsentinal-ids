"""Threat intelligence: MISP attributes in, IoC matches on alerts out.

Two halves that are deliberately kept apart.

**Sync** pulls attributes from a MISP instance into the ``iocs`` table. Parsing is
separated from fetching so the mapping - which MISP type becomes which IoC type, and
what happens to the ones with no equivalent - is testable without a MISP to talk to.

**Enrichment** matches an alert's addresses against that table and records the hits in
``alert_iocs``. The query is one thin function; the rule that decides what a match does
takes the alert and the matches as arguments, for the same reason the response gate
does - a rule that needs a database to exercise is a rule nobody exercises.

What is asked of MISP matters as much as what is done with the answer. The search
requests ``to_ids`` attributes only and enforces the warninglists, so the feed that
arrives is the set of indicators MISP itself considers actionable and not, say, every
address someone once mentioned in an event. Without those two flags a public feed will
happily hand over 8.8.8.8, and one afternoon later every DNS lookup in the lab is an
alert with intelligence backing it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from sqlalchemy import Select, select, tuple_

from netsentinel_api.db.models import Alert, AlertIoC, IoC, IoCType, Severity

logger = logging.getLogger("netsentinel.intel")

#: MISP attribute type to the contract's IoC type. Anything absent is skipped rather
#: than coerced: an indicator stored under the wrong type never matches, which is a
#: silent miss, and a silent miss in threat intelligence is worse than a visible gap.
MISP_TYPE_MAP: dict[str, IoCType] = {
    "ip-src": IoCType.ip,
    "ip-dst": IoCType.ip,
    "ip-src|port": IoCType.ip,
    "ip-dst|port": IoCType.ip,
    "domain": IoCType.domain,
    "hostname": IoCType.domain,
    "domain|ip": IoCType.domain,
    "url": IoCType.url,
    "sha256": IoCType.sha256,
    "filename|sha256": IoCType.sha256,
    "ja4": IoCType.ja4,
    "ja4-fingerprint": IoCType.ja4,
}

#: MISP threat levels are inverted - 1 is the most severe - and stored as MISP means
#: them so an indicator can be traced back to its event without a translation table.
MISP_THREAT_HIGH = 1

#: Severity ladder, for the one-band escalation a high-threat match earns.
SEVERITY_LADDER: tuple[Severity, ...] = (
    Severity.info,
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
)

#: iocs.value is VARCHAR(500). A URL longer than that is truncated by the database
#: without complaint, and a truncated indicator matches nothing while looking fine.
MAX_VALUE_LENGTH = 500


class IntelError(RuntimeError):
    """Intelligence could not be synchronised."""


@dataclass(slots=True, frozen=True)
class Indicator:
    """One MISP attribute, in this system's terms."""

    value: str
    type: IoCType
    event_id: int | None = None
    threat_level: int | None = None

    @property
    def key(self) -> tuple[str, IoCType]:
        """What uq_ioc_value_type makes unique."""
        return (self.value, self.type)


@dataclass(slots=True)
class SyncStats:
    fetched: int = 0
    added: int = 0
    updated: int = 0
    skipped: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "fetched": self.fetched,
            "added": self.added,
            "updated": self.updated,
            "skipped": self.skipped,
        }


# --- parsing ---------------------------------------------------------------

def parse_attributes(payload: Any) -> list[Indicator]:
    """Turn a restSearch response into indicators, dropping what does not map.

    Composite MISP values (``1.2.3.4|443``, ``example.com|1.2.3.4``) keep the left
    half, which is the part this system can match against a flow.
    """
    if not isinstance(payload, dict):
        raise IntelError(f"MISP returned {type(payload).__name__}, expected an object")

    attributes = (payload.get("response") or {}).get("Attribute")
    if attributes is None:
        raise IntelError("MISP response has no response.Attribute array")

    indicators: list[Indicator] = []
    for attribute in attributes:
        if not isinstance(attribute, dict):
            continue
        ioc_type = MISP_TYPE_MAP.get(str(attribute.get("type")))
        if ioc_type is None:
            continue

        value = str(attribute.get("value") or "").strip()
        if "|" in value:
            value = value.split("|", 1)[0].strip()
        if not value or len(value) > MAX_VALUE_LENGTH:
            continue

        indicators.append(
            Indicator(
                value=value,
                type=ioc_type,
                event_id=_optional_int(attribute.get("event_id")),
                threat_level=_optional_int(
                    (attribute.get("Event") or {}).get("threat_level_id")
                ),
            )
        )
    return indicators


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --- sync ------------------------------------------------------------------

def sync(session, indicators: Iterable[Indicator], existing: Iterable[IoC]) -> SyncStats:
    """Add or refresh the ``iocs`` rows for these indicators.

    ``existing`` is passed in rather than queried so the decision - which indicator is
    new, which one moved to another event - is exercisable without a database.

    Duplicates within one feed collapse onto one row: the unique constraint would
    reject the second insert and take the whole sync with it.
    """
    stats = SyncStats()
    by_key: dict[tuple[str, IoCType], IoC] = {(row.value, row.type): row for row in existing}

    for indicator in indicators:
        stats.fetched += 1
        row = by_key.get(indicator.key)
        if row is None:
            row = IoC(
                value=indicator.value,
                type=indicator.type,
                misp_event_id=indicator.event_id,
                threat_level=indicator.threat_level,
            )
            session.add(row)
            by_key[indicator.key] = row
            stats.added += 1
            continue

        if (row.misp_event_id, row.threat_level) == (
            indicator.event_id,
            indicator.threat_level,
        ):
            stats.skipped += 1
            continue

        row.misp_event_id = indicator.event_id
        row.threat_level = indicator.threat_level
        stats.updated += 1

    return stats


# --- enrichment ------------------------------------------------------------

def lookup_keys(alert: Alert) -> list[tuple[str, IoCType]]:
    """What of this alert can be looked up in the IoC table.

    Addresses only for now. A flow carries no domain, URL or file hash - those reach
    the system through Zeek and Wazuh, which land in ClickHouse rather than here.
    """
    return [
        (str(address), IoCType.ip)
        for address in (alert.src_ip, alert.dst_ip)
        if address
    ]


def match_statement(keys: Sequence[tuple[str, IoCType]]) -> Select:
    """Every IoC row matching one of these (value, type) pairs.

    One query over the pair rather than two over the value, because uq_ioc_value_type
    is on the pair: an address and a hostname can share a string, and matching on the
    value alone would attribute a domain indicator to an address.
    """
    return select(IoC).where(tuple_(IoC.value, IoC.type).in_([tuple(key) for key in keys]))


def find(session, alert: Alert) -> list[IoC]:
    """The indicators this alert touches. Nothing is queried when there is nothing to ask."""
    keys = lookup_keys(alert)
    if not keys:
        return []
    return list(session.scalars(match_statement(keys)))


def link(session, alert: Alert, matches: Sequence[IoC]) -> list[IoC]:
    """Record the matches against the alert and escalate if any is high threat.

    One band, once, however many indicators matched. An alert that touches four
    members of the same botnet is not four times as urgent as one that touches one,
    and stacking the escalation would walk every such alert to critical.
    """
    if not matches:
        return []

    already = {ioc.ioc_id for ioc in alert.iocs} if alert.iocs else set()
    linked: list[IoC] = []
    for ioc in matches:
        if ioc.ioc_id is not None and ioc.ioc_id in already:
            continue
        session.add(AlertIoC(alert_id=alert.alert_id, ioc_id=ioc.ioc_id))
        linked.append(ioc)

    if any(ioc.threat_level == MISP_THREAT_HIGH for ioc in matches):
        alert.severity = escalate(alert.severity)
    return linked


def escalate(severity: Severity) -> Severity:
    """One band up, capped at critical."""
    index = SEVERITY_LADDER.index(severity)
    return SEVERITY_LADDER[min(index + 1, len(SEVERITY_LADDER) - 1)]
