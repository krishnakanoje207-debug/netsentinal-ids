"""Suricata signature alerts into the ``alerts`` table.

The models score flows; Suricata matches known-bad content against ET Open rules.
Both end up in front of the same analyst, so both belong in the same feed. A
signature alert has no detection behind it - ``alerts.detection_id`` is nullable for
exactly this - and the dashboard already says "no model explanation" when it sees one.

Input is Suricata's ``eve.json``: one JSON object per line, of which only
``event_type: alert`` records are alerts. The rest (flow, http, ssh, stats) is
telemetry the models have their own path for.

The table has no column for the signature itself, so the rule name and sid are not
stored. What is kept is what the schema has room for: when, between whom, how bad,
and the ATT&CK technique when the rule's metadata names one.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from netsentinel_api.db.models import Alert, Severity
from netsentinel_api.services.vulns import normalise_ip

SOURCE = "suricata"

#: Suricata's severity runs 1 (worst) to 3; ET Open uses exactly those three. Critical
#: is left to the models and to people, since a rule match alone is not a confirmed
#: compromise.
SEVERITIES = {1: Severity.high, 2: Severity.medium, 3: Severity.low}

_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class EveError(Exception):
    """The file could not be read as eve.json."""


@dataclass(frozen=True)
class SignatureAlert:
    """One rule match, reduced to what an ``alerts`` row can hold."""

    at: datetime
    src_ip: str | None
    dst_ip: str | None
    severity: Severity
    technique: str | None

    @property
    def key(self) -> tuple:
        return (self.at, self.src_ip, self.dst_ip, self.severity, self.technique)


def parse_eve(lines: Iterable[str]) -> list[SignatureAlert]:
    """The alert records in an eve.json stream, in file order."""
    found: list[SignatureAlert] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise EveError(f"line {number} is not JSON: {exc}") from exc
        if event.get("event_type") != "alert":
            continue
        alert = event.get("alert") or {}
        found.append(
            SignatureAlert(
                at=_time(event.get("timestamp"), number),
                src_ip=_ip(event.get("src_ip")),
                dst_ip=_ip(event.get("dest_ip")),
                severity=SEVERITIES.get(alert.get("severity"), Severity.info),
                technique=_technique(alert.get("metadata") or {}),
            )
        )
    return found


def _time(value: str | None, number: int) -> datetime:
    try:
        return datetime.fromisoformat(value or "")
    except ValueError as exc:
        raise EveError(f"line {number} has no usable timestamp: {value!r}") from exc


def _ip(value: str | None) -> str | None:
    return normalise_ip(value) if value else None


def _technique(metadata: dict) -> str | None:
    """The first ATT&CK technique id in the rule's metadata, if it names one.

    ET Open writes it as ``mitre_technique_id``; many rules have none, and a guess
    would be worse than the empty column.
    """
    for value in metadata.get("mitre_technique_id") or []:
        if _TECHNIQUE.match(value):
            return value
    return None


def sync(session, found: Iterable[SignatureAlert], existing: Iterable[Alert]) -> int:
    """Insert the alerts not already recorded, and return how many were added.

    ``existing`` is passed in, as in ``services.vulns``, so the decision is testable
    without a database. Re-importing a file must not double the feed, and there is no
    event id column to be unique on, so the rows are compared as a multiset: a file
    with three identical matches and a table already holding two gets one more.
    """
    have = Counter(
        (
            alert.created_at,
            _ip(str(alert.src_ip)) if alert.src_ip else None,
            _ip(str(alert.dst_ip)) if alert.dst_ip else None,
            alert.severity,
            alert.mitre_technique,
        )
        for alert in existing
        if alert.source == SOURCE
    )
    added = 0
    for match in found:
        if have[match.key] > 0:
            have[match.key] -= 1
            continue
        session.add(
            Alert(
                source=SOURCE,
                severity=match.severity,
                src_ip=match.src_ip,
                dst_ip=match.dst_ip,
                mitre_technique=match.technique,
                created_at=match.at,
            )
        )
        added += 1
    return added
