"""Suricata signature alerts into the ``alerts`` table.

The models score flows; Suricata matches known-bad content against ET Open rules.
Both end up in front of the same analyst, so both belong in the same feed. A
signature alert has no detection behind it - ``alerts.detection_id`` is nullable for
exactly this - and the dashboard already says "no model explanation" when it sees one.

Input is Suricata's ``eve.json``: one JSON object per line, of which only
``event_type: alert`` records are alerts. The rest (flow, http, ssh, stats) is
telemetry the models have their own path for.

Not every alert record is a detection. ET Open's ``ET INFO`` and ``ET HUNTING`` rules
are context - curl talking to a bare IP, an unconfigured nginx - and on the lab's
captures they outnumbered the attack signatures eight to one, and were every alert on
the benign one. They are counted and skipped, so the feed holds what an analyst should
act on.

The table has no column for the signature itself, so the rule name and sid are not
stored. What is kept is what the schema has room for: when, between whom, how bad,
and the ATT&CK technique when the rule's metadata names one.

**Corroboration** is the signature half of FR-10's fusion. A model alert and a rule
match between the same two addresses at the same time are two independent methods
agreeing, one on the flow's shape and one on its content, and the model alert is
raised a band for it, once, as an intelligence match raises it. The signature alert
stays in the feed as its own row; the model alert names it.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable

from netsentinel_api.db.models import Alert, AuditLog, Severity
from netsentinel_api.services.intel import escalate
from netsentinel_api.services.vulns import normalise_ip

SOURCE = "suricata"

#: Suricata's severity runs 1 (worst) to 3; ET Open uses exactly those three. Critical
#: is left to the models and to people, since a rule match alone is not a confirmed
#: compromise.
SEVERITIES = {1: Severity.high, 2: Severity.medium, 3: Severity.low}

#: Rule-name prefixes of ET Open's informational and hunting rules, which are not
#: detections.
CONTEXT_PREFIXES = ("ET INFO ", "ET HUNTING ")

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
    signature: str

    @property
    def context(self) -> bool:
        return self.signature.startswith(CONTEXT_PREFIXES)

    @property
    def key(self) -> tuple:
        return (self.at, self.src_ip, self.dst_ip, self.severity, self.technique)


def parse_eve(lines: Iterable[str], malformed: list[int] | None = None) -> list[SignatureAlert]:
    """The alert records in an eve.json stream, in file order.

    A line that is not a usable record is skipped and its number appended to
    ``malformed``: one bad line must not cost every alert after it. The exception is
    a last line with no newline that does not parse. Suricata is still appending it,
    so it is left alone; the next run reads the file from the start again and finds
    it finished.
    """
    found: list[SignatureAlert] = []
    skipped = malformed if malformed is not None else []
    unfinished: int | None = None
    for number, line in enumerate(lines, start=1):
        if unfinished is not None:
            # A line followed by another was not being written; it is just bad.
            skipped.append(unfinished)
            unfinished = None
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            if line.endswith("\n"):
                skipped.append(number)
            else:
                unfinished = number
            continue
        if not isinstance(event, dict):
            skipped.append(number)
            continue
        if event.get("event_type") != "alert":
            continue
        try:
            at = _time(event.get("timestamp"), number)
        except EveError:
            skipped.append(number)
            continue
        alert = event.get("alert") or {}
        found.append(
            SignatureAlert(
                at=at,
                src_ip=_ip(event.get("src_ip")),
                dst_ip=_ip(event.get("dest_ip")),
                severity=SEVERITIES.get(alert.get("severity"), Severity.info),
                technique=_technique(alert.get("metadata") or {}),
                signature=alert.get("signature") or "",
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

    Context rules (``CONTEXT_PREFIXES``) are never inserted.

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
        if match.context:
            continue
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


# --- corroboration ---------------------------------------------------------

#: How far apart a rule match and a model alert on the same flow can be. A rule fires
#: on a packet; the model alert is written when the flow ends, up to the sensor's
#: active timeout (120 s) plus its idle timeout (15 s) later, and delivery adds seconds.
CORROBORATION_WINDOW = timedelta(seconds=150)


def corroborate(
    model_alerts: Iterable[Alert],
    signature_alerts: Iterable[Alert],
    window: timedelta = CORROBORATION_WINDOW,
) -> list[tuple[Alert, Alert]]:
    """Pair each model alert with the nearest signature alert between the same two
    addresses, in either direction, within ``window``.

    Either direction, because a rule can fire on the reply: ET's web rules match the
    request, but a response rule names the server as the source. An alert already
    corroborated, or with no detection behind it, is left alone.
    """
    by_pair: dict[frozenset, list[Alert]] = defaultdict(list)
    for signature in signature_alerts:
        # Only a rule match counts: two model alerts agreeing are one method twice.
        if signature.source == SOURCE and signature.src_ip and signature.dst_ip:
            by_pair[_pair(signature)].append(signature)

    pairs = []
    for alert in model_alerts:
        if alert.detection_id is None or alert.corroborated_by_alert_id is not None:
            continue
        if not (alert.src_ip and alert.dst_ip):
            continue
        near = [
            signature
            for signature in by_pair.get(_pair(alert), ())
            if abs(signature.created_at - alert.created_at) <= window
        ]
        if near:
            pairs.append(
                (alert, min(near, key=lambda s: abs(s.created_at - alert.created_at)))
            )
    return pairs


def raise_corroborated(session, pairs: Iterable[tuple[Alert, Alert]]) -> int:
    """Raise each model alert a band, record the signature that did it, and audit it."""
    raised = 0
    for alert, signature in pairs:
        before = alert.severity
        alert.severity = escalate(before)
        alert.corroborated_by_alert_id = signature.alert_id
        session.add(
            AuditLog(
                user_id=None,  # the import pass decided it; nobody is logged in
                action="alert.corroborated",
                entity=f"alert:{alert.alert_id}",
                details={
                    "signature_alert_id": signature.alert_id,
                    "from": before.value,
                    "to": alert.severity.value,
                },
            )
        )
        raised += 1
    return raised


def _pair(alert: Alert) -> frozenset:
    return frozenset({_ip(str(alert.src_ip)), _ip(str(alert.dst_ip))})
