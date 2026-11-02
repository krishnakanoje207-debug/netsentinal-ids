"""Wazuh alerts reduced to explicit rule and event metadata, never raw payloads."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import PureWindowsPath

from sqlalchemy.dialects.postgresql import insert

from netsentinel_api.db.models import Alert, AlertStatus, Severity
from netsentinel_api.services.vulns import normalise_ip


def _object(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    return value


def _text(value, length=255) -> str | None:
    if value is None:
        return None
    if not isinstance(value, (str, int)) or isinstance(value, bool):
        raise ValueError("expected text")
    return " ".join(str(value).split())[:length]


def _time(value) -> datetime:
    at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if at.tzinfo is None:
        raise ValueError("event time must include timezone")
    return at


def severity_for(level: int) -> Severity:
    # Our conservative mapping; retain the original Wazuh level as evidence.
    if level >= 15:
        return Severity.critical
    if level >= 11:
        return Severity.high
    if level >= 7:
        return Severity.medium
    return Severity.low


@dataclass(frozen=True)
class HostAlert:
    event_id: str
    at: datetime
    severity: Severity
    src_ip: str | None
    dst_ip: str | None
    technique: str | None
    details: dict


def parse_alert(line: str) -> HostAlert | None:
    """Only actual Wazuh alerts (level >= 3); reject malformed identity/time."""
    if len(line) > 1_048_576:
        raise ValueError("event exceeds the import size bound")
    event = _object(json.loads(line))
    rule, agent, manager = (_object(event[key]) for key in ("rule", "agent", "manager"))
    level = rule["level"]
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 16:
        raise ValueError("invalid Wazuh level")
    if level < 3:
        return None
    identity, manager_name = event["id"], manager["name"]
    if (not isinstance(identity, str) or not re.fullmatch(r"\d{1,20}\.\d{1,40}", identity)
            or not isinstance(manager_name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", manager_name)):
        raise ValueError("invalid Wazuh event identity")
    agent_id, rule_id = _text(agent["id"], 32), _text(rule["id"], 32)
    if not agent_id or not rule_id or not agent_id.isdigit() or not rule_id.isdigit():
        raise ValueError("invalid agent or rule identity")
    reported_at = _time(event["timestamp"])
    data = _object(event.get("data", {}))
    win = _object(data.get("win", {}))
    system, fields = _object(win.get("system", {})), _object(win.get("eventdata", {}))
    at = _time(system["systemTime"]) if system.get("systemTime") else reported_at
    mitre = _object(rule.get("mitre", {})).get("id", [])
    if not isinstance(mitre, list):
        raise ValueError("invalid MITRE identifiers")
    technique = next((x for x in mitre if isinstance(x, str)
                      and re.fullmatch(r"T\d{4}(?:\.\d{3})?", x)), None)
    image = _text(fields.get("image"), 1024)
    details = {
        "agent_id": agent_id, "agent_name": _text(agent.get("name")),
        "manager": manager_name, "rule_id": rule_id, "rule_level": level,
        "description": _text(rule.get("description"), 500),
        "channel": _text(system.get("channel")), "event_id": _text(system.get("eventID"), 32),
        "event_record_id": _text(system.get("eventRecordID"), 32),
        "computer": _text(system.get("computer")),
        "process_image": PureWindowsPath(image).name if image else None,
        "process_id": _text(fields.get("processId"), 32),
        "reported_at": reported_at.isoformat(),
    }
    # agent.ip is its transport connection to the manager, often loopback here.
    # Only addresses explicitly observed in the event describe network traffic.
    src = fields.get("sourceIp") or data.get("srcip")
    dst = fields.get("destinationIp") or data.get("dstip")
    return HostAlert(
        f"{manager_name}:{identity}", at, severity_for(level),
        normalise_ip(src) if isinstance(src, str) else None,
        normalise_ip(dst) if isinstance(dst, str) else None,
        technique, details,
    )


def import_alert(session, event: HostAlert, *, asset_id: int | None = None) -> int | None:
    """Database uniqueness handles replays and concurrent importers atomically."""
    return session.scalar(insert(Alert).values(
        source="wazuh", source_event_id=event.event_id, source_details=event.details,
        created_at=event.at, severity=event.severity, status=AlertStatus.new,
        src_ip=event.src_ip, dst_ip=event.dst_ip, asset_id=asset_id,
        mitre_technique=event.technique,
    ).on_conflict_do_nothing(constraint="uq_alert_source_event").returning(Alert.alert_id))
