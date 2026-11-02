"""The complete cloud export contract: identifiers and alert metadata only."""
from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy.dialects.postgresql import insert

from netsentinel_api.db.models import Alert, AlertStatus, Severity


class TelemetryAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    local_alert_id: int = Field(gt=0, strict=True)
    occurred_at: AwareDatetime
    severity: Severity
    source: Literal["ml", "wazuh", "suricata"]
    rule_id: str | None = Field(default=None, pattern=r"^[0-9]{1,32}$")
    model_id: int | None = Field(default=None, gt=0, strict=True)


class TelemetryBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host_id: str = Field(pattern=r"^host_[a-f0-9]{24}$")
    alerts: list[TelemetryAlert] = Field(min_length=1, max_length=100)


def export_alert(alert: Alert) -> TelemetryAlert | None:
    source = "ml" if alert.detection is not None else alert.source
    if source not in {"ml", "wazuh", "suricata"}:
        return None
    rule_id = (alert.source_details or {}).get("rule_id")
    # Old signature imports have no saved rule ID; do not invent one.
    return TelemetryAlert(
        local_alert_id=alert.alert_id, occurred_at=alert.created_at,
        severity=alert.severity, source=source,
        rule_id=rule_id if isinstance(rule_id, str) and rule_id.isascii() and rule_id.isdigit() else None,
        model_id=alert.detection.model_id if alert.detection else None,
    )


def receive(session, batch: TelemetryBatch) -> int:
    added = 0
    for event in batch.alerts:
        metadata = event.model_dump(mode="json", exclude={"occurred_at", "severity"})
        metadata["host_id"] = batch.host_id
        result = session.scalar(insert(Alert).values(
            source="telemetry", source_event_id=f"{batch.host_id}:{event.local_alert_id}",
            source_details=metadata, created_at=event.occurred_at,
            severity=event.severity, status=AlertStatus.new,
        ).on_conflict_do_nothing(constraint="uq_alert_source_event").returning(Alert.alert_id))
        added += result is not None
    return added
