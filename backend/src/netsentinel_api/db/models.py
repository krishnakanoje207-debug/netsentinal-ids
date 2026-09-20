"""The application schema from M2 section 3.2, as SQLAlchemy models.

PostgreSQL-specific on purpose: JSONB and INET are in the design, and testing
against a different database than the one we deploy on is how schema bugs reach
production. The DDL tests compile against the PostgreSQL dialect, which needs no
running server.

Three invariants from the M2 class diagram are enforced here rather than left to
application code, because a rule that lives only in a service is one forgotten
call away from being broken:

1. ``detections.shap_values`` is NOT NULL - no unexplained ML verdict can exist.
2. ``approvals.action_id`` is UNIQUE - an action has at most one decision.
3. ``response_actions`` cannot be marked executed without an execution time, and
   the service layer additionally refuses to execute one without an approval.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


def _enum(python_enum: type[enum.Enum], name: str) -> Enum:
    """Store enums as VARCHAR plus a CHECK, not as a native PostgreSQL ENUM.

    Adding a value to a native enum needs a migration that cannot run inside a
    transaction on older servers; widening a CHECK is a plain ALTER.

    ``create_constraint=True`` is not the default and has not been since
    SQLAlchemy 1.4: without it this renders a bare VARCHAR that accepts any
    string, and the value domain is enforced nowhere.
    """
    return Enum(
        python_enum,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
    )


# --- value domains ---------------------------------------------------------

class Severity(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    new = "new"
    triaging = "triaging"
    escalated = "escalated"
    closed_true_positive = "closed_true_positive"
    closed_false_positive = "closed_false_positive"


class Criticality(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"


class SensorType(str, enum.Enum):
    suricata = "suricata"
    zeek = "zeek"
    early_flow = "early_flow"
    wazuh_agent = "wazuh_agent"
    openvas = "openvas"


class SensorStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    degraded = "degraded"


class ModelTier(str, enum.Enum):
    """The four tiers of the M2 AI/ML engine."""

    A = "A"  # LightGBM / XGBoost over flow aggregates
    B = "B"  # 1D-CNN + BiLSTM over packet sequences
    C = "C"  # E-GraphSAGE over the flow graph
    D = "D"  # Isolation Forest + autoencoder, unsupervised


class ModelMode(str, enum.Enum):
    shadow = "shadow"
    active = "active"
    retired = "retired"


class IncidentStatus(str, enum.Enum):
    open = "open"
    contained = "contained"
    closed = "closed"


class IoCType(str, enum.Enum):
    ip = "ip"
    domain = "domain"
    url = "url"
    sha256 = "sha256"
    ja4 = "ja4"


class ActionType(str, enum.Enum):
    block_ip = "block_ip"
    isolate_host = "isolate_host"
    kill_process = "kill_process"
    disable_account = "disable_account"


class ActionStatus(str, enum.Enum):
    pending_approval = "pending_approval"
    approved = "approved"
    rejected = "rejected"
    executed = "executed"
    rolled_back = "rolled_back"
    failed = "failed"


class ApprovalDecision(str, enum.Enum):
    approved = "approved"
    rejected = "rejected"


# --- identity and access ---------------------------------------------------

class Role(Base):
    __tablename__ = "roles"

    role_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    permissions: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    users: Mapped[list[User]] = relationship(back_populates="role")


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role_id: Mapped[int] = mapped_column(ForeignKey("roles.role_id"), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    role: Mapped[Role] = relationship(back_populates="users")


# --- estate ----------------------------------------------------------------

class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(INET, nullable=False)
    os: Mapped[str | None] = mapped_column(String(100))
    criticality: Mapped[Criticality] = mapped_column(
        _enum(Criticality, "criticality"), nullable=False, default=Criticality.medium
    )


class Sensor(Base):
    __tablename__ = "sensors"

    sensor_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    type: Mapped[SensorType] = mapped_column(_enum(SensorType, "sensor_type"), nullable=False)
    host_asset_id: Mapped[int] = mapped_column(ForeignKey("assets.asset_id"), nullable=False)
    status: Mapped[SensorStatus] = mapped_column(
        _enum(SensorStatus, "sensor_status"), nullable=False, default=SensorStatus.offline
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    vuln_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.asset_id"), nullable=False)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False)
    cvss: Mapped[float | None] = mapped_column(Float)
    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("cvss IS NULL OR (cvss >= 0 AND cvss <= 10)", name="ck_cvss_range"),
    )


# --- models and detections -------------------------------------------------

class MLModel(Base):
    __tablename__ = "ml_models"

    model_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    tier: Mapped[ModelTier] = mapped_column(_enum(ModelTier, "model_tier"), nullable=False)
    version: Mapped[str] = mapped_column(String(30), nullable=False)
    onnx_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    threshold: Mapped[float] = mapped_column(Float, nullable=False)
    mode: Mapped[ModelMode] = mapped_column(
        # A new model is never trusted on arrival: it observes until someone
        # promotes it.
        _enum(ModelMode, "model_mode"), nullable=False, default=ModelMode.shadow
    )
    pr_auc: Mapped[float | None] = mapped_column(Float)
    deployed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_model_name_version"),
        CheckConstraint("char_length(onnx_sha256) = 64", name="ck_onnx_sha256_length"),
    )


class Detection(Base):
    """One scored flow. Always carries its explanation."""

    __tablename__ = "detections"

    detection_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    flow_id: Mapped[str] = mapped_column(String(120), nullable=False)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.sensor_id"), nullable=False)
    model_id: Mapped[int] = mapped_column(ForeignKey("ml_models.model_id"), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    model_scores: Mapped[dict] = mapped_column(JSONB, nullable=False)
    # NOT NULL is the point: M2's class diagram composes a Detection with exactly
    # one Explanation, so an unexplained verdict must be unrepresentable.
    shap_values: Mapped[dict] = mapped_column(JSONB, nullable=False)
    shadow: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="ck_risk_score_range"),
        Index("ix_detections_flow_id", "flow_id"),
    )


# --- triage ----------------------------------------------------------------

class Incident(Base):
    __tablename__ = "incidents"

    incident_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    iris_case_id: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        _enum(IncidentStatus, "incident_status"), nullable=False, default=IncidentStatus.open
    )
    owner_id: Mapped[int | None] = mapped_column(ForeignKey("users.user_id"))
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Alert(Base):
    __tablename__ = "alerts"

    alert_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable: signature and host alerts arrive from Suricata or Wazuh with no ML
    # detection behind them.
    detection_id: Mapped[int | None] = mapped_column(ForeignKey("detections.detection_id"))
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.asset_id"))
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.incident_id"))
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        _enum(AlertStatus, "alert_status"), nullable=False, default=AlertStatus.new
    )
    src_ip: Mapped[str | None] = mapped_column(INET)
    dst_ip: Mapped[str | None] = mapped_column(INET)
    mitre_technique: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    detection: Mapped[Detection | None] = relationship()
    iocs: Mapped[list[IoC]] = relationship(secondary="alert_iocs", back_populates="alerts")
    actions: Mapped[list[ResponseAction]] = relationship(back_populates="alert")

    __table_args__ = (
        # The dashboard's default view is newest-first, so the index is too.
        Index("ix_alerts_created_at", created_at.desc()),
        Index("ix_alerts_status_severity", "status", "severity"),
        Index("ix_alerts_src_ip", "src_ip"),
    )


class IoC(Base):
    __tablename__ = "iocs"

    ioc_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    type: Mapped[IoCType] = mapped_column(_enum(IoCType, "ioc_type"), nullable=False)
    misp_event_id: Mapped[int | None] = mapped_column(Integer)
    threat_level: Mapped[int | None] = mapped_column(Integer)

    alerts: Mapped[list[Alert]] = relationship(secondary="alert_iocs", back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("value", "type", name="uq_ioc_value_type"),
        Index("ix_iocs_value", "value"),
    )


class AlertIoC(Base):
    """Resolves the many-to-many between alerts and IoCs (M2 3NF note)."""

    __tablename__ = "alert_iocs"

    alert_id: Mapped[int] = mapped_column(
        ForeignKey("alerts.alert_id", ondelete="CASCADE"), primary_key=True
    )
    ioc_id: Mapped[int] = mapped_column(
        ForeignKey("iocs.ioc_id", ondelete="CASCADE"), primary_key=True
    )


# --- response and the human gate -------------------------------------------

class ResponseAction(Base):
    __tablename__ = "response_actions"

    action_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    action_type: Mapped[ActionType] = mapped_column(_enum(ActionType, "action_type"), nullable=False)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[ActionStatus] = mapped_column(
        _enum(ActionStatus, "action_status"),
        nullable=False,
        default=ActionStatus.pending_approval,
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    alert: Mapped[Alert] = relationship(back_populates="actions")
    approval: Mapped[Approval | None] = relationship(back_populates="action", uselist=False)

    __table_args__ = (
        # An action cannot claim to have executed without saying when. Only this
        # direction is enforced: a rolled back action keeps the executed_at of the
        # execution it is undoing, so a timestamp without the 'executed' status is
        # legitimate.
        CheckConstraint(
            "status <> 'executed' OR executed_at IS NOT NULL",
            name="ck_executed_has_timestamp",
        ),
        Index("ix_response_actions_alert_id", "alert_id"),
    )


class Approval(Base):
    """A human decision on one action. The gate in "human-in-the-loop"."""

    __tablename__ = "approvals"

    approval_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Unique, not merely a foreign key: M2 makes this 1:1, so one action cannot
    # accumulate approvals until one of them says yes.
    action_id: Mapped[int] = mapped_column(
        ForeignKey("response_actions.action_id"), nullable=False, unique=True
    )
    approver_id: Mapped[int] = mapped_column(ForeignKey("users.user_id"), nullable=False)
    decision: Mapped[ApprovalDecision] = mapped_column(
        _enum(ApprovalDecision, "approval_decision"), nullable=False
    )
    comment: Mapped[str | None] = mapped_column(Text)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    action: Mapped[ResponseAction] = relationship(back_populates="approval")


# --- copilot and audit -----------------------------------------------------

class CopilotSummary(Base):
    __tablename__ = "copilot_summaries"

    summary_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.alert_id"), nullable=False)
    summary_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    llm_model: Mapped[str] = mapped_column(String(100), nullable=False)
    # False means the model returned something that failed Pydantic validation.
    # Kept rather than discarded, because a pattern of invalid output is a signal.
    schema_valid: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    log_id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so system actions are recordable, and ON DELETE SET NULL so an
    # audit row outlives the user it refers to. An audit trail that can be erased
    # by deleting an account is not an audit trail.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.user_id", ondelete="SET NULL")
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    entity: Mapped[str] = mapped_column(String(100), nullable=False)
    details: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (Index("ix_audit_log_ts", "ts"),)
