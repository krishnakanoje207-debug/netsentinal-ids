"""Request and response models.

Separate from the ORM on purpose: a response schema decides what leaves the system.
``password_hash`` exists on the User model and appears in no schema here, which is
the sort of leak that happens the moment a handler returns an ORM object directly.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field

from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    AlertStatus,
    ApprovalDecision,
    Criticality,
    IncidentStatus,
    ModelMode,
    ModelTier,
    SensorStatus,
    SensorType,
    Severity,
)


def _as_text(value: object) -> object:
    """Whatever the driver handed back, as a string.

    ``INET`` columns come out of psycopg 3 as ``ipaddress.IPv4Address`` objects,
    not as text, and Pydantic will not quietly turn one into a ``str``. Without this
    every alert in the feed fails response validation against a real PostgreSQL -
    which the test suite cannot see, because the repositories are faked and hand
    back the strings the fakes were written with.

    Coerced rather than typed as ``IPvAnyAddress`` on purpose: these addresses are
    rendered and never computed with, the dashboard already documents them as
    strings, and a stricter type would change the published schema to buy nothing.
    """
    return str(value) if value is not None else value


#: An address column, as it leaves the API. See ``_as_text``.
IpText = Annotated[str, BeforeValidator(_as_text)]


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(description="seconds until the token expires")


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: int
    username: str
    email: str
    is_active: bool


class CurrentUserOut(UserOut):
    """The caller's own identity, plus what they may do.

    Permissions are served rather than inferred client-side. The dashboard needs them
    to avoid offering a button that will only ever return 403, and duplicating the
    role-to-permission table in TypeScript would guarantee the two drift.
    """

    role: str | None
    permissions: list[str]


class CopilotSummaryOut(BaseModel):
    """A schema-valid summary from the local model, as the dashboard shows it."""

    headline: str
    what_happened: str
    why_it_scored: str
    assessment: str
    next_steps: list[str]
    llm_model: str


class SourceCount(BaseModel):
    address: str
    alerts: int


class AlertSummaryOut(BaseModel):
    """How things stand across every alert, not only the page on screen."""

    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    top_sources: list[SourceCount]


class ActivityBucketOut(BaseModel):
    """One minute of the activity strip."""

    start: datetime = Field(description="the start of the minute, UTC")
    alerts: int
    flows: int | None = Field(
        description="flows scored in the minute; null when flow counts are unavailable"
    )


class ActivityOut(BaseModel):
    """Alerts raised and flows scored per minute, over the last ``minutes`` minutes.

    A flow count ClickHouse could not give is null rather than zero, as with
    ``EvidenceOut``: the dashboard must be able to tell a quiet network from one it
    cannot see.
    """

    minutes: int
    until: datetime = Field(
        description="the end of the newest bucket, which is the current, partial minute"
    )
    buckets: list[ActivityBucketOut] = Field(description="one per minute, oldest first")
    flows_available: bool


class AlertOut(BaseModel):
    """Feed row. Deliberately compact - the dashboard renders hundreds."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: int
    source: str
    severity: Severity
    status: AlertStatus
    src_ip: IpText | None
    dst_ip: IpText | None
    mitre_technique: str | None
    created_at: datetime
    detection_id: int | None


class ExplanationOut(BaseModel):
    """Why the model said what it said.

    ``feature_contributions`` maps a contract feature name to its SHAP value. The
    keys come from netsentinel_core's FEATURE_ORDER, so the dashboard never invents
    a feature name.
    """

    risk_score: float
    model_scores: dict[str, float]
    feature_contributions: dict[str, float]
    top_features: list[str] = Field(
        description="feature names ordered by absolute contribution, strongest first"
    )
    shadow: bool = Field(
        description="true when the verdict was logged but not acted on"
    )


class AlertDetailOut(AlertOut):
    explanation: ExplanationOut | None = None
    ioc_values: list[str] = Field(default_factory=list)


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class EscalateIn(BaseModel):
    # Both optional: the title falls back to one generated from the alert, and an
    # analyst escalating a clear-cut finding has nothing to add that the evidence
    # does not already say.
    title: str | None = Field(default=None, max_length=255)
    summary: str | None = Field(default=None, max_length=4000)


class IncidentOut(BaseModel):
    """An incident as the escalation endpoint returns it.

    Two nullable ids, for different reasons. ``incident_id`` and ``opened_at`` are
    unset until the row reaches the database, as with ``ApprovalOut``.
    ``iris_case_id`` stays null when IRIS is unconfigured or could not be reached,
    which is a state the dashboard has to be able to show rather than an error.
    """

    model_config = ConfigDict(from_attributes=True)

    incident_id: int | None
    iris_case_id: int | None
    title: str
    status: IncidentStatus
    owner_id: int | None
    opened_at: datetime | None


class VulnerabilityOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    vuln_id: int
    cve_id: str
    cvss: float | None
    detected_at: datetime


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: int
    hostname: str
    # INET arrives from psycopg as an ipaddress object; the dashboard renders it and
    # never does arithmetic on it, so it leaves here as text. See ``_as_text``.
    ip_address: IpText
    os: str | None
    criticality: Criticality
    last_scanned_at: datetime | None


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    approval_id: int | None
    approver_id: int
    decision: ApprovalDecision
    comment: str | None
    decided_at: datetime | None


class ActionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    action_id: int
    alert_id: int
    action_type: ActionType
    target: str
    status: ActionStatus
    executed_at: datetime | None
    approval: ApprovalOut | None = None


class ProposeActionIn(BaseModel):
    action_type: ActionType
    # Optional only for block_ip, which defaults to the address the alert says the
    # traffic came from. A host action names an agent, and guessing which machine
    # to isolate is not a default worth having.
    target: str | None = Field(default=None, max_length=255)


class DecisionIn(BaseModel):
    decision: ApprovalDecision
    # Required on a rejection is enforced in the route, not here, so the message
    # can explain why.
    comment: str | None = Field(default=None, max_length=2000)


class RollbackIn(BaseModel):
    # Mandatory, unlike a decision's comment: an executed action is a block a human
    # already authorised on the evidence, so undoing it is always a claim that
    # something about that judgement was wrong, and that is what the next analyst
    # needs to read.
    reason: str = Field(min_length=1, max_length=2000)


class EvidenceOut(BaseModel):
    """What one model did over the report window.

    Not ground truth, and the field names refuse to pretend otherwise. These are
    counts of agreement with analyst verdicts on the flows that were triaged, which
    is a biased sample: nobody labels the traffic nothing fired on. ``unlabelled``
    is served beside ``precision`` for exactly that reason - a tier that fires
    constantly on flows no one ever opens reads as perfect precision and is not.

    True negatives are unknowable here and so are absent rather than zero. A metric
    with nothing to compute it from is null for the same reason: the dashboard must
    be able to tell "no evidence" from "came out at zero".
    """

    scored: int = Field(description="verdicts recorded in the window")
    labelled: int = Field(description="of those, ones an analyst closed a verdict on")
    unlabelled: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float | None
    recall: float | None
    f1: float | None
    average_precision: float | None = Field(
        description="threshold-free ranking quality; how candidates are compared"
    )
    false_positives_per_day: float | None = Field(
        description="the number an analyst actually feels"
    )
    days: float = Field(description="span of shadow traffic observed in the window")


class ModelOut(BaseModel):
    """A registry row with the evidence for and against promoting it."""

    # ``model_id`` and ``model_scores`` are column names, not Pydantic's namespace.
    model_config = ConfigDict(protected_namespaces=())

    model_id: int
    name: str
    tier: ModelTier
    version: str
    threshold: float
    mode: ModelMode
    pr_auc: float | None = Field(description="from the training run, not from live traffic")
    deployed_at: datetime | None
    evidence: EvidenceOut
    blocked_by: str | None = Field(
        description=(
            "why this model may not be promoted, or null if it may; a sentence "
            "rather than a boolean, so the reason can be acted on"
        )
    )


class ModelModeOut(BaseModel):
    """A registry row reduced to what the sensor needs to run the model it names."""

    name: str
    version: str
    tier: ModelTier
    mode: ModelMode


class PromoteIn(BaseModel):
    # The window the decision is made on, spelled as the report and the MISP sync
    # spell it. It travels in the request because the evidence recorded in the
    # audit row has to come from the same query that justified the promotion.
    since: str = Field(default="7d", max_length=10)


class AccountOut(UserOut):
    """An account as the administrator's page lists it. No password hash, as ever."""

    role: str | None
    created_at: datetime | None


class AccountIn(BaseModel):
    username: str = Field(min_length=1, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    # The length rule bcrypt imposes is checked by hash_password, which says why.
    password: str = Field(min_length=1)
    role: str = Field(max_length=50)


class AccountUpdate(BaseModel):
    """Either field, or both; one left out is left alone."""

    role: str | None = Field(default=None, max_length=50)
    is_active: bool | None = None


class RoleOut(BaseModel):
    name: str
    permissions: list[str]


class SensorOut(BaseModel):
    sensor_id: int
    type: SensorType
    hostname: str
    status: SensorStatus
    last_seen: datetime | None
    revoked: bool


class SensorUpdate(BaseModel):
    revoked: bool


class AuditEntryOut(BaseModel):
    log_id: int
    ts: datetime
    user_id: int | None
    username: str | None = Field(description="null for a system action")
    action: str
    entity: str
    details: dict


class HealthOut(BaseModel):
    status: str
    version: str
    feature_dim: int = Field(description="size of the model input vector in use")
