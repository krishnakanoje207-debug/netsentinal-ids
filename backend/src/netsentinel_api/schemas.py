"""Request and response models.

Separate from the ORM on purpose: a response schema decides what leaves the system.
``password_hash`` exists on the User model and appears in no schema here, which is
the sort of leak that happens the moment a handler returns an ORM object directly.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    AlertStatus,
    ApprovalDecision,
    Criticality,
    IncidentStatus,
    ModelMode,
    ModelTier,
    Severity,
)


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


class AlertOut(BaseModel):
    """Feed row. Deliberately compact - the dashboard renders hundreds."""

    model_config = ConfigDict(from_attributes=True)

    alert_id: int
    source: str
    severity: Severity
    status: AlertStatus
    src_ip: str | None
    dst_ip: str | None
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
    # INET comes back as a string; the dashboard renders it and never does
    # arithmetic on it.
    ip_address: str
    os: str | None
    criticality: Criticality


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


class PromoteIn(BaseModel):
    # The window the decision is made on, spelled as the report and the MISP sync
    # spell it. It travels in the request because the evidence recorded in the
    # audit row has to come from the same query that justified the promotion.
    since: str = Field(default="7d", max_length=10)


class HealthOut(BaseModel):
    status: str
    version: str
    feature_dim: int = Field(description="size of the model input vector in use")
