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


class DecisionIn(BaseModel):
    decision: ApprovalDecision
    # Required on a rejection is enforced in the route, not here, so the message
    # can explain why.
    comment: str | None = Field(default=None, max_length=2000)


class HealthOut(BaseModel):
    status: str
    version: str
    feature_dim: int = Field(description="size of the model input vector in use")
