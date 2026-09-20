"""Permissions and the roles from the M2 use case diagram.

Permissions are stored per role in ``roles.permissions`` (JSONB) rather than
hardcoded against role names, so an administrator can adjust them without a
deployment. The constants here are the vocabulary and the seed.

One rule is not adjustable: no role is granted both ``approvals:decide`` and the
ability to create the actions it would approve, because a human gate that one
account can open on both sides is not a gate. That is asserted in the tests.
"""

from __future__ import annotations

from typing import Final

# --- the vocabulary --------------------------------------------------------

ALERTS_READ: Final = "alerts:read"
ALERTS_TRIAGE: Final = "alerts:triage"
DETECTIONS_READ: Final = "detections:read"
APPROVALS_DECIDE: Final = "approvals:decide"
RESPONSE_PROPOSE: Final = "response:propose"
SENSORS_MANAGE: Final = "sensors:manage"
MODELS_READ: Final = "models:read"
MODELS_DEPLOY: Final = "models:deploy"
USERS_MANAGE: Final = "users:manage"
AUDIT_READ: Final = "audit:read"

ALL_PERMISSIONS: Final[frozenset[str]] = frozenset(
    {
        ALERTS_READ,
        ALERTS_TRIAGE,
        DETECTIONS_READ,
        APPROVALS_DECIDE,
        RESPONSE_PROPOSE,
        SENSORS_MANAGE,
        MODELS_READ,
        MODELS_DEPLOY,
        USERS_MANAGE,
        AUDIT_READ,
    }
)

# --- the roles -------------------------------------------------------------

SOC_ANALYST: Final = "soc_analyst"
ADMINISTRATOR: Final = "administrator"
ML_ENGINEER: Final = "ml_engineer"

#: Seed permissions per role, straight from the M2 use cases.
DEFAULT_ROLE_PERMISSIONS: Final[dict[str, frozenset[str]]] = {
    # Monitors alerts, reads explanations, decides on responses.
    SOC_ANALYST: frozenset(
        {ALERTS_READ, ALERTS_TRIAGE, DETECTIONS_READ, APPROVALS_DECIDE, MODELS_READ}
    ),
    # Manages sensors, thresholds and accounts, and reads the audit trail.
    # Notably not APPROVALS_DECIDE: administering the system and authorising action
    # on the network are different jobs.
    ADMINISTRATOR: frozenset(
        {
            ALERTS_READ,
            DETECTIONS_READ,
            SENSORS_MANAGE,
            USERS_MANAGE,
            AUDIT_READ,
            MODELS_READ,
            RESPONSE_PROPOSE,
        }
    ),
    # Registers models and promotes them out of shadow mode.
    ML_ENGINEER: frozenset({MODELS_READ, MODELS_DEPLOY, DETECTIONS_READ, ALERTS_READ}),
}


def permissions_for(role_permissions: dict | None) -> frozenset[str]:
    """Read a role's permission set out of its JSONB column.

    Unknown strings are dropped rather than trusted: a typo in the database should
    not silently become a permission nobody checks.
    """
    if not role_permissions:
        return frozenset()
    granted = role_permissions.get("granted", [])
    if not isinstance(granted, list):
        return frozenset()
    return frozenset(p for p in granted if p in ALL_PERMISSIONS)


def as_column(permissions: frozenset[str] | set[str]) -> dict:
    """Render a permission set for storage in ``roles.permissions``."""
    unknown = set(permissions) - ALL_PERMISSIONS
    if unknown:
        raise ValueError(f"unknown permissions: {sorted(unknown)}")
    return {"granted": sorted(permissions)}
