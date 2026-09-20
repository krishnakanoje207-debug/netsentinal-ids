"""Role and permission rules, including the separation of duties the design needs."""

from __future__ import annotations

import pytest

from netsentinel_api.rbac import (
    ADMINISTRATOR,
    ALERTS_READ,
    ALL_PERMISSIONS,
    APPROVALS_DECIDE,
    DEFAULT_ROLE_PERMISSIONS,
    ML_ENGINEER,
    MODELS_DEPLOY,
    RESPONSE_PROPOSE,
    SOC_ANALYST,
    as_column,
    permissions_for,
)


def test_every_seeded_permission_is_in_the_vocabulary():
    for role, granted in DEFAULT_ROLE_PERMISSIONS.items():
        unknown = granted - ALL_PERMISSIONS
        assert not unknown, f"{role} is granted unknown permissions {unknown}"


def test_no_role_can_both_propose_and_approve_a_response():
    """A gate one account can open from both sides is not a gate."""
    for role, granted in DEFAULT_ROLE_PERMISSIONS.items():
        assert not (APPROVALS_DECIDE in granted and RESPONSE_PROPOSE in granted), (
            f"{role} could raise an action and approve its own action"
        )


def test_only_the_ml_engineer_can_promote_a_model():
    """Moving a model out of shadow mode is not an analyst's call."""
    holders = [r for r, g in DEFAULT_ROLE_PERMISSIONS.items() if MODELS_DEPLOY in g]
    assert holders == [ML_ENGINEER]


def test_only_the_analyst_decides_on_responses():
    holders = [r for r, g in DEFAULT_ROLE_PERMISSIONS.items() if APPROVALS_DECIDE in g]
    assert holders == [SOC_ANALYST]


def test_every_role_can_at_least_read_alerts():
    for role, granted in DEFAULT_ROLE_PERMISSIONS.items():
        assert ALERTS_READ in granted, f"{role} cannot see anything"


def test_administrator_cannot_authorise_network_changes():
    assert APPROVALS_DECIDE not in DEFAULT_ROLE_PERMISSIONS[ADMINISTRATOR]


# --- reading and writing the JSONB column ---------------------------------

def test_round_trip_through_the_column():
    granted = DEFAULT_ROLE_PERMISSIONS[SOC_ANALYST]
    assert permissions_for(as_column(granted)) == granted


def test_unknown_permission_in_the_database_is_dropped():
    """A typo must not become a permission nobody checks."""
    assert permissions_for({"granted": [ALERTS_READ, "alerts:reed"]}) == {ALERTS_READ}


def test_storing_an_unknown_permission_is_refused():
    with pytest.raises(ValueError, match="unknown permissions"):
        as_column({"alerts:reed"})


@pytest.mark.parametrize("value", [None, {}, {"granted": None}, {"granted": "all"}, {"other": []}])
def test_malformed_permission_columns_grant_nothing(value):
    """Failure closed: a broken row means no access, never full access."""
    assert permissions_for(value) == frozenset()
