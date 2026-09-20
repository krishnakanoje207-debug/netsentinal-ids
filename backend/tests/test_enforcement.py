"""The enforcement points.

The bodies are tested, not the clients: what CrowdSec and Wazuh are asked to do is
the part that decides whether traffic stops, and it is the part that can be checked
without either of them running. The HTTP around it is a handful of lines whose only
honest test needs a real instance.
"""

from __future__ import annotations

import pytest

from netsentinel_api.config import Settings
from netsentinel_api.db.models import ActionType, ResponseAction
from netsentinel_api.services.enforcement import (
    DEFAULT_BAN_DURATION,
    ORIGIN,
    UNDO_COMMANDS,
    WAZUH_COMMANDS,
    CrowdSecEnforcer,
    EnforcementError,
    WazuhEnforcer,
    active_response_body,
    ban_request,
    ban_target,
    can_undo,
    enforcers_from,
    split_target,
)

SECRET = "K7vQp2xR9mLt4wZn6bYc3sEdJf8hGa1uNqXrVoWiTyBk5Pz0"


def _action(**overrides) -> ResponseAction:
    fields = {
        "action_id": 500,
        "alert_id": 100,
        "action_type": ActionType.block_ip,
        "target": "203.0.113.9",
    }
    fields.update(overrides)
    return ResponseAction(**fields)


# --- the ban CrowdSec is asked for -----------------------------------------

def test_the_decision_bans_the_action_target():
    decision = ban_request(_action())["decisions"][0]
    assert decision["value"] == "203.0.113.9"
    assert decision["scope"] == "Ip"
    assert decision["type"] == "ban"


def test_the_ban_expires():
    """An expiring decision fails open; a permanent one is a hole nobody remembers."""
    assert ban_request(_action())["decisions"][0]["duration"] == DEFAULT_BAN_DURATION
    assert ban_request(_action(), "30m")["decisions"][0]["duration"] == "30m"


def test_the_ban_is_attributable():
    body = ban_request(_action())
    assert body["decisions"][0]["origin"] == ORIGIN
    # The action id travels with the ban, so CrowdSec alone can answer who
    # authorised it.
    assert body["labels"]["netsentinel_action_id"] == "500"
    assert "alert 100" in body["message"]


def test_the_source_matches_the_decision():
    """CrowdSec scopes the alert as well as the decision; disagreement is a bug."""
    body = ban_request(_action())
    assert body["source"] == {"scope": "Ip", "value": "203.0.113.9"}


def test_an_ipv6_target_is_accepted():
    assert ban_target(_action(target="2001:db8::5")) == "2001:db8::5"


@pytest.mark.parametrize("target", ["attacker.example.test", "203.0.113.999", "", "10.0.0.0/8"])
def test_a_target_that_is_not_an_address_is_refused(target):
    """A literal CrowdSec cannot match looks exactly like a block that worked."""
    with pytest.raises(EnforcementError, match="not an IP address"):
        ban_target(_action(target=target))


def test_a_padded_target_is_still_banned():
    assert ban_target(_action(target=" 203.0.113.9 ")) == "203.0.113.9"


# --- the command Wazuh is asked to run -------------------------------------

def test_isolating_a_host_needs_only_the_agent():
    assert split_target(_action(action_type=ActionType.isolate_host, target="001")) == (
        "001",
        None,
    )


@pytest.mark.parametrize(
    ("action_type", "target", "expected"),
    [
        (ActionType.kill_process, "001:4172", ("001", "4172")),
        (ActionType.disable_account, "003:svc-backup", ("003", "svc-backup")),
    ],
)
def test_a_host_action_carries_what_it_acts_on(action_type, target, expected):
    assert split_target(_action(action_type=action_type, target=target)) == expected


def test_an_action_inside_a_host_must_name_its_subject():
    with pytest.raises(EnforcementError, match="names no process or account"):
        split_target(_action(action_type=ActionType.kill_process, target="001"))


def test_an_action_without_an_agent_is_refused():
    with pytest.raises(EnforcementError, match="names no Wazuh agent"):
        split_target(_action(action_type=ActionType.isolate_host, target=""))


def test_the_command_body_carries_the_argument_and_the_ids():
    body = active_response_body(
        _action(action_type=ActionType.disable_account, target="003:svc-backup"),
        WAZUH_COMMANDS[ActionType.disable_account],
        "svc-backup",
    )
    assert body["command"] == "!disable-account"
    assert body["arguments"] == ["svc-backup"]
    assert body["alert"]["data"]["netsentinel_action_id"] == "500"


def test_isolation_sends_no_arguments():
    body = active_response_body(
        _action(action_type=ActionType.isolate_host, target="001"),
        WAZUH_COMMANDS[ActionType.isolate_host],
        None,
    )
    assert body["arguments"] == []


def test_every_host_action_type_has_a_command():
    """block_ip is the edge's job; everything else is the agent's."""
    assert set(WAZUH_COMMANDS) == set(ActionType) - {ActionType.block_ip}


# --- undoing ---------------------------------------------------------------

@pytest.mark.parametrize(
    ("action_type", "reversible"),
    [
        (ActionType.block_ip, True),
        (ActionType.isolate_host, True),
        (ActionType.disable_account, True),
        (ActionType.kill_process, False),
    ],
)
def test_only_what_can_be_put_back_can_be_undone(action_type, reversible):
    """A killed process is gone; the other three are states, and states revert."""
    assert can_undo(action_type) is reversible


def test_killing_a_process_has_no_undo_command():
    assert ActionType.kill_process not in UNDO_COMMANDS


def test_the_undo_command_is_not_the_command_it_undoes():
    """Re-running the original would extend the very action being lifted."""
    for action_type, command in UNDO_COMMANDS.items():
        assert command != WAZUH_COMMANDS[action_type]


def test_undoing_an_isolation_sends_the_unisolate_command():
    body = active_response_body(
        _action(action_type=ActionType.isolate_host, target="001"),
        UNDO_COMMANDS[ActionType.isolate_host],
        None,
    )
    assert body["command"] == "!netsentinel-unisolate"
    assert body["arguments"] == []


def test_undoing_a_disabled_account_names_the_account():
    body = active_response_body(
        _action(action_type=ActionType.disable_account, target="003:svc-backup"),
        UNDO_COMMANDS[ActionType.disable_account],
        "svc-backup",
    )
    assert body["command"] == "!netsentinel-enable-account"
    assert body["arguments"] == ["svc-backup"]


def test_wazuh_refuses_to_undo_an_action_type_with_no_undo():
    """Refused before the client is built, so nothing is sent to the agent."""
    wazuh = WazuhEnforcer("https://localhost:55000", "wazuh-wui", "a-wazuh-password")
    with pytest.raises(EnforcementError, match="cannot be undone"):
        wazuh.undo(_action(action_type=ActionType.kill_process, target="001:4172"))


# --- wiring ----------------------------------------------------------------

def _settings(**overrides) -> Settings:
    return Settings(jwt_secret=SECRET, **overrides)


def test_nothing_configured_enforces_nothing():
    """A valid state: approvals are collected, nothing on the network changes."""
    assert enforcers_from(_settings()) == {}


def test_crowdsec_serves_block_ip_alone():
    points = enforcers_from(
        _settings(
            crowdsec_url="http://localhost:8080",
            crowdsec_machine_id="netsentinel",
            crowdsec_password="a-machine-password",
        )
    )
    assert set(points) == {ActionType.block_ip}
    assert isinstance(points[ActionType.block_ip], CrowdSecEnforcer)


def test_wazuh_serves_the_host_actions():
    points = enforcers_from(
        _settings(
            wazuh_url="https://localhost:55000",
            wazuh_user="wazuh-wui",
            wazuh_password="a-wazuh-password",
        )
    )
    assert set(points) == set(WAZUH_COMMANDS)
    assert all(isinstance(p, WazuhEnforcer) for p in points.values())


def test_half_configured_crowdsec_is_not_wired():
    """A URL without credentials would fail at the first login, in an incident."""
    assert enforcers_from(_settings(crowdsec_url="http://localhost:8080")) == {}
