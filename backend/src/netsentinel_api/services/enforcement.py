"""The enforcement points: where an approved action meets the network.

Nothing here decides anything. This module translates a ``ResponseAction`` that a
human already approved into the request CrowdSec or Wazuh expects, and reports
whether that request was accepted. The decision stayed in ``services.response``,
and the only caller is the responder worker, which passes the gate first - so an
unapproved action never reaches a client in this file.

Two backends, because they enforce in different places:

* **CrowdSec** owns the network edge. A decision posted to its Local API is read by
  the firewall bouncer on the VM, which writes the nftables set. That is why this
  talks to the LAPI rather than shelling out to ``nft``: the bouncer already owns
  those rules, and a second writer would fight it.
* **Wazuh Active Response** owns the host. Isolating a machine, killing a process or
  disabling an account happens on the endpoint, through an agent already installed
  there.

Both raise ``EnforcementError`` and nothing else. The worker has to distinguish "the
network changed" from "it did not"; which client library raised what is not a
distinction it should have to know about.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone

from netsentinel_api.config import Settings
from netsentinel_api.db.models import ActionType, ResponseAction

logger = logging.getLogger("netsentinel.enforcement")

REQUEST_TIMEOUT_SECONDS = 15.0

#: How long a ban lasts unless configured otherwise. Bounded on purpose: an expiring
#: decision fails open, so a mistaken block costs four hours rather than leaving a
#: permanent hole in the lab that nobody remembers punching.
DEFAULT_BAN_DURATION = "4h"

#: CrowdSec attributes every decision to an origin, and its own scenarios are
#: namespaced this way. A ban from here is then visible as ours in
#: ``cscli decisions list``, which is what someone asks when working out why an
#: address is blocked.
ORIGIN = "netsentinel"

#: The Active Response commands this system invokes, per action type. The ``!``
#: prefix tells the agent to run ``active-response/bin/<name>`` directly, with no
#: command declared in the manager's configuration, so the file name is the contract.
#: ``disable-account`` ships with Wazuh; the other two are scripts deployed with the
#: agent (``sensors/wazuh/active-response/netsentinel-ar``), because Wazuh has no
#: stock command for either.
WAZUH_COMMANDS: dict[ActionType, str] = {
    ActionType.isolate_host: "!netsentinel-isolate",
    ActionType.kill_process: "!netsentinel-kill-process",
    ActionType.disable_account: "!disable-account",
}

#: The Active Response commands that put back what ``WAZUH_COMMANDS`` took away.
#: ``kill_process`` has no entry and never will: a killed process cannot be
#: un-killed, and listing a command here that quietly does nothing would let an
#: analyst believe a rollback restored something.
UNDO_COMMANDS: dict[ActionType, str] = {
    ActionType.isolate_host: "!netsentinel-unisolate",
    ActionType.disable_account: "!netsentinel-enable-account",
}


class EnforcementError(Exception):
    """The enforcement point refused, or could not be reached."""


def can_undo(action_type: ActionType) -> bool:
    """Whether this system can reverse an action of this type.

    Covers both backends, because the question is asked at the API - before an
    analyst is allowed to request a rollback - and the route should not have to
    know which backend serves which type. A ban is a decision CrowdSec can delete;
    isolation and a disabled account have undo commands; a killed process has
    nothing to restore.
    """
    return action_type is ActionType.block_ip or action_type in UNDO_COMMANDS


# --- request bodies, kept out of the clients so they can be tested ---------

def ban_target(action: ResponseAction) -> str:
    """The address to ban, refusing anything that is not one.

    A hostname or a typo reaching CrowdSec is either rejected with a message no
    analyst will ever read or, worse, stored as a literal value that matches no
    traffic and looks exactly like a block that worked.
    """
    target = (action.target or "").strip()
    try:
        ipaddress.ip_address(target)
    except ValueError as exc:
        raise EnforcementError(
            f"action {action.action_id} targets {target!r}, which is not an IP address"
        ) from exc
    return target


def ban_request(action: ResponseAction, duration: str = DEFAULT_BAN_DURATION) -> dict:
    """The alert-with-decision body the LAPI accepts.

    CrowdSec has no "add this decision" endpoint; decisions arrive attached to an
    alert, which is also how the ban carries its reason into ``cscli``.
    """
    value = ban_target(action)
    now = _rfc3339(datetime.now(timezone.utc))
    scenario = f"{ORIGIN}/{action.action_type.value}"
    return {
        "scenario": scenario,
        "scenario_hash": "",
        "scenario_version": "",
        "message": (
            f"alert {action.alert_id} approved for {action.action_type.value}: "
            f"ban {value} for {duration}"
        ),
        # One approved action is one event, however many flows led to the alert.
        "events_count": 1,
        "events": [],
        "start_at": now,
        "stop_at": now,
        "capacity": 0,
        "leakspeed": "0",
        "simulated": False,
        "remediation": True,
        "source": {"scope": "Ip", "value": value},
        "decisions": [
            {
                "duration": duration,
                "origin": ORIGIN,
                "scenario": scenario,
                "scope": "Ip",
                "type": "ban",
                "value": value,
            }
        ],
        # An approval is the authority for this ban, so the action id travels with
        # it: "who blocked this address" is then answerable from CrowdSec alone.
        "labels": {"netsentinel_action_id": str(action.action_id)},
    }


def split_target(action: ResponseAction) -> tuple[str, str | None]:
    """Split a host action's target into the agent and what the command acts on.

    ``isolate_host`` acts on the machine itself, so its target is the Wazuh agent id
    alone. ``kill_process`` and ``disable_account`` act on something inside it, so
    they carry ``<agent>:<pid|username>``. One column has to say both, and splitting
    on a colon beats a second column that is null for most rows.
    """
    agent, _, argument = (action.target or "").strip().partition(":")
    if not agent:
        raise EnforcementError(
            f"action {action.action_id} names no Wazuh agent in target "
            f"{action.target!r}"
        )
    if action.action_type is not ActionType.isolate_host and not argument:
        raise EnforcementError(
            f"action {action.action_id} is {action.action_type.value} but its target "
            f"{action.target!r} names no process or account"
        )
    return agent, argument or None


def active_response_body(action: ResponseAction, command: str,
                         argument: str | None) -> dict:
    """The body of a PUT /active-response call."""
    # The AR script reads its context from the alert object. Carrying our two
    # ids means the script's own log line leads back to the approval.
    data = {
        "netsentinel_action_id": str(action.action_id),
        "netsentinel_alert_id": str(action.alert_id),
    }
    # Wazuh's stock disable-account ignores arguments and takes the user from
    # alert.data.dstuser, as if the alert had named it. Our enable-account reads
    # arguments, so the name goes in both.
    if action.action_type is ActionType.disable_account and argument:
        data["dstuser"] = argument
    return {
        "command": command,
        "arguments": [argument] if argument else [],
        "alert": {"data": data},
    }


def _rfc3339(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


# --- clients ---------------------------------------------------------------

class CrowdSecEnforcer:
    """Posts a ban decision to the CrowdSec Local API.

    Registered as a watcher, not a bouncer: bouncers read decisions, watchers write
    them, and writing is what this does. The credentials are the pair
    ``cscli machines add`` prints.
    """

    def __init__(
        self,
        url: str,
        machine_id: str,
        password: str,
        ban_duration: str = DEFAULT_BAN_DURATION,
        verify_tls: bool = True,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._url = url.rstrip("/")
        self._machine_id = machine_id
        self._password = password
        self._ban_duration = ban_duration
        self._verify_tls = verify_tls
        self._timeout = timeout

    def apply(self, action: ResponseAction) -> dict:
        """Ban the action's target. Returns what CrowdSec recorded."""
        import httpx

        # Built before the connection: a target that is not an address is our bug,
        # and finding it out after a round trip only makes the message worse.
        body = ban_request(action, self._ban_duration)

        with httpx.Client(timeout=self._timeout, verify=self._verify_tls) as client:
            token = self._login(client)
            try:
                response = client.post(
                    f"{self._url}/v1/alerts",
                    headers={"Authorization": f"Bearer {token}"},
                    json=[body],
                )
                response.raise_for_status()
                created = response.json()
            except httpx.HTTPError as exc:
                raise EnforcementError(f"CrowdSec refused the decision: {exc}") from exc
            except ValueError as exc:
                raise EnforcementError(
                    f"CrowdSec returned a body that is not JSON: {exc}"
                ) from exc

        return {
            "backend": "crowdsec",
            "target": body["source"]["value"],
            "duration": self._ban_duration,
            "alert_ids": created,
        }

    def undo(self, action: ResponseAction) -> dict:
        """Lift the ban on the action's target. Returns what was deleted."""
        import httpx

        value = ban_target(action)

        with httpx.Client(timeout=self._timeout, verify=self._verify_tls) as client:
            token = self._login(client)
            try:
                response = client.delete(
                    f"{self._url}/v1/decisions",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"scope": "Ip", "value": value},
                )
                response.raise_for_status()
                deleted = response.json()
            except httpx.HTTPError as exc:
                raise EnforcementError(
                    f"CrowdSec refused to lift the ban on {value}: {exc}"
                ) from exc
            except ValueError as exc:
                raise EnforcementError(
                    f"CrowdSec returned a body that is not JSON: {exc}"
                ) from exc

        # A delete that matched nothing is a success, not a failure. Decisions
        # expire, so the ban may well have lapsed between the approval and this
        # call - and "no ban in place" is precisely the state the caller asked for.
        # Treating an empty result as an error would leave the action stuck in the
        # undo queue forever, retrying a deletion that has nothing left to delete.
        return {"backend": "crowdsec", "target": value, "deleted": deleted}

    def _login(self, client) -> str:
        """A fresh token per action.

        A LAPI token lives about an hour and this worker runs for days. Caching one
        means handling its expiry in the middle of an incident, which is more code
        than one extra request per approved action - and approved actions are rare
        by design.
        """
        import httpx

        try:
            response = client.post(
                f"{self._url}/v1/watchers/login",
                json={"machine_id": self._machine_id, "password": self._password},
            )
            response.raise_for_status()
            token = response.json().get("token")
        except httpx.HTTPError as exc:
            raise EnforcementError(f"CrowdSec login failed: {exc}") from exc
        except ValueError as exc:
            raise EnforcementError(f"CrowdSec login returned no JSON: {exc}") from exc

        if not token:
            raise EnforcementError("CrowdSec login returned no token")
        return token


class WazuhEnforcer:
    """Runs an Active Response command on the agent the action names."""

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        verify_tls: bool = True,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._url = url.rstrip("/")
        self._user = user
        self._password = password
        self._verify_tls = verify_tls
        self._timeout = timeout

    def apply(self, action: ResponseAction) -> dict:
        return self._run(action, WAZUH_COMMANDS[action.action_type])

    def undo(self, action: ResponseAction) -> dict:
        command = UNDO_COMMANDS.get(action.action_type)
        if command is None:
            raise EnforcementError(
                f"action {action.action_id} is {action.action_type.value}, which "
                "cannot be undone"
            )
        return self._run(action, command)

    def _run(self, action: ResponseAction, command: str) -> dict:
        """Send one Active Response command. Applying and undoing differ only here."""
        import httpx

        agent, argument = split_target(action)
        body = active_response_body(action, command, argument)

        with httpx.Client(timeout=self._timeout, verify=self._verify_tls) as client:
            token = self._authenticate(client)
            try:
                response = client.put(
                    f"{self._url}/active-response",
                    params={"agents_list": agent},
                    headers={"Authorization": f"Bearer {token}"},
                    json=body,
                )
                response.raise_for_status()
                payload = response.json()
            except httpx.HTTPError as exc:
                raise EnforcementError(
                    f"Wazuh refused {command} on agent {agent}: {exc}"
                ) from exc
            except ValueError as exc:
                raise EnforcementError(
                    f"Wazuh returned a body that is not JSON: {exc}"
                ) from exc

        # Wazuh answers 200 with a per-agent result, so a command that reached no
        # agent is a success at the HTTP level and a failure in fact. Believing the
        # status code here would mark an unisolated host isolated.
        failed = (payload.get("data") or {}).get("failed_items") or []
        if failed:
            raise EnforcementError(
                f"Wazuh could not run {command} on agent {agent}: {failed}"
            )

        return {"backend": "wazuh", "agent": agent, "command": command}

    def _authenticate(self, client) -> str:
        import httpx

        try:
            response = client.post(
                f"{self._url}/security/user/authenticate",
                auth=(self._user, self._password),
            )
            response.raise_for_status()
            token = (response.json().get("data") or {}).get("token")
        except httpx.HTTPError as exc:
            raise EnforcementError(f"Wazuh authentication failed: {exc}") from exc
        except ValueError as exc:
            raise EnforcementError(
                f"Wazuh authentication returned no JSON: {exc}"
            ) from exc

        if not token:
            raise EnforcementError("Wazuh authentication returned no token")
        return token


# --- wiring ----------------------------------------------------------------

def enforcers_from(settings: Settings) -> dict[ActionType, object]:
    """The enforcement points this deployment has, by the action type each serves.

    An empty mapping is a legitimate state: with neither CrowdSec nor Wazuh
    configured the system still detects, explains, alerts and collects approvals -
    it simply cannot carry them out. The worker leaves such actions approved rather
    than failing them, so configuring the backend later executes them instead of
    sending the analyst back to approve a second time.
    """
    points: dict[ActionType, object] = {}

    if settings.crowdsec_url and settings.crowdsec_machine_id and settings.crowdsec_password:
        points[ActionType.block_ip] = CrowdSecEnforcer(
            settings.crowdsec_url,
            settings.crowdsec_machine_id,
            settings.crowdsec_password.get_secret_value(),
            ban_duration=settings.crowdsec_ban_duration,
            verify_tls=settings.crowdsec_verify_tls,
        )

    if settings.wazuh_url and settings.wazuh_user and settings.wazuh_password:
        wazuh = WazuhEnforcer(
            settings.wazuh_url,
            settings.wazuh_user,
            settings.wazuh_password.get_secret_value(),
            verify_tls=settings.wazuh_verify_tls,
        )
        for action_type in WAZUH_COMMANDS:
            points[action_type] = wazuh

    return points
