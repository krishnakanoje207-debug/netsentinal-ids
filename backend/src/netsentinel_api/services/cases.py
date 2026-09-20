"""Opening a DFIR-IRIS case when an analyst escalates an alert.

Escalation is the point where a finding stops being a row in a feed and becomes work
somebody owns. IRIS is where that work happens - timeline, notes, tasks, evidence -
and this module is the one place that knows how to ask it for a case.

Two decisions shape what is written here.

**The case opens with the evidence, not a reference.** The description carries the
addresses, the technique, the matched indicators and, when the alert came from the
model, its risk score and strongest SHAP contributors. An analyst who has to go back
to the dashboard to learn why anything was escalated will read a case containing one
alert id and close it again, so the argument travels with the case.

**Opening a case is best effort, exactly as forwarding to Keep is.** The incident row
in this system's own database is the record; the IRIS case is where humans work it.
That is why ``create_case`` raises rather than deciding anything: the caller has
already written the incident by the time this is called, and it catches ``CaseError``
and carries on with ``iris_case_id`` unset.

The API shape is verified rather than assumed. Against iris-web v2.4.29 - the release
the project's research pinned - a case is created with ``POST /manage/cases/add``,
authenticated with ``Authorization: Bearer <api key>``. Its marshmallow schema
requires ``case_name``, ``case_description``, ``case_soc_id`` and ``case_customer``
(an integer customer id), and the reply is ``{"status": "success", "data": {"case_id":
<int>, ...}}``. The ``/api/v2/cases`` scheme discussed upstream is not in 2.4.29, so it
is deliberately not used here.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Iterable

from netsentinel_api.config import Settings
from netsentinel_api.db.models import (
    ActionStatus,
    Alert,
    Detection,
    IoC,
    ResponseAction,
)

logger = logging.getLogger("netsentinel.cases")

REQUEST_TIMEOUT_SECONDS = 15.0

#: How many contributing features the description carries. Five is enough to show
#: what drove the score; the full vector is on the alert detail page.
TOP_FEATURE_COUNT = 5

#: IRIS keeps a free-text reference on every case for the system it came from. Ours
#: is the alert id, so "which alert is this case" is answerable from IRIS alone.
SOC_ID_PREFIX = "netsentinel-alert-"

#: IRIS seeds fifteen event categories in a fixed order and 3 is "Remediation",
#: which is what a block being applied or lifted is. Unspecified (1) would leave
#: every response entry uncategorised in the case's own filters.
REMEDIATION_CATEGORY = 3

#: The format IRIS parses ``event_date`` with. It carries no offset - the zone is a
#: separate field - so the timestamp is converted to UTC before it is written and
#: ``event_tz`` says so.
EVENT_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

#: What a response action reaching the enforcement point is called in the timeline,
#: by the state it has just arrived in.
RESPONSE_VERBS: dict[ActionStatus, str] = {
    ActionStatus.executed: "applied",
    ActionStatus.rolled_back: "lifted",
}


class CaseError(RuntimeError):
    """The case could not be opened."""


# --- what the case says, kept out of the client so it can be tested ---------

def case_title(alert: Alert) -> str:
    """The one line an analyst reads in the IRIS case list.

    Severity and technique first because that is what the list is scanned for; the
    alert id last because it is looked up rather than read.
    """
    technique = f" {alert.mitre_technique}" if alert.mitre_technique else ""
    return (
        f"{alert.severity.value} {alert.source}{technique}: "
        f"{alert.src_ip or '?'} -> {alert.dst_ip or '?'} (alert {alert.alert_id})"
    )


def case_description(
    alert: Alert,
    iocs: Iterable[IoC] = (),
    summary: str | None = None,
) -> str:
    """The case body: why this was escalated, and what is known.

    The analyst's own summary goes first when there is one - it is the reason the
    case exists, and the facts below it are available to anyone who asks the API.
    Lines with nothing to say are left out rather than printed empty, because a
    field reading "MITRE technique: None" is worse than its absence.
    """
    lines: list[str] = []
    if summary and summary.strip():
        lines += [summary.strip(), ""]

    lines.append(f"Escalated from NetSentinel alert {alert.alert_id}.")
    lines.append("")
    lines.append(f"Source: {alert.source}")
    lines.append(f"Severity: {alert.severity.value}")
    if alert.src_ip or alert.dst_ip:
        lines.append(f"Traffic: {alert.src_ip or '?'} -> {alert.dst_ip or '?'}")
    if alert.mitre_technique:
        lines.append(f"MITRE technique: {alert.mitre_technique}")

    matched = [str(ioc.value) for ioc in iocs]
    if matched:
        lines.append(f"Matched indicators: {', '.join(matched)}")

    return "\n".join(lines + _evidence(alert.detection))


def _evidence(detection: Detection | None) -> list[str]:
    """The model's reasoning, or nothing when no model was involved.

    Signature and host alerts reach this system from Suricata and Wazuh with no
    detection behind them, so the absence is normal rather than an error.
    Contributors are ranked by absolute value and printed with their sign: a
    strongly negative contribution is still part of why the flow scored as it did.
    """
    if detection is None:
        return []

    contributions = {k: float(v) for k, v in (detection.shap_values or {}).items()}
    ranked = sorted(contributions, key=lambda k: abs(contributions[k]), reverse=True)

    lines = ["", f"Risk score: {detection.risk_score:.2f}"]
    if ranked:
        top = ", ".join(
            f"{name} {contributions[name]:+.3f}" for name in ranked[:TOP_FEATURE_COUNT]
        )
        lines.append(f"Top contributing features: {top}")
    return lines


def response_event(action: ResponseAction, when: datetime | None = None) -> dict:
    """A timeline entry for a response action that reached the enforcement point.

    The entry is written from the state the action has just arrived in rather than
    from a caller's argument, so the timeline cannot disagree with the row: an
    action is described as lifted because it is ``rolled_back``, not because the
    worker believed it had lifted it.

    Only those two states produce an entry. An action that failed or is waiting has
    changed nothing on the network, and a case timeline is a record of what happened
    to the estate, not of what this system attempted.
    """
    verb = RESPONSE_VERBS.get(action.status)
    if verb is None:
        raise CaseError(
            f"action {action.action_id} is {action.status.value}; nothing reached "
            "the network, so there is nothing to put on the timeline"
        )

    moment = (when or datetime.now(timezone.utc)).astimezone(timezone.utc)
    lines = [
        f"{action.action_type.value} on {action.target} was {verb} at the "
        "enforcement point.",
        "",
        f"NetSentinel alert: {action.alert_id}",
        f"NetSentinel action: {action.action_id}",
    ]
    if action.approval is not None:
        # The authority for the change, in the case where the argument about it
        # will happen.
        lines.append(f"Approved by user {action.approval.approver_id}")

    return {
        "event_title": f"Response {verb}: {action.action_type.value} {action.target}",
        "event_content": "\n".join(lines),
        "event_date": moment.strftime(EVENT_DATE_FORMAT),
        "event_tz": "+00:00",
        "event_category_id": REMEDIATION_CATEGORY,
        # Required by the schema and meaningless here: linking assets and IoCs is
        # the analyst's work inside the case, not ours.
        "event_assets": [],
        "event_iocs": [],
        # A containment action belongs in the summary an investigator reads first.
        "event_in_summary": True,
        "event_source": "NetSentinel",
    }


def case_body(alert: Alert, title: str, description: str, customer_id: int) -> dict:
    """The JSON ``POST /manage/cases/add`` accepts.

    All four fields are required by the IRIS case schema; ``case_customer`` is a
    customer id rather than a name, which is why the setting is an integer.
    """
    return {
        "case_name": title,
        "case_description": description,
        "case_customer": customer_id,
        "case_soc_id": f"{SOC_ID_PREFIX}{alert.alert_id}",
    }


# --- the client ------------------------------------------------------------

class IrisClient:
    """Opens cases through the DFIR-IRIS REST API.

    ``httpx`` is imported lazily for the same reason as in ``services.soar``: a
    deployment with no IRIS never constructs a client, and the tests exercise the
    bodies without one.
    """

    def __init__(
        self,
        url: str,
        api_key: str,
        customer_id: int,
        verify_tls: bool = True,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._url = url.rstrip("/")
        self._api_key = api_key
        self._customer_id = customer_id
        self._verify_tls = verify_tls
        self._timeout = timeout

    def create_case(self, alert: Alert, title: str, description: str) -> int:
        """Open a case for this alert and return the IRIS case id."""
        import httpx

        body = case_body(alert, title, description, self._customer_id)

        with httpx.Client(timeout=self._timeout, verify=self._verify_tls) as client:
            try:
                response = client.post(
                    f"{self._url}/manage/cases/add",
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json=body,
                )
                response.raise_for_status()
                payload = response.json()
            except httpx.HTTPError as exc:
                raise CaseError(f"IRIS refused the case: {exc}") from exc
            except ValueError as exc:
                raise CaseError(f"IRIS returned a body that is not JSON: {exc}") from exc

        # IRIS reports a refused case in the body, so the status code alone is not
        # the answer. Trusting it would store a case id that is not there.
        if payload.get("status") != "success":
            raise CaseError(f"IRIS did not open the case: {payload.get('message')}")

        case_id = (payload.get("data") or {}).get("case_id")
        if not isinstance(case_id, int):
            raise CaseError(f"IRIS opened a case with no usable id: {payload.get('data')}")
        return case_id

    def add_timeline_event(self, case_id: int, event: dict) -> None:
        """Write one entry onto a case's timeline.

        ``cid`` is a query parameter and it is not optional here, whatever IRIS
        thinks: asked without one it falls back to the caller's current case and
        then to case 1, so a missing id does not fail - it files the entry against
        somebody else's investigation.
        """
        import httpx

        if not isinstance(case_id, int):
            raise CaseError(f"refusing to write a timeline entry to case {case_id!r}")

        with httpx.Client(timeout=self._timeout, verify=self._verify_tls) as client:
            try:
                response = client.post(
                    f"{self._url}/case/timeline/events/add",
                    params={"cid": case_id},
                    headers={"Authorization": f"Bearer {self._api_key}"},
                    json=event,
                )
                response.raise_for_status()
                payload = response.json()
            except httpx.HTTPError as exc:
                raise CaseError(f"IRIS refused the timeline entry: {exc}") from exc
            except ValueError as exc:
                raise CaseError(f"IRIS returned a body that is not JSON: {exc}") from exc

        if payload.get("status") != "success":
            raise CaseError(
                f"IRIS did not record the timeline entry: {payload.get('message')}"
            )


def client_from(settings: Settings) -> IrisClient | None:
    """A client if IRIS is configured, otherwise nothing.

    Nothing is a valid answer. Escalation writes the incident either way, so an
    unconfigured IRIS costs the case, not the escalation.
    """
    if not settings.iris_url or not settings.iris_api_key:
        return None
    return IrisClient(
        settings.iris_url,
        settings.iris_api_key.get_secret_value(),
        customer_id=settings.iris_customer_id,
        verify_tls=settings.iris_verify_tls,
    )
