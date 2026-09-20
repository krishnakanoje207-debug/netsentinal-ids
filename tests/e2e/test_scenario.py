"""The chain, end to end: detected, explained, enriched, case, approved block.

This is the D13 exit criterion written as a test. Each of the five links is covered
on its own elsewhere; what nothing else covers is that they join up - that the alert
the writer raises is the one the analyst escalates, that the case the responder
narrates into is the one the escalation opened, and that the block that lands at the
enforcement point is the one somebody approved.

The scenarios are the ones the plan names: a port scan, an SSH brute force, a C2
channel and DNS exfiltration. They differ here only in the flow each one puts on the
wire, because to this pipeline that is what they are - four flows whose scores
cleared a threshold. What makes them different attacks is a question for the models,
and it is asked where the models are.
"""

from __future__ import annotations

import pytest
from netsentinel_api.db.models import (
    ActionStatus,
    ActionType,
    Alert,
    AlertIoC,
    AlertStatus,
    ApprovalDecision,
    Detection,
    Incident,
    IncidentStatus,
    ResponseAction,
)
from netsentinel_api.responder import execute_action, record_in_case, roll_back_action
from netsentinel_api.services.cases import case_description, case_title
from netsentinel_api.services.response import (
    mark_executed,
    propose,
    record_decision,
    request_rollback,
)

#: The scenarios D13 emulates, by the flow each one puts on the wire.
SCENARIOS = [
    ("scan", "203.0.113.9:44321-172.30.0.10:443-6"),
    ("brute force", "203.0.113.9:44322-172.30.0.10:22-6"),
    ("c2", "203.0.113.9:44323-172.30.0.10:443-6"),
    ("dns exfiltration", "203.0.113.9:44324-172.30.0.10:53-17"),
]


@pytest.mark.parametrize(("name", "flow_id"), SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_a_scenario_runs_from_the_wire_to_an_approved_block(
    name, flow_id, session, run_writer, keep, iris, enforcer,
    scenario, known_bad, analyst, administrator, estate, attacker,
):
    # --- detected --------------------------------------------------------
    run_writer([scenario(flow_id)], iocs=[known_bad])

    detection, = session.rows(Detection)
    alert, = session.rows(Alert)
    assert detection.flow_id == flow_id
    assert alert.detection_id == detection.detection_id
    assert alert.status is AlertStatus.new

    # --- explained -------------------------------------------------------
    # The column is NOT NULL and the writer refuses to invent one, so a stored
    # detection is an explained detection by construction.
    assert detection.shap_values

    # --- enriched --------------------------------------------------------
    links = session.rows(AlertIoC)
    assert [link.ioc_id for link in links] == [known_bad.ioc_id]
    # And forwarded, after the commit, with the match attached.
    forwarded_alert, forwarded_iocs = keep.sent[0]
    assert forwarded_alert is alert and forwarded_iocs == [known_bad]

    # --- case ------------------------------------------------------------
    # The relationship a real escalation reads through: AlertRepository.get
    # joinedloads it, and with no database nothing has populated it here.
    alert.detection = detection
    incident = Incident(
        title=case_title(alert), status=IncidentStatus.open, owner_id=analyst.user_id
    )
    session.add(incident)
    session.flush()
    alert.incident_id = incident.incident_id
    alert.status = AlertStatus.escalated
    incident.iris_case_id = iris.create_case(
        alert, incident.title, case_description(alert, [known_bad])
    )
    session.case_id = incident.iris_case_id

    assert iris.cases[0][0] == alert.alert_id
    # The case argues for itself: the indicator and the score are in its body.
    assert attacker in iris.cases[0][2]
    assert "Risk score" in iris.cases[0][2]

    # --- proposed by one person ------------------------------------------
    action = propose(
        session, alert, ActionType.block_ip, None, administrator,
        existing=alert.actions,
        protected=[asset.ip_address for asset in estate],
    )
    session.flush()
    assert action.target == attacker
    assert action.status is ActionStatus.pending_approval

    # --- approved by another ---------------------------------------------
    record_decision(session, action, analyst, ApprovalDecision.approved,
                    f"{name}: confirmed against the lab host")
    assert action.status is ActionStatus.approved

    # --- and only then, the block ----------------------------------------
    assert execute_action(session, action, enforcer) is True
    assert enforcer.applied == [("block_ip", attacker)]
    assert action.status is ActionStatus.executed

    record_in_case(session, action, iris)
    case_id, event = iris.timeline[0]
    assert case_id == incident.iris_case_id
    assert event["event_title"].startswith("Response applied:")

    # The whole chain, in the order it happened, attributable to whoever did it.
    assert session.audit_actions() == [
        "response.proposed",
        "response.approved",
        "response.executed",
    ]


def test_the_estate_is_never_the_target_of_its_own_block(
    session, run_writer, scenario, administrator, estate, attacker, victim,
):
    """The same chain, with the addresses the other way round.

    An alert about an internal host reaching out is real and common - and the
    obvious block, the source address, is a machine this system exists to protect.
    """
    from netsentinel_api.services.response import ProtectedTarget

    payload = scenario(f"{victim}:44321-{attacker}-6")
    payload["flow"]["src_ip"], payload["flow"]["dst_ip"] = victim, attacker
    run_writer([payload])
    alert, = session.rows(Alert)

    with pytest.raises(ProtectedTarget):
        propose(session, alert, ActionType.block_ip, None, administrator,
                protected=[asset.ip_address for asset in estate])

    # Nothing was queued for anybody to approve.
    assert session.rows(ResponseAction) == []


def test_a_block_can_be_lifted_again(
    session, run_writer, iris, enforcer, scenario, analyst, administrator, estate,
    attacker,
):
    """The other half of the gate: an approved block, undone the same way."""
    run_writer([scenario(SCENARIOS[0][1])])
    alert, = session.rows(Alert)
    session.case_id = 4242

    action = propose(session, alert, ActionType.block_ip, None, administrator,
                     protected=[asset.ip_address for asset in estate])
    session.flush()
    record_decision(session, action, analyst, ApprovalDecision.approved)
    execute_action(session, action, enforcer)

    request_rollback(session, action, analyst, "the address was a shared NAT gateway")
    assert action.status is ActionStatus.rollback_requested
    assert enforcer.undone == []  # asking is not doing

    assert roll_back_action(session, action, enforcer) is True
    assert enforcer.undone == [("block_ip", attacker)]
    assert action.status is ActionStatus.rolled_back

    record_in_case(session, action, iris)
    assert iris.timeline[-1][1]["event_title"].startswith("Response lifted:")


def test_nothing_reaches_the_network_without_the_human_in_the_middle(
    session, run_writer, enforcer, scenario, administrator, estate,
):
    """The chain with the approval removed, which is the whole point of it."""
    from netsentinel_api.services.response import ApprovalRequired

    run_writer([scenario(SCENARIOS[0][1])])
    alert, = session.rows(Alert)

    action = propose(session, alert, ActionType.block_ip, None, administrator,
                     protected=[asset.ip_address for asset in estate])
    session.flush()

    with pytest.raises(ApprovalRequired):
        mark_executed(session, action)
    with pytest.raises(ApprovalRequired):
        execute_action(session, action, enforcer)

    assert enforcer.applied == []
    assert action.status is ActionStatus.pending_approval


def test_an_ml_alert_carries_no_technique_yet(session, run_writer, scenario):
    """A gap this chain makes visible, recorded rather than worked around.

    Nothing in the ML path assigns a MITRE technique: the sensor publishes flow
    features, the writer stores a score, and neither has anything to map to ATT&CK
    with. Signature alerts from Suricata arrive with one; these do not.

    It matters in two places - the Keep fingerprint includes the technique, so it
    is empty for every ML alert, and the case description leaves the line out. Both
    degrade rather than break, which is why this is a test and not a fix: the fix
    is a mapping somebody has to design, not a field somebody forgot.
    """
    run_writer([scenario(SCENARIOS[0][1])])
    alert, = session.rows(Alert)
    assert alert.mitre_technique is None
