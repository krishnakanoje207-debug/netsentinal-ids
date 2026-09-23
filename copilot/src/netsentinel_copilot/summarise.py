"""One alert, summarised and stored.

The evidence handed to the model is assembled here, and what comes back is checked
here. Both halves are deliberately free of HTTP and of the database: this module
takes an alert and a client and returns a row to add, which is what makes the
injection tests in this package possible without an LLM or a PostgreSQL.

What the model is given is exactly what an analyst can already see on the alert
detail page. Nothing about other alerts, nothing about the estate, no credentials
and no history - a summary that can only restate the page it sits next to is a
summary whose worst failure is being unhelpful.
"""

from __future__ import annotations

import logging
from typing import Iterable

from netsentinel_api.db.models import Alert, CopilotSummary, Detection, IoC
from pydantic import ValidationError

from netsentinel_copilot.sanitise import build_prompt
from netsentinel_copilot.schema import AlertSummary, json_schema, validate

logger = logging.getLogger("netsentinel.copilot")

#: How many contributing features go into the prompt, ranked by absolute
#: contribution. The model is asked to put them in a sentence, not to decide which
#: of them mattered.
TOP_FEATURE_COUNT = 5

#: Plain names for the contract features, the same words the dashboard uses. A 3B model
#: handed "l4_dst_port +8.012" writes "multiple contributing features"; handed
#: "destination port" it can write a sentence an analyst recognises. The raw name stays
#: beside it so the summary can be checked against the chart.
FEATURE_NAMES = {
    "proto": "protocol",
    "l4_src_port": "source port",
    "l4_dst_port": "destination port",
    "duration_ms": "connection length",
    "in_pkts": "packets sent",
    "out_pkts": "packets returned",
    "in_bytes": "data sent",
    "out_bytes": "data returned",
    "pkt_rate": "packets per second",
    "byte_rate": "data per second",
    "bytes_per_pkt_in": "size of sent packets",
    "bytes_per_pkt_out": "size of returned packets",
    "bytes_ratio_out_in": "reply-to-request ratio",
}


def evidence(alert: Alert, iocs: Iterable[IoC] = ()) -> dict[str, object]:
    """The facts about one alert, as fields for the data block.

    Every value here is scrubbed downstream, including the ones that look safe: a
    source or a technique is ours today and could be a string from a feed tomorrow.
    """
    detection: Detection | None = alert.detection
    fields: dict[str, object] = {
        "alert id": alert.alert_id,
        "detected by": alert.source,
        "severity": alert.severity.value if alert.severity else None,
        "source address": alert.src_ip,
        "destination address": alert.dst_ip,
        "MITRE technique": alert.mitre_technique,
    }

    if detection is not None:
        fields["risk score"] = f"{detection.risk_score:.0%}"
        contributions = {k: float(v) for k, v in (detection.shap_values or {}).items()}
        ranked = sorted(contributions, key=lambda k: abs(contributions[k]), reverse=True)
        # Direction and rank only, never the SHAP value itself. Given "+8.67" a small
        # model reported packets "8.67 times larger than average" - a measurement
        # nobody took, stated as fact. An influence weight has no unit to misread if
        # it is not in the prompt.
        fields["top contributing features, strongest first"] = "; ".join(
            f"{FEATURE_NAMES.get(name, name)} ({name}) pushed toward "
            f"{'attack' if contributions[name] > 0 else 'normal traffic'}"
            for name in ranked[:TOP_FEATURE_COUNT]
        )

    matched = [str(ioc.value) for ioc in iocs]
    if matched:
        # The most attacker-controlled field in the prompt: an indicator value is a
        # string somebody else chose, arriving from a feed.
        fields["matched threat indicators"] = ", ".join(matched)

    return fields


def summarise(client, alert: Alert, iocs: Iterable[IoC] = ()) -> tuple[dict, AlertSummary | None]:
    """Ask for a summary of this alert. Returns (what came back, what validated).

    A rejected reply is returned rather than raised, because it is still a row: a
    pattern of invalid output says something about the model, the prompt, or
    somebody feeding the sensor sentences addressed to it.
    """
    system, user = build_prompt(evidence(alert, iocs))

    # CopilotError propagates: unreachable is not invalid. There is nothing to store
    # and nothing to show, and whether that is worth retrying is the caller's call.
    payload = client.complete(system, user, json_schema())

    try:
        return payload, validate(payload)
    except ValidationError as exc:
        logger.warning("the model returned output that is not a summary: %s", exc)
        return payload, None


def as_row(alert: Alert, payload: dict, summary: AlertSummary | None,
           model_name: str) -> CopilotSummary:
    """The ``copilot_summaries`` row for one attempt, valid or not.

    ``schema_valid`` is the flag the dashboard filters on: an invalid summary is
    kept as evidence and never rendered as though a model had explained anything.
    """
    return CopilotSummary(
        alert_id=alert.alert_id,
        summary_json=summary.as_row if summary is not None else {"rejected": payload},
        llm_model=model_name,
        schema_valid=summary is not None,
    )
