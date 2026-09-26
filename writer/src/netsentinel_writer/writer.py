"""Scored flows off the bus, explained detections into PostgreSQL.

This is the consumer the sensor was built to feed. It takes a flow's feature vector
and verdict from the topic, attributes the score to features with TreeSHAP, and
writes a ``detections`` row - plus an ``alerts`` row when the verdict crossed its
threshold for real.

Three decisions worth stating, because each one is a judgement rather than an
obvious mechanic.

**Not every flow becomes a detection.** The flow sink (``flow_sink.py``, its own
consumer group) is what keeps every scored flow, features included, in ClickHouse
``network_flows``; PostgreSQL holds the ones that mean something. Here a flow below the
deciding threshold is counted and dropped, so the alert store stays the size of the interesting traffic
rather than the size of the link.

**A shadow verdict is still stored, and still never alerts.** With no active model
the fused score is undecided by design, so the shadow tier's own probability is
recorded against its own threshold. That is what makes a shadow period measurable:
at the end of it somebody has to be able to ask what the model would have said. It
produces no alert, because a model nobody has promoted must not page anyone.

**A detection is never stored unexplained.** M2 composes a Detection with exactly one
Explanation and the column is NOT NULL, so if the explaining tier did not score this
flow the writer stops rather than inventing an empty explanation.

Delivery is at-least-once: the bus offset is committed after the database
transaction, so a crash between them replays a message rather than losing it. A
duplicate detection is visible and reconcilable; a missing one is evidence that was
never collected. De-duplicating the resulting alerts is the SOAR layer's job, which is
what the stable fingerprint in ``services.soar`` is for.

An alert is enriched inside the transaction and forwarded outside it. Matching against
the IoC table is a local query and belongs with the write; posting to Keep is a call to
another process, and a network round trip inside an open transaction holds a row lock
for as long as a third party feels like taking.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from netsentinel_api.db.models import Alert, AlertStatus, Detection, IoC, Severity
from netsentinel_api.services.intel import find, link
from netsentinel_api.services.soar import Forwarder
from netsentinel_core.features.contract import FEATURE_DIM
from sqlalchemy.orm import Session

from netsentinel_writer.consumer import Consumer
from netsentinel_writer.explain import Explainer
from netsentinel_writer.technique import Labeller

logger = logging.getLogger("netsentinel.writer")

#: Severity answers two questions: how sure the models are, and how much harm the
#: attack could do. Confidence alone made 134 of 135 replayed attacks critical, because
#: Tier A is almost always sure, and a port scan then outranked nothing.
#:
#: How sure: bands of the calibrated probability, read floor-first. Absolute bands are
#: only meaningful because the score is calibrated.
CONFIDENCE_BANDS: tuple[tuple[float, int], ...] = ((0.95, 3), (0.85, 2), (0.70, 1), (0.0, 0))

#: How much harm, claimed only where the technique is claimed: the family model is
#: confident and that family's confident labels were precise on validation (see
#: technique.py). Exploitation and denial of service do damage; a scan is a precursor.
#: An attack whose kind is not known counts as medium, never low - an unidentified
#: attack must not be ranked below an identified scan.
TECHNIQUE_IMPACT: dict[str, int] = {"T1190": 1, "T1499": 1, "T1046": -1}

SEVERITY_LADDER: tuple[Severity, ...] = (
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
)


class WriterError(RuntimeError):
    """The writer refused a message. The message says which rule it broke."""


class ContractMismatch(WriterError):
    """The stream was produced against a different feature contract than this build.

    Fatal rather than skippable: every following message is produced by the same
    sensor against the same contract, so this is not a bad message, it is the wrong
    pipeline. Continuing would fill the alert store with explanations whose feature
    names mean something else.
    """


def severity_for(risk_score: float, technique: str | None = None) -> Severity:
    """Critical needs both: the models sure (>= 0.95) and an attack that does harm.

    |            | harmful  | not known | scan   |
    | >= 0.95    | critical | high      | medium |
    | >= 0.85    | high     | medium    | low    |
    | >= 0.70    | medium   | low       | low    |
    """
    confidence = next(level for floor, level in CONFIDENCE_BANDS if risk_score >= floor)
    impact = TECHNIQUE_IMPACT.get(technique or "", 0)
    return SEVERITY_LADDER[max(0, min(len(SEVERITY_LADDER) - 1, confidence + impact - 1))]


@dataclass(slots=True)
class WriteStats:
    messages: int = 0
    detections: int = 0
    alerts: int = 0
    enriched: int = 0
    shadow: int = 0
    below_threshold: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "messages": self.messages,
            "detections": self.detections,
            "alerts": self.alerts,
            "enriched": self.enriched,
            "shadow": self.shadow,
            "below_threshold": self.below_threshold,
        }


class DetectionWriter:
    """Turns one scored-flow message into the rows it justifies."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        explainer: Explainer,
        sensor_id: int,
        model_id: int,
        forwarder: Forwarder | None = None,
        labeller: Labeller | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._explainer = explainer
        self._sensor_id = sensor_id
        self._model_id = model_id
        self._forwarder = forwarder
        # Optional: without it an ML alert carries no technique, as before.
        self._labeller = labeller
        # Alerts raised by the message in flight, forwarded once it is committed.
        self._to_forward: list[tuple[Alert, list[IoC]]] = []
        self.stats = WriteStats()

    def handle(self, session: Session, payload: Mapping[str, Any]) -> Detection | None:
        """Write the rows this message justifies. Returns the detection, if any."""
        flow = payload.get("flow") or {}
        verdict = payload.get("verdict") or {}

        declared = (payload.get("contract") or {}).get("features")
        if declared != FEATURE_DIM:
            raise ContractMismatch(
                f"stream declares {declared} features, this build produces "
                f"{FEATURE_DIM}. Retrain, or pin the core the sensor was built "
                "against; do not write these detections."
            )

        scored_by = {
            f"{model.get('name')}:{model.get('version')}"
            for model in payload.get("models") or []
        }
        if self._explainer.identity not in scored_by:
            raise WriterError(
                f"{self._explainer.identity} did not score this flow (models: "
                f"{sorted(scored_by) or 'none'}), so the detection would have no "
                "explanation. Point the writer at a model the sensor is loading."
            )

        model_scores = {k: float(v) for k, v in (verdict.get("model_scores") or {}).items()}
        shadow = bool(verdict.get("shadow", True))

        risk_score = verdict.get("risk_score")
        threshold = verdict.get("threshold")
        if risk_score is None:
            # Undecided: no active tier moved the number. Fall back to what the
            # explaining tier said on its own, judged against its own threshold.
            tier_key = f"tier_{self._explainer.tier.lower()}"
            if tier_key not in model_scores:
                raise WriterError(
                    f"verdict carries no {tier_key} score, so there is nothing to "
                    "record for the shadow tier"
                )
            risk_score = model_scores[tier_key]
            threshold = self._explainer.threshold
        if threshold is None:
            threshold = self._explainer.threshold

        risk_score = float(risk_score)
        if risk_score < float(threshold):
            # ClickHouse is the flow sink's job. PostgreSQL is for the ones that mean
            # something.
            self.stats.below_threshold += 1
            return None

        detection = Detection(
            flow_id=str(flow.get("flow_id", "")),
            sensor_id=self._sensor_id,
            model_id=self._model_id,
            risk_score=risk_score,
            model_scores=model_scores,
            shap_values=self._explainer.explain(flow),
            shadow=shadow,
        )
        session.add(detection)
        self.stats.detections += 1
        if shadow:
            self.stats.shadow += 1

        if verdict.get("is_alert") and not shadow:
            # Identities the alert needs, so it is flushed before the alert is built.
            session.flush()
            technique = self._labeller.label(flow).technique if self._labeller is not None else None
            alert = Alert(
                detection_id=detection.detection_id,
                source=str(flow.get("sensor") or "early_flow"),
                severity=severity_for(risk_score, technique),
                status=AlertStatus.new,
                src_ip=flow.get("src_ip"),
                dst_ip=flow.get("dst_ip"),
                mitre_technique=technique,
            )
            session.add(alert)
            session.flush()
            matches = self._enrich(session, alert)
            self.stats.alerts += 1
            self.stats.enriched += 1 if matches else 0
            self._to_forward.append((alert, matches))

        return detection

    def _enrich(self, session: Session, alert: Alert) -> list[IoC]:
        """Link the alert to any indicator it touches, escalating if one is high threat."""
        return link(session, alert, find(session, alert))

    def _forward(self) -> None:
        """Hand committed alerts to the SOAR layer. Never fatal."""
        pending, self._to_forward = self._to_forward, []
        if self._forwarder is None:
            return
        for alert, iocs in pending:
            try:
                self._forwarder.send(alert, iocs)
            except Exception:  # noqa: BLE001 - a SOAR outage is not a writer outage
                logger.exception("could not forward alert %s", alert.alert_id)

    def run(self, consumer: Consumer) -> WriteStats:
        """Consume until the source is exhausted or closed."""
        for payload in consumer.messages():
            self.stats.messages += 1
            with self._session_factory() as session:
                self.handle(session, payload)
                session.commit()
            # Only now. See the module docstring on at-least-once delivery.
            consumer.commit()
            self._forward()
        return self.stats
