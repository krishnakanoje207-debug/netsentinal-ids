"""Deciding whether a model has earned its way out of shadow mode.

Every model is born in ``shadow``: it scores live traffic, its verdicts are stored,
and it pages nobody. Promotion is the moment that stops being true, so it is the one
decision in this system that is gated on measurement rather than on somebody being
confident.

**Where the labels come from.** A shadow model raises no alert, so it has no closed
alerts of its own to be judged on. What it does have is a score on the same flow some
other model alerted on, and an analyst's verdict on that alert - closed as a true or
a false positive. Labels are therefore per flow, not per model: whatever the analyst
concluded about the flow is applied to every model that scored it. ``flow_id`` is the
join, which is why it is indexed.

**What is measured, honestly.** These are not ground-truth metrics over all traffic.
They are agreement with analyst verdicts on the flows that were triaged, which is a
biased sample by construction: nobody labels the traffic nothing fired on. So a
model's unlabelled volume is reported next to its precision, because a tier that
fires constantly on flows no one ever looks at reads as perfect precision and is not.
True negatives are unknowable here and are not invented.

**What promotion refuses.** Too few labels, too short a period, or a candidate that
is worse than the model already serving. The thresholds are arguments rather than
constants because a lab demo and a production rollout are different evidential bars -
but they are recorded in the audit row, so a promotion made on five labels says so
forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from netsentinel_api.db.models import (
    AlertStatus,
    AuditLog,
    MLModel,
    ModelMode,
    User,
)

#: Labelled detections a model needs before its numbers mean anything. Fifty is not
#: a statistical threshold, it is a smell test: below it one analyst's bad afternoon
#: moves precision by ten points.
MIN_LABELLED = 50

#: Days a model must have been scoring live traffic. The research plan budgets about
#: six on lab traffic and at least fourteen on real traffic; the default is the lab
#: figure, because that is what this deployment is.
MIN_SHADOW_DAYS = 6

#: An analyst's verdict, as the alert statuses that carry one.
LABELS: dict[AlertStatus, bool] = {
    AlertStatus.closed_true_positive: True,
    AlertStatus.closed_false_positive: False,
}


class PromotionRefused(Exception):
    """The model has not earned promotion. The message says what is missing."""


@dataclass(frozen=True)
class Scored:
    """One model's verdict on one flow, with the analyst's conclusion if there is one."""

    model_id: int
    risk_score: float
    created_at: datetime
    #: True, False, or None when nobody triaged the flow this scored.
    label: bool | None


@dataclass
class Outcome:
    """How one model did over the window."""

    model_id: int
    name: str
    version: str
    tier: str
    mode: str
    threshold: float
    scored: int = 0
    labelled: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    #: Filled by ``evaluate``: a ranking metric that does not depend on the
    #: threshold.
    average_precision: float | None = None

    @property
    def unlabelled(self) -> int:
        """Verdicts nobody ever judged. Reported beside precision, not hidden."""
        return self.scored - self.labelled

    @property
    def precision(self) -> float | None:
        fired = self.true_positives + self.false_positives
        return self.true_positives / fired if fired else None

    @property
    def recall(self) -> float | None:
        actual = self.true_positives + self.false_negatives
        return self.true_positives / actual if actual else None

    @property
    def f1(self) -> float | None:
        precision, recall = self.precision, self.recall
        if not precision or not recall:
            return None
        return 2 * precision * recall / (precision + recall)

    @property
    def days(self) -> float:
        if self.first_seen is None or self.last_seen is None:
            return 0.0
        return (self.last_seen - self.first_seen).total_seconds() / 86400

    @property
    def false_positives_per_day(self) -> float | None:
        """The number an analyst actually feels. A model is unusable long before
        its precision looks bad if it produces forty of these a day."""
        if self.days <= 0:
            return None
        return self.false_positives / self.days

    def as_dict(self) -> dict:
        return {
            "model_id": self.model_id,
            "name": self.name,
            "version": self.version,
            "tier": self.tier,
            "mode": self.mode,
            "scored": self.scored,
            "labelled": self.labelled,
            "unlabelled": self.unlabelled,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "average_precision": self.average_precision,
            "false_positives_per_day": self.false_positives_per_day,
            "days": round(self.days, 2),
        }


def evaluate(models: Iterable[MLModel], scored: Iterable[Scored]) -> list[Outcome]:
    """Score every model over the same labelled flows.

    Each model is judged against its own threshold, because that is the number it
    would serve with - comparing two models at a shared cut-off would flatter
    whichever one happens to be calibrated for it.
    """
    outcomes = {
        model.model_id: Outcome(
            model_id=model.model_id,
            name=model.name,
            version=model.version,
            tier=model.tier.value,
            mode=model.mode.value,
            threshold=model.threshold,
        )
        for model in models
    }
    ranked: dict[int, list[tuple[float, bool]]] = {model_id: [] for model_id in outcomes}

    for verdict in scored:
        outcome = outcomes.get(verdict.model_id)
        if outcome is None:
            # A detection from a model that has since been deleted from the
            # registry. Counted nowhere rather than attributed to the wrong row.
            continue

        outcome.scored += 1
        moment = verdict.created_at
        if outcome.first_seen is None or moment < outcome.first_seen:
            outcome.first_seen = moment
        if outcome.last_seen is None or moment > outcome.last_seen:
            outcome.last_seen = moment

        if verdict.label is None:
            continue

        outcome.labelled += 1
        ranked[verdict.model_id].append((verdict.risk_score, verdict.label))
        fired = verdict.risk_score >= outcome.threshold
        if fired and verdict.label:
            outcome.true_positives += 1
        elif fired:
            outcome.false_positives += 1
        elif verdict.label:
            outcome.false_negatives += 1
        # Below threshold and labelled false is the one case with nothing to record:
        # the model was right to stay quiet, and true negatives here would be
        # counted from a sample that only contains flows somebody looked at.

    for model_id, pairs in ranked.items():
        outcomes[model_id].average_precision = average_precision(pairs)

    return sorted(outcomes.values(), key=lambda o: o.model_id)


def average_precision(pairs: list[tuple[float, bool]]) -> float | None:
    """Area under the precision-recall curve, by the step-wise definition.

    Threshold-free on purpose: it says whether the model ranks bad flows above good
    ones, which is the question when choosing between candidates. Precision at one
    cut-off says whether today's threshold is well placed, which is a different
    argument and a smaller one.
    """
    positives = sum(1 for _, label in pairs if label)
    if not positives:
        return None

    # Ties broken towards the negative, so a model cannot look good by scoring
    # everything identically.
    ordered = sorted(pairs, key=lambda pair: (-pair[0], pair[1]))
    hits = 0
    total = 0.0
    for index, (_, label) in enumerate(ordered, start=1):
        if label:
            hits += 1
            total += hits / index
    return total / positives


def refusal(
    candidate: Outcome,
    active: Outcome | None,
    min_labelled: int = MIN_LABELLED,
    min_days: float = MIN_SHADOW_DAYS,
) -> str | None:
    """Why this model may not be promoted, or None if it may.

    A refusal is a sentence rather than a boolean because the operator has to be
    able to act on it: "nineteen labelled detections" tells them to keep triaging,
    where False tells them to look for a flag to override.
    """
    if candidate.labelled < min_labelled:
        return (
            f"{candidate.labelled} labelled detection(s), and {min_labelled} are "
            "required; a shadow period is evidence, not a formality"
        )
    if candidate.days < min_days:
        return (
            f"{candidate.days:.1f} day(s) of shadow traffic, and {min_days} are "
            "required"
        )
    if candidate.average_precision is None:
        # Every labelled flow in the window was a false positive, so the window
        # contains no evidence that this model detects anything - only that it
        # agrees with an analyst about what is harmless.
        return (
            "no labelled true positive in the window, so nothing shows this model "
            "detects anything"
        )
    if active is None:
        return None

    # Compared on ranking rather than on precision: the candidate will be served
    # with its own threshold, and a threshold can be moved afterwards where a model
    # that ranks badly cannot be fixed by moving one.
    if (candidate.average_precision or 0) < (active.average_precision or 0):
        return (
            f"average precision {candidate.average_precision:.3f} is below the "
            f"active model's {active.average_precision:.3f}"
        )
    return None


def promote(
    session,
    candidate: MLModel,
    active: MLModel | None,
    outcome: Outcome,
    actor: User | None = None,
    at: datetime | None = None,
) -> None:
    """Make this model the one that decides, and retire the one it replaces.

    Both halves happen here and in one transaction. Two active models of the same
    tier would have the fusion scorer loading whichever the query returned first,
    and a shadow period ending in an ambiguity is worse than one that never ended.
    """
    if candidate.mode is not ModelMode.shadow:
        raise PromotionRefused(
            f"model {candidate.model_id} is {candidate.mode.value}, not shadow"
        )
    if active is not None and active.tier is not candidate.tier:
        raise PromotionRefused(
            f"model {active.model_id} is tier {active.tier.value}, so it is not the "
            f"model {candidate.model_id} would replace"
        )

    candidate.mode = ModelMode.active
    candidate.deployed_at = at or datetime.now(timezone.utc)
    if active is not None:
        # Retired rather than returned to shadow: it has already been evaluated,
        # and a retired model keeps its rows and its history without scoring
        # anything again.
        active.mode = ModelMode.retired

    session.add(
        AuditLog(
            user_id=actor.user_id if actor is not None else None,
            action="model.promoted",
            entity=f"ml_model:{candidate.model_id}",
            # The evidence travels with the decision. A promotion made on five
            # labelled detections says so permanently.
            details={
                "replaced": active.model_id if active is not None else None,
                "evidence": outcome.as_dict(),
            },
        )
    )
