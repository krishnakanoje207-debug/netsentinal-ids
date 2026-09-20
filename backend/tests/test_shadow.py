"""The shadow period, and what it takes to end one.

Promotion is the moment a model stops being an observer and starts deciding what an
analyst sees, so these tests are mostly about refusals: too little evidence, too
short a period, a candidate that ranks worse than the model already serving. The
metrics are tested on sets small enough to work out by hand, because a metric nobody
can check by hand is one people stop believing when it disagrees with them.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from netsentinel_api.db.models import (
    AlertStatus,
    AuditLog,
    MLModel,
    ModelMode,
    ModelTier,
    User,
)
from netsentinel_api.services.shadow import (
    LABELS,
    Outcome,
    PromotionRefused,
    Scored,
    average_precision,
    evaluate,
    promote,
    refusal,
)
from netsentinel_api.shadow_report import window_start

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


def _model(model_id: int = 1, mode: ModelMode = ModelMode.shadow,
           threshold: float = 0.5, tier: ModelTier = ModelTier.A) -> MLModel:
    return MLModel(
        model_id=model_id,
        name="tier-a-lgbm",
        tier=tier,
        version=f"0.{model_id}.0",
        onnx_sha256="a" * 64,
        threshold=threshold,
        mode=mode,
    )


def _scored(scores_and_labels, model_id: int = 1, spread_days: float = 7.0):
    """Verdicts spread evenly across a window, so days() is predictable."""
    count = max(len(scores_and_labels) - 1, 1)
    step = timedelta(days=spread_days) / count
    return [
        Scored(model_id=model_id, risk_score=score,
               created_at=NOW - timedelta(days=spread_days) + step * index,
               label=label)
        for index, (score, label) in enumerate(scores_and_labels)
    ]


class StubSession:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, instance: object, /) -> None:
        self.added.append(instance)


# --- counting --------------------------------------------------------------

def test_each_verdict_lands_in_one_box():
    outcome, = evaluate(
        [_model(threshold=0.5)],
        _scored([(0.9, True), (0.8, False), (0.4, True), (0.1, False)]),
    )
    assert (outcome.true_positives, outcome.false_positives,
            outcome.false_negatives) == (1, 1, 1)
    assert outcome.precision == 0.5
    assert outcome.recall == 0.5


def test_a_model_is_judged_against_its_own_threshold():
    """A shared cut-off flatters whichever model happens to be calibrated for it."""
    verdicts = _scored([(0.6, True), (0.4, True)])
    strict, = evaluate([_model(threshold=0.7)], verdicts)
    lenient, = evaluate([_model(threshold=0.3)], verdicts)
    assert strict.true_positives == 0 and lenient.true_positives == 2


def test_an_unlabelled_verdict_is_counted_but_not_scored():
    """A tier that fires on flows nobody looks at must not read as perfect."""
    outcome, = evaluate([_model()], _scored([(0.9, True), (0.9, None), (0.9, None)]))
    assert outcome.scored == 3 and outcome.labelled == 1
    assert outcome.unlabelled == 2
    assert outcome.precision == 1.0  # and the 2 beside it is the point


def test_a_verdict_from_an_unknown_model_is_not_attributed_to_another():
    outcome, = evaluate([_model(model_id=1)], _scored([(0.9, True)], model_id=99))
    assert outcome.scored == 0


def test_false_positives_are_reported_per_day():
    """The number an analyst feels, rather than the ratio that hides it."""
    outcome, = evaluate(
        [_model(threshold=0.5)],
        _scored([(0.9, False)] * 14, spread_days=7.0),
    )
    assert outcome.false_positives == 14
    assert outcome.false_positives_per_day == pytest.approx(2.0)


def test_a_model_with_one_verdict_has_no_rate():
    """One verdict spans no time; a rate computed from it would be invented."""
    outcome, = evaluate([_model()], [Scored(1, 0.9, NOW, False)])
    assert outcome.false_positives_per_day is None


# --- ranking ---------------------------------------------------------------

def test_average_precision_is_computed_the_step_wise_way():
    # Ranked: hit at 1 (1/1), miss, hit at 3 (2/3) -> (1 + 0.667) / 2
    assert average_precision([(0.9, True), (0.8, False), (0.7, True)]) == pytest.approx(
        0.8333333, abs=1e-6
    )


def test_a_perfect_ranking_scores_one():
    assert average_precision([(0.9, True), (0.8, True), (0.2, False)]) == 1.0


def test_a_model_that_scores_everything_the_same_gains_nothing():
    """Ties break towards the negative, so flat output cannot look decisive."""
    assert average_precision([(0.5, True), (0.5, False)]) == pytest.approx(0.5)


def test_a_window_with_no_true_positives_has_no_ranking_metric():
    assert average_precision([(0.9, False), (0.1, False)]) is None


# --- the labels ------------------------------------------------------------

def test_only_a_closed_alert_carries_a_verdict():
    """An open alert is a question, not an answer."""
    assert set(LABELS) == {
        AlertStatus.closed_true_positive,
        AlertStatus.closed_false_positive,
    }
    assert LABELS[AlertStatus.closed_true_positive] is True


@pytest.mark.parametrize(("since", "expected_days"), [("7d", 7), ("1d", 1)])
def test_the_window_is_read_the_way_the_misp_sync_reads_it(since, expected_days):
    assert window_start(since, NOW) == NOW - timedelta(days=expected_days)


def test_an_hour_window_is_understood():
    assert window_start("12h", NOW) == NOW - timedelta(hours=12)


def test_a_window_nobody_can_read_is_refused():
    with pytest.raises(ValueError, match="cannot read a window"):
        window_start("last tuesday", NOW)


# --- refusing to promote ---------------------------------------------------

def _outcome(labelled: int = 100, ap: float | None = 0.9, days: float = 7.0,
             model_id: int = 1) -> Outcome:
    outcome = Outcome(model_id=model_id, name="tier-a-lgbm", version="0.1.0",
                      tier="A", mode="shadow", threshold=0.5)
    outcome.labelled = labelled
    outcome.scored = labelled
    outcome.average_precision = ap
    outcome.first_seen = NOW - timedelta(days=days)
    outcome.last_seen = NOW
    return outcome


def test_a_model_with_enough_evidence_may_be_promoted():
    assert refusal(_outcome(), None) is None


def test_too_few_labels_is_a_refusal_that_says_so():
    """A shadow period is evidence, not a formality."""
    reason = refusal(_outcome(labelled=19), None)
    assert "19 labelled detection" in reason


def test_too_short_a_period_is_a_refusal():
    reason = refusal(_outcome(days=1.0), None)
    assert "day(s) of shadow traffic" in reason


def test_a_candidate_that_ranks_worse_than_the_incumbent_is_refused():
    """The threshold can be moved afterwards; a bad ranking cannot be fixed by it."""
    reason = refusal(_outcome(ap=0.70), _outcome(ap=0.85, model_id=2))
    assert "below the active model" in reason


def test_a_candidate_that_ranks_better_replaces_it():
    assert refusal(_outcome(ap=0.91), _outcome(ap=0.85, model_id=2)) is None


def test_a_model_that_never_found_anything_is_refused():
    """Fifty labelled flows that were all false positives show agreement about
    what is harmless, not an ability to detect."""
    reason = refusal(_outcome(ap=None), None)
    assert "detects anything" in reason


def test_the_bar_can_be_lowered_deliberately():
    """A lab demo and a production rollout are different evidential bars, and the
    number used is recorded in the audit row."""
    assert refusal(_outcome(labelled=5, days=0.5), None, min_labelled=5,
                   min_days=0.5) is None


# --- promoting -------------------------------------------------------------

def test_promotion_makes_one_model_decide_and_retires_the_other():
    session = StubSession()
    candidate, active = _model(model_id=3), _model(model_id=2, mode=ModelMode.active)

    promote(session, candidate, active, _outcome(model_id=3), at=NOW)

    assert candidate.mode is ModelMode.active and candidate.deployed_at == NOW
    # Retired, not returned to shadow: it has already been evaluated.
    assert active.mode is ModelMode.retired


def test_the_first_active_model_replaces_nothing():
    session = StubSession()
    candidate = _model(model_id=1)

    promote(session, candidate, None, _outcome(), at=NOW)

    entry, = [o for o in session.added if isinstance(o, AuditLog)]
    assert entry.details["replaced"] is None


def test_the_evidence_travels_with_the_decision():
    """A promotion made on five labelled detections says so permanently."""
    session = StubSession()
    promote(session, _model(model_id=3), None, _outcome(labelled=5), at=NOW)

    entry, = [o for o in session.added if isinstance(o, AuditLog)]
    assert entry.details["evidence"]["labelled"] == 5
    assert entry.action == "model.promoted"
    assert entry.entity == "ml_model:3"


def test_a_promotion_can_name_who_made_it():
    session = StubSession()
    actor = User(user_id=7, username="analyst", email="a@example.test",
                 password_hash="x", role_id=1)

    promote(session, _model(), None, _outcome(), actor=actor, at=NOW)

    entry, = [o for o in session.added if isinstance(o, AuditLog)]
    assert entry.user_id == 7


def test_a_model_that_is_already_active_is_not_promoted_again():
    with pytest.raises(PromotionRefused, match="is active, not shadow"):
        promote(StubSession(), _model(mode=ModelMode.active), None, _outcome(), at=NOW)


def test_a_model_cannot_replace_one_from_another_tier():
    """Tiers are not interchangeable; retiring D because B improved is a bug."""
    candidate = _model(model_id=3, tier=ModelTier.B)
    active = _model(model_id=2, mode=ModelMode.active, tier=ModelTier.D)
    with pytest.raises(PromotionRefused, match="is tier D"):
        promote(StubSession(), candidate, active, _outcome(model_id=3), at=NOW)
