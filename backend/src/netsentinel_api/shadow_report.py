"""What the models said during their shadow period, and promotion.

    python -m netsentinel_api.shadow_report --since 7d
    python -m netsentinel_api.shadow_report --since 7d --promote 3 --by analyst

Reporting and promoting are one command because they are one decision: the numbers
printed here are the numbers recorded in the audit row of the promotion, from the
same window and the same query. A report that could be produced separately from the
decision it justifies is a report somebody can go shopping for.

The queries live here and the arithmetic lives in ``services.shadow``, the split
used everywhere else in this package: what counts as a true positive is exercisable
without a database, and this module stays the part that needs one.
"""

from __future__ import annotations

import argparse
import logging
import re
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from netsentinel_api.db.models import (
    Alert,
    Detection,
    MLModel,
    ModelMode,
    ModelTier,
    User,
)
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.services.shadow import (
    LABELS,
    MIN_LABELLED,
    MIN_SHADOW_DAYS,
    Outcome,
    PromotionRefused,
    Scored,
    evaluate,
    promote,
    refusal,
)

logger = logging.getLogger("netsentinel.shadow")

_WINDOW = re.compile(r"^(\d+)([hd])$")


def window_start(since: str, now: datetime | None = None) -> datetime:
    """Turn ``7d`` or ``12h`` into a moment. Same spelling as the MISP sync uses."""
    match = _WINDOW.match(since.strip().lower())
    if match is None:
        raise ValueError(f"cannot read a window from {since!r}; use 7d or 12h")
    amount, unit = int(match.group(1)), match.group(2)
    delta = timedelta(days=amount) if unit == "d" else timedelta(hours=amount)
    return (now or datetime.now(timezone.utc)) - delta


def labels_by_flow(session, start: datetime) -> dict[str, bool]:
    """The analyst's conclusion per flow, from the alerts they closed.

    A flow with two alerts closed differently is counted as a true positive: an
    analyst concluding that something was there outranks another concluding it was
    not, and the alternative is dropping the flow that generated the disagreement -
    which is the most informative one in the set.
    """
    rows = session.execute(
        select(Detection.flow_id, Alert.status)
        .join(Alert, Alert.detection_id == Detection.detection_id)
        .where(Alert.status.in_(list(LABELS)), Detection.created_at >= start)
    )

    labels: dict[str, bool] = {}
    for flow_id, status in rows:
        label = LABELS[status]
        labels[flow_id] = labels.get(flow_id, False) or label
    return labels


def collect(session, start: datetime) -> tuple[list[MLModel], list[Scored]]:
    """Every model, and every verdict it recorded in the window."""
    models = list(session.scalars(select(MLModel)))
    labels = labels_by_flow(session, start)

    scored = [
        Scored(
            model_id=model_id,
            risk_score=risk_score,
            created_at=created_at,
            label=labels.get(flow_id),
        )
        for model_id, risk_score, created_at, flow_id in session.execute(
            select(
                Detection.model_id,
                Detection.risk_score,
                Detection.created_at,
                Detection.flow_id,
            ).where(Detection.created_at >= start)
        )
    ]
    return models, scored


def active_for(session, tier: ModelTier) -> MLModel | None:
    return session.scalar(
        select(MLModel).where(MLModel.tier == tier, MLModel.mode == ModelMode.active)
    )


def render(outcomes: list[Outcome]) -> str:
    """The report, as a table an operator reads in a terminal."""
    header = (
        f"{'id':>3}  {'model':<24} {'tier':<4} {'mode':<8} {'labelled':>8} "
        f"{'unlab.':>7} {'prec':>6} {'recall':>6} {'AP':>6} {'FP/day':>7}"
    )
    lines = [header, "-" * len(header)]
    for outcome in outcomes:
        lines.append(
            f"{outcome.model_id:>3}  "
            f"{outcome.name[:18] + ' ' + outcome.version[:5]:<24} "
            f"{outcome.tier:<4} {outcome.mode:<8} {outcome.labelled:>8} "
            f"{outcome.unlabelled:>7} {_number(outcome.precision):>6} "
            f"{_number(outcome.recall):>6} {_number(outcome.average_precision):>6} "
            f"{_number(outcome.false_positives_per_day, '.1f'):>7}"
        )
    return "\n".join(lines)


def _number(value: float | None, spec: str = ".3f") -> str:
    # "-" rather than 0.000: a metric nothing could be computed for and a metric
    # that came out at zero are different findings.
    return "-" if value is None else format(value, spec)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Report the shadow period, and promote a model that has earned it"
    )
    parser.add_argument("--since", default="7d", help="window, e.g. 7d or 12h (default: 7d)")
    parser.add_argument("--promote", type=int, metavar="MODEL_ID",
                        help="promote this model to active if the evidence allows")
    parser.add_argument("--by", metavar="USERNAME",
                        help="attribute the promotion to this user in the audit log")
    parser.add_argument("--min-labelled", type=int, default=MIN_LABELLED)
    parser.add_argument("--min-days", type=float, default=MIN_SHADOW_DAYS)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-5s %(name)s %(message)s",
    )

    try:
        start = window_start(args.since)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    with get_sessionmaker()() as session:
        models, scored = collect(session, start)
        outcomes = evaluate(models, scored)
        print(f"shadow report since {start.isoformat()}\n")
        print(render(outcomes))

        if args.promote is None:
            return 0

        candidate = session.get(MLModel, args.promote)
        if candidate is None:
            print(f"\nno model {args.promote}", file=sys.stderr)
            return 2

        outcome = next(o for o in outcomes if o.model_id == candidate.model_id)
        active = active_for(session, candidate.tier)
        active_outcome = next(
            (o for o in outcomes if active is not None and o.model_id == active.model_id),
            None,
        )

        reason = refusal(outcome, active_outcome, args.min_labelled, args.min_days)
        if reason is not None:
            print(f"\nrefusing to promote model {candidate.model_id}: {reason}",
                  file=sys.stderr)
            return 1

        actor = None
        if args.by:
            actor = session.scalar(select(User).where(User.username == args.by))
            if actor is None:
                print(f"\nno user named {args.by}", file=sys.stderr)
                return 2

        try:
            promote(session, candidate, active, outcome, actor)
        except PromotionRefused as exc:
            print(f"\n{exc}", file=sys.stderr)
            return 1

        session.commit()
        replaced = f", replacing model {active.model_id}" if active is not None else ""
        print(f"\nmodel {candidate.model_id} is now active{replaced}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
