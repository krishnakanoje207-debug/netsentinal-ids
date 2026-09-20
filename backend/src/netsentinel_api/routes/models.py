"""The model registry, and promotion out of shadow mode.

Reading the registry and promoting from it are one module for the reason they are
one command in ``shadow_report``: they are one decision. The evidence recorded in a
promotion's audit row comes from the same window and the same query that produced
the numbers on the page somebody clicked from. A report that can be produced
separately from the decision it justifies is a report somebody can go shopping for.

Two permissions, not one. ``models:read`` is held by analysts, administrators and
the ML engineer, because which model is deciding is context for every alert on the
dashboard. ``models:deploy`` is held only by the ML engineer: promotion is the
moment a model stops observing and starts raising alerts people are paged on.

The bar a candidate must clear is a deployment setting rather than a request
parameter. See ``config.Settings.promotion_min_labelled``.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from netsentinel_api.config import Settings
from netsentinel_api.db.models import MLModel, ModelMode
from netsentinel_api.db.repositories import ModelRepository
from netsentinel_api.deps import ModelRepoDep, SessionDep, SettingsDep, require
from netsentinel_api.rbac import MODELS_DEPLOY, MODELS_READ
from netsentinel_api.schemas import EvidenceOut, ModelOut, PromoteIn
from netsentinel_api.services.shadow import (
    Outcome,
    PromotionRefused,
    evaluate,
    promote,
    refusal,
    window_start,
)

router = APIRouter(prefix="/models", tags=["models"])


def _report(models: ModelRepository, since: str) -> dict[int, Outcome]:
    """Every model's window, keyed by id.

    Both handlers start here, so the refusal shown beside a model on the page is
    computed the same way as the refusal that would stop its promotion.
    """
    try:
        start = window_start(since)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    outcomes = evaluate(models.list(), models.scored_since(start))
    return {outcome.model_id: outcome for outcome in outcomes}


def _blocked_by(
    model: MLModel,
    outcomes: dict[int, Outcome],
    models: ModelRepository,
    settings: Settings,
) -> str | None:
    """Why this model may not be promoted, or None if it may."""
    if model.mode is not ModelMode.shadow:
        # Deliberately not a verdict from ``refusal()``: that function weighs
        # evidence, and a model that is already deciding has no promotion to weigh.
        return f"already {model.mode.value}"

    active = models.active_for(model.tier)
    return refusal(
        outcomes[model.model_id],
        outcomes.get(active.model_id) if active is not None else None,
        settings.promotion_min_labelled,
        settings.promotion_min_shadow_days,
    )


def _evidence(outcome: Outcome) -> EvidenceOut:
    """The outcome's own dictionary, minus the identity fields ``ModelOut`` carries.

    Built from ``as_dict`` rather than field by field so the report the CLI prints
    and the report the dashboard draws cannot drift apart silently: a metric added
    to ``Outcome`` and forgotten here is a KeyError on the next request, not a
    column that quietly stops appearing.
    """
    fields = outcome.as_dict()
    for identity in ("model_id", "name", "version", "tier", "mode"):
        fields.pop(identity)
    return EvidenceOut(**fields)


def _rendered(
    model: MLModel,
    outcomes: dict[int, Outcome],
    models: ModelRepository,
    settings: Settings,
) -> ModelOut:
    return ModelOut(
        model_id=model.model_id,
        name=model.name,
        tier=model.tier,
        version=model.version,
        threshold=model.threshold,
        mode=model.mode,
        pr_auc=model.pr_auc,
        deployed_at=model.deployed_at,
        evidence=_evidence(outcomes[model.model_id]),
        blocked_by=_blocked_by(model, outcomes, models, settings),
    )


@router.get("", response_model=list[ModelOut])
def list_models(
    models: ModelRepoDep,
    settings: SettingsDep,
    _: Annotated[object, Depends(require(MODELS_READ))],
    since: Annotated[str, Query(description="report window, e.g. 7d or 12h")] = "7d",
) -> list[ModelOut]:
    """Every registered model, with what it did over the window.

    Retired models are listed too. A retired model is the evidence for the last
    promotion, and dropping it from the page would leave the current model's
    predecessor unaccounted for - which is exactly what is asked about after a
    missed detection.
    """
    outcomes = _report(models, since)
    return [_rendered(model, outcomes, models, settings) for model in models.list()]


@router.post("/{model_id}/promote", response_model=ModelOut)
def promote_model(
    model_id: int,
    payload: PromoteIn,
    models: ModelRepoDep,
    session: SessionDep,
    settings: SettingsDep,
    user: Annotated[object, Depends(require(MODELS_DEPLOY))],
) -> ModelOut:
    """Make this model the one that decides for its tier, and retire the incumbent.

    The evidence is re-evaluated here rather than trusted from the page: the window
    has moved since that page was drawn, and the numbers written into the audit row
    have to be the ones that actually justified this promotion.

    A refusal is a 422 carrying the sentence that says what is missing. The caller
    is deciding whether to keep triaging or to look at a different candidate, and a
    bare "forbidden" answers neither question.
    """
    model = models.get(model_id)
    if model is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="model not found")

    outcomes = _report(models, payload.since)
    reason = _blocked_by(model, outcomes, models, settings)
    if reason is not None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"refusing to promote model {model_id}: {reason}",
        )

    active = models.active_for(model.tier)
    try:
        promote(session, model, active, outcomes[model_id], user)  # type: ignore[arg-type]
    except PromotionRefused as exc:
        # The service checks the same two things from the rows rather than from the
        # report. Reaching this means the two disagreed, which is worth surfacing
        # as a refusal rather than as a 500 - and nothing has been committed.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)
        ) from exc

    # Re-rendered after the promotion, so the reply carries the mode the caller just
    # created rather than the one they clicked from.
    return _rendered(model, outcomes, models, settings)
