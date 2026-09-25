"""The fusion scorer: features in, an explained verdict out.

Fusion rule, and why it is this one:

* Each tier produces a calibrated probability, so the numbers are comparable and a
  weighted mean means something. Averaging raw margins from different model families
  would not.
* Only **active** tiers contribute to the fused score. A shadow tier is scored and
  reported so its judgement can be compared against the analyst's, but it cannot move
  the number anything acts on. That is what shadow mode is for (M2 §2.3).
* With no active tier, the result is explicitly *undecided* rather than a score of
  zero. Zero means "confidently benign", and silence must never be mistaken for that.

The explanation is carried with the verdict, never derived later, because M2 composes
a Detection with exactly one Explanation - a verdict without one should not exist long
enough to be stored.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from netsentinel_core.features.contract import FlowFeatures
from netsentinel_scoring.registry import LoadedModel

#: Weight per tier in the fused score. Tier A carries most of it because it is the
#: tier trained on labelled benchmark data; the unsupervised tier is a corroborator,
#: not an accuser, since on its own it flags anything unusual including benign change.
DEFAULT_TIER_WEIGHTS: dict[str, float] = {"A": 0.5, "B": 0.3, "C": 0.1, "D": 0.1}


class ScoringError(RuntimeError):
    """Scoring could not be completed."""


@dataclass(slots=True)
class Verdict:
    """One scored flow, with everything needed to justify it."""

    flow_id: str
    # Undecided by default: a Verdict starts with nothing having voted, and that is
    # deliberately distinct from a score of 0.0.
    risk_score: float | None = None
    model_scores: dict[str, float] = field(default_factory=dict)
    shap_values: dict[str, float] = field(default_factory=dict)
    decided_by: list[str] = field(default_factory=list)
    shadow: bool = True
    threshold: float | None = None

    @property
    def is_undecided(self) -> bool:
        """True when no active model contributed; never the same as low risk."""
        return self.risk_score is None

    @property
    def is_alert(self) -> bool:
        if self.risk_score is None or self.threshold is None:
            return False
        return self.risk_score >= self.threshold


class FusionScorer:
    def __init__(
        self,
        models: list[LoadedModel],
        weights: dict[str, float] | None = None,
    ) -> None:
        if not models:
            raise ScoringError("a scorer needs at least one model")
        active_tiers = [model.tier for model in models if model.is_active]
        if len(active_tiers) != len(set(active_tiers)):
            # Weights are per tier, so a second active model of one tier would count
            # that tier twice in the fused score.
            raise ScoringError(f"more than one active model per tier: {active_tiers}")
        self._models = models
        self._weights = weights or DEFAULT_TIER_WEIGHTS
        tiers = [model.tier for model in models]
        # A tier's score is reported as ``tier_x``. A shadow model sharing its tier
        # with another model is reported under its own name instead, so it cannot
        # overwrite the score of the model it is being compared against.
        # With several shadow models and no active one, no model speaks for the tier,
        # so none is reported as ``tier_x``; each is kept under its own name.
        keys = [
            f"tier_{model.tier.lower()}"
            if model.is_active or tiers.count(model.tier) == 1
            else model.name
            for model in models
        ]
        # Two versions of one model share a name; the version tells them apart, so
        # neither score overwrites the other.
        self._keys = [
            f"{model.name}:{model.version}"
            if key == model.name and keys.count(key) > 1
            else key
            for model, key in zip(models, keys)
        ]
        if len(set(self._keys)) != len(self._keys):
            raise ScoringError(f"a model is loaded more than once: {sorted(self._keys)}")

    @property
    def models(self) -> list[LoadedModel]:
        return list(self._models)

    @property
    def has_active_model(self) -> bool:
        return any(model.is_active for model in self._models)

    def _vector_for(self, model: LoadedModel, features: FlowFeatures) -> np.ndarray:
        """Select this tier's inputs, in the order its card declared.

        Built by name from the contract rather than by slicing the full vector, so a
        tier reading a subset cannot silently read the wrong columns.
        """
        missing = [name for name in model.feature_order if name not in features.scalars]
        if missing:
            # The SPLT fields live outside scalars, so a sequence tier reads them
            # from the arrays instead.
            flattened = _flatten(features)
            missing = [name for name in model.feature_order if name not in flattened]
            if missing:
                raise ScoringError(
                    f"tier {model.tier} needs features absent from this flow: {missing}"
                )
            return np.array([[flattened[name] for name in model.feature_order]])
        return np.array([[features.scalars[name] for name in model.feature_order]])

    def score(self, features: FlowFeatures) -> Verdict:
        """Score one flow through every loaded tier."""
        verdict = Verdict(flow_id=str(features.key))

        weighted_total = 0.0
        weight_sum = 0.0
        for model, key in zip(self._models, self._keys):
            probability = float(model.score(self._vector_for(model, features))[0])
            verdict.model_scores[key] = probability

            if not model.is_active:
                continue
            weight = self._weights.get(model.tier, 0.0)
            if weight <= 0:
                continue
            weighted_total += probability * weight
            weight_sum += weight
            verdict.decided_by.append(f"{model.name}:{model.version}")

        if weight_sum == 0:
            # Undecided. Left as None so nothing downstream reads it as "benign".
            return verdict

        verdict.risk_score = weighted_total / weight_sum
        verdict.shadow = False
        # The fused threshold is the weighted mean of the contributing tiers', so a
        # tier calibrated at a stricter cut-off keeps its influence.
        verdict.threshold = sum(
            model.threshold * self._weights.get(model.tier, 0.0)
            for model in self._models
            if model.is_active and self._weights.get(model.tier, 0.0) > 0
        ) / weight_sum
        return verdict

    def explain(self, features: FlowFeatures, contributions: dict[str, float]) -> dict[str, float]:
        """Attach precomputed SHAP contributions, keyed by contract feature name.

        SHAP itself lives in training: TreeSHAP needs the tree structure, not the
        ONNX graph. At serving time the values come from the training-time explainer
        applied to this flow, and this method exists to validate the keys so a
        dashboard can never be handed a feature name the contract does not know.
        """
        known = set(_flatten(features))
        unknown = sorted(set(contributions) - known)
        if unknown:
            raise ScoringError(f"explanation names features outside the contract: {unknown}")
        return dict(contributions)


def _flatten(features: FlowFeatures) -> dict[str, float]:
    """Every contract feature of one flow, by name."""
    from netsentinel_core.features.contract import SPLT_IAT_FIELDS, SPLT_LEN_FIELDS

    flat: dict[str, float] = dict(features.scalars)
    flat.update({name: float(v) for name, v in zip(SPLT_LEN_FIELDS, features.splt_len)})
    flat.update({name: float(v) for name, v in zip(SPLT_IAT_FIELDS, features.splt_iat)})
    return flat
