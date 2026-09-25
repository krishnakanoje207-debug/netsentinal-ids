"""The MITRE technique on an ML alert, from the family model.

Signature alerts arrive with a technique because a rule author wrote one down. An ML
verdict has only a score, so the writer asks the family model (training/models/family)
which kind of attack the flow looks like and maps that to ATT&CK - but only when the
model is confident and only for families with a single, defensible technique. Every
other alert keeps ``mitre_technique`` null, which the dashboard shows as not identified
rather than as a guess.

Loaded the way the explainer is: the booster must match the hash in its card, and the
card's feature order must be the contract's, so a technique can never come from a model
reading different columns than the one that raised the alert.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from netsentinel_core.features.contract import FEATURE_ORDER

from netsentinel_writer.explain import sha256_of

REQUIRED_CARD_FIELDS = (
    "name", "version", "booster_sha256", "feature_order", "classes", "min_confidence",
    "techniques",
)


class LabellerError(RuntimeError):
    """The family model was refused, or a flow could not be labelled."""


@dataclass(slots=True, frozen=True)
class Label:
    family: str
    confidence: float
    technique: str | None


@dataclass(slots=True)
class Labeller:
    name: str
    version: str
    feature_order: tuple[str, ...]
    classes: tuple[str, ...]
    min_confidence: float
    techniques: dict[str, str]
    booster: Any
    #: Added to each class's log-probability before the argmax and the confidence, as in
    #: training (family.apply_bias). Empty for a card that predates it.
    class_bias: tuple[float, ...] = ()

    def label(self, flow: Mapping[str, Any]) -> Label:
        """The most likely family, how sure, and the technique if it may be claimed."""
        import numpy as np

        missing = [name for name in self.feature_order if name not in flow]
        if missing:
            raise LabellerError(f"flow is missing features the family model reads: {missing}")
        vector = np.array([[float(flow[name]) for name in self.feature_order]])
        probs = self.booster.predict(vector)[0]
        if self.class_bias:
            logits = np.log(np.clip(probs, 1e-12, 1.0)) + np.asarray(self.class_bias)
            probs = np.exp(logits - logits.max())
            probs /= probs.sum()
        best = int(np.argmax(probs))
        family, confidence = self.classes[best], float(probs[best])
        technique = self.techniques.get(family) if confidence >= self.min_confidence else None
        return Label(family=family, confidence=confidence, technique=technique)


def load_labeller(card_path: str | Path) -> Labeller:
    card_path = Path(card_path)
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LabellerError(f"cannot read family model card {card_path}: {exc}") from exc

    missing = [field for field in REQUIRED_CARD_FIELDS if field not in card]
    if missing:
        raise LabellerError(f"family model card {card_path} is missing fields {missing}")

    unknown = [name for name in card["feature_order"] if name not in FEATURE_ORDER]
    if unknown:
        raise LabellerError(f"family model reads features outside the contract: {unknown}")

    booster_path = card_path.parent / "family.lgb.txt"
    if not booster_path.exists():
        raise LabellerError(f"no booster at {booster_path}")
    actual = sha256_of(booster_path)
    if actual != card["booster_sha256"]:
        raise LabellerError(
            f"{booster_path.name} does not match its card (card {card['booster_sha256'][:12]}..., "
            f"file {actual[:12]}...). A technique from this file would come from an "
            "unevaluated model."
        )

    import lightgbm as lgb

    booster = lgb.Booster(model_file=str(booster_path))
    # A multiclass booster grows one tree per class each iteration.
    if booster.num_model_per_iteration() != len(card["classes"]):
        raise LabellerError(
            f"booster predicts {booster.num_model_per_iteration()} classes; "
            f"the card names {len(card['classes'])}"
        )
    class_bias = tuple(float(v) for v in card.get("class_bias", ()))
    if class_bias and len(class_bias) != len(card["classes"]):
        raise LabellerError(
            f"family model card has {len(class_bias)} class biases for "
            f"{len(card['classes'])} classes"
        )
    return Labeller(
        name=str(card["name"]),
        version=str(card["version"]),
        feature_order=tuple(card["feature_order"]),
        classes=tuple(card["classes"]),
        min_confidence=float(card["min_confidence"]),
        techniques=dict(card["techniques"]),
        booster=booster,
        class_bias=class_bias,
    )
