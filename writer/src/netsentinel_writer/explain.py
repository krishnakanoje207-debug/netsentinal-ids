"""Per-detection explanation, from the tree structure ONNX does not carry.

The sensor scores through ONNX and publishes the feature vector. It cannot explain
what it did: TreeSHAP walks the trees, and an ONNX graph is a computation, not a
forest. So the native LightGBM booster is kept beside the ONNX at training time and
read here.

That split is also why this package exists at all. LightGBM must not be importable
from the API - the whole workspace layout is arranged so it cannot be - and the
sensor is meant to stay installable on a constrained host with no compiler.

Contributions come from LightGBM's own ``pred_contrib``, not from the ``shap``
package. It is the same TreeSHAP algorithm, it is already in the wheel, and this
runs per detection rather than once per training run, so the lighter path wins.

Two things are checked before a single flow is explained:

* the booster file matches the SHA-256 in its card, exactly as the ONNX does at
  scoring time, so a detection cannot be explained by a different model than the
  one that scored it;
* every name in the card's feature order is a name the contract knows, because a
  contribution labelled with the wrong feature is worse than no explanation - it
  reads as an answer.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from netsentinel_core.features.contract import FEATURE_ORDER

REQUIRED_CARD_FIELDS = ("name", "tier", "version", "threshold", "feature_order")


class ExplainerError(RuntimeError):
    """An explainer was refused, or a flow could not be explained."""


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(slots=True)
class Explainer:
    """One tree model, ready to attribute a score to features."""

    name: str
    tier: str
    version: str
    threshold: float
    feature_order: tuple[str, ...]
    booster: Any

    @property
    def identity(self) -> str:
        """``name:version``, which is how a verdict names the models that scored."""
        return f"{self.name}:{self.version}"

    def explain(self, flow: Mapping[str, Any]) -> dict[str, float]:
        """SHAP contribution per feature for one flow, keyed by contract name.

        The flow row comes off the bus with the exact values that produced the
        verdict, so nothing is re-derived from packets here - that would be a second
        place for the feature contract to drift.
        """
        import numpy as np

        missing = [name for name in self.feature_order if name not in flow]
        if missing:
            raise ExplainerError(
                f"flow is missing features this model reads: {missing}"
            )

        try:
            vector = np.array([[float(flow[name]) for name in self.feature_order]])
        except (TypeError, ValueError) as exc:
            raise ExplainerError(f"flow carries a non-numeric feature: {exc}") from exc

        # pred_contrib returns one column per feature plus a trailing base value -
        # the model's expected output before any feature moved it. The dashboard
        # renders contract features only, so the base value is dropped rather than
        # smuggled in as a feature name nobody could look up.
        contributions = self.booster.predict(vector, pred_contrib=True)[0]
        expected = len(self.feature_order) + 1
        if len(contributions) != expected:
            raise ExplainerError(
                f"booster returned {len(contributions)} contributions for "
                f"{len(self.feature_order)} features; expected {expected}"
            )
        return {
            name: float(value)
            for name, value in zip(self.feature_order, contributions[:-1])
        }


def load_explainer(card_path: str | Path, booster_path: str | Path | None = None) -> Explainer:
    """Load a tier's booster from its card, verifying the artefact and the names."""
    card_path = Path(card_path)
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ExplainerError(f"cannot read model card {card_path}: {exc}") from exc

    missing = [field for field in REQUIRED_CARD_FIELDS if field not in card]
    if missing:
        raise ExplainerError(f"model card {card_path} is missing fields {missing}")

    tier = str(card["tier"])
    booster_path = (
        Path(booster_path)
        if booster_path
        else card_path.parent / f"tier_{tier.lower()}.lgb.txt"
    )
    if not booster_path.exists():
        raise ExplainerError(
            f"no booster at {booster_path}. Training saves it beside the ONNX; a "
            "model trained before that cannot explain a detection and must be "
            "retrained rather than served unexplained."
        )

    declared = card.get("booster_sha256")
    if not declared:
        raise ExplainerError(
            f"model card {card_path} does not pin booster_sha256, so the file on "
            "disk cannot be shown to be the one that was evaluated"
        )
    actual = sha256_of(booster_path)
    if actual != declared:
        raise ExplainerError(
            f"{booster_path.name} does not match its card: card says "
            f"{str(declared)[:12]}..., file is {actual[:12]}.... An explanation from "
            "this file would describe a different model than the one that scored."
        )

    feature_order = tuple(str(name) for name in card["feature_order"])
    unknown = [name for name in feature_order if name not in FEATURE_ORDER]
    if unknown:
        raise ExplainerError(
            f"model card {card_path} names features outside the contract: {unknown}"
        )

    import lightgbm as lgb

    try:
        booster = lgb.Booster(model_file=str(booster_path))
    except Exception as exc:  # lightgbm raises its own error types
        raise ExplainerError(f"cannot load booster {booster_path}: {exc}") from exc

    width = booster.num_feature()
    if width != len(feature_order):
        raise ExplainerError(
            f"{booster_path.name} takes {width} features but the card declares "
            f"{len(feature_order)}; the contributions would be misnamed"
        )

    return Explainer(
        name=str(card["name"]),
        tier=tier,
        version=str(card["version"]),
        threshold=float(card["threshold"]),
        feature_order=feature_order,
        booster=booster,
    )
