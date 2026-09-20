"""Loading a model, and refusing to load the wrong one.

This is where the feature contract earns its keep. A model card records the feature
order it was trained on and the SHA-256 of its ONNX file. Both are checked before the
model is allowed to score anything, so the two failures that would otherwise be
silent become loud:

* an artefact that is not the one that was evaluated (hash mismatch),
* a model trained against a different contract than the sensor is producing
  (feature order mismatch) - the exact train/serve skew the whole design guards
  against.

A model that fails either check does not load. Scoring traffic with a model whose
inputs mean something else is worse than not scoring at all, because the output
looks plausible.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import onnxruntime as ort

from netsentinel_core.features.contract import TIER_A_FEATURES, TIER_B_FEATURES

#: Feature order expected per tier, so a card can be checked without guessing.
TIER_FEATURES: dict[str, tuple[str, ...]] = {
    "A": TIER_A_FEATURES,
    "B": TIER_B_FEATURES,
    "D": TIER_A_FEATURES,  # the unsupervised tier scores the same aggregates
}

REQUIRED_CARD_FIELDS = (
    "name",
    "tier",
    "version",
    "onnx_sha256",
    "threshold",
    "mode",
    "feature_order",
)


class ModelLoadError(RuntimeError):
    """A model was refused. The message says which check failed and why."""


#: Calibration methods this serving path knows how to reproduce. A card naming
#: anything else is refused at load rather than at first score, so a model that
#: cannot be served correctly never enters the registry.
SUPPORTED_CALIBRATIONS = frozenset({"platt", "empirical_quantiles"})


def apply_calibration(raw: np.ndarray, calibration: dict | None) -> np.ndarray:
    """Turn a tier's raw output into a probability, per its card."""
    if not calibration:
        return raw

    method = calibration.get("method")
    if method == "platt":
        # Platt scaling was fitted on the raw LightGBM margin, but the ONNX graph
        # emits sigmoid(margin), so the margin is recovered by its logit first.
        probability = np.clip(raw, 1e-12, 1.0 - 1e-12)
        margin = np.log(probability / (1.0 - probability))
        a = float(calibration.get("a", 1.0))
        b = float(calibration.get("b", 0.0))
        return 1.0 / (1.0 + np.exp(-np.clip(a * margin + b, -500.0, 500.0)))

    if method == "empirical_quantiles":
        # The share of benign traffic that looks more normal than this flow.
        levels = calibration["levels"]
        quantiles = calibration["scores"]
        return 1.0 - np.interp(raw, quantiles, levels)

    raise ModelLoadError(f"unsupported calibration method {method!r}")


@dataclass(slots=True)
class LoadedModel:
    """One tier, ready to score."""

    name: str
    tier: str
    version: str
    mode: str
    threshold: float
    feature_order: tuple[str, ...]
    calibration: dict | None
    session: ort.InferenceSession
    input_name: str

    @property
    def is_active(self) -> bool:
        """Active models contribute to the fused score; shadow ones only report."""
        return self.mode == "active"

    def score(self, matrix: np.ndarray) -> np.ndarray:
        """Return one calibrated probability per row.

        Calibration is applied here, not by the caller, because what an ONNX graph
        emits differs by tier: the tree classifier outputs an uncalibrated
        probability, the Isolation Forest an arbitrary-scale decision function.
        Fusion can only average numbers that mean the same thing.
        """
        outputs = self.session.run(None, {self.input_name: matrix.astype(np.float32)})
        raw = np.asarray(outputs[-1])
        if raw.ndim == 2 and raw.shape[1] > 1:
            # Binary classifier: column 1 is the attack probability.
            raw = raw[:, -1]
        return apply_calibration(raw.ravel().astype(np.float64), self.calibration)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_model(card_path: str | Path, onnx_path: str | Path | None = None) -> LoadedModel:
    """Load a model from its card, verifying the artefact and the contract."""
    card_path = Path(card_path)
    try:
        card = json.loads(card_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelLoadError(f"cannot read model card {card_path}: {exc}") from exc

    missing = [field for field in REQUIRED_CARD_FIELDS if field not in card]
    if missing:
        raise ModelLoadError(f"model card {card_path} is missing fields {missing}")

    tier = str(card["tier"])
    if tier not in TIER_FEATURES:
        raise ModelLoadError(f"unknown tier {tier!r} in {card_path}")

    onnx_path = Path(onnx_path) if onnx_path else card_path.parent / f"tier_{tier.lower()}.onnx"
    if not onnx_path.exists():
        raise ModelLoadError(f"ONNX artefact not found at {onnx_path}")

    actual = sha256_of(onnx_path)
    if actual != card["onnx_sha256"]:
        raise ModelLoadError(
            f"{onnx_path.name} does not match its card: card says "
            f"{card['onnx_sha256'][:12]}..., file is {actual[:12]}.... This is not "
            "the artefact that was evaluated; refusing to load it."
        )

    expected = TIER_FEATURES[tier]
    declared = tuple(card["feature_order"])
    if declared != expected:
        raise ModelLoadError(
            f"tier {tier} model {card['name']!r} was trained on a different feature "
            f"contract: card declares {len(declared)} features, this build expects "
            f"{len(expected)}. First difference at "
            f"{_first_difference(declared, expected)}. Retrain or pin the older core."
        )

    calibration = card.get("calibration")
    if calibration:
        method = calibration.get("method")
        if method not in SUPPORTED_CALIBRATIONS:
            raise ModelLoadError(
                f"model {card['name']!r} declares calibration {method!r}, which this "
                f"serving path cannot reproduce. Supported: "
                f"{sorted(SUPPORTED_CALIBRATIONS)}."
            )
        if method == "empirical_quantiles":
            missing_keys = [k for k in ("levels", "scores") if k not in calibration]
            if missing_keys:
                raise ModelLoadError(
                    f"empirical_quantiles calibration is missing {missing_keys}"
                )

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    inputs = session.get_inputs()
    if len(inputs) != 1:
        raise ModelLoadError(f"{onnx_path.name} expects {len(inputs)} inputs, wanted one")

    width = inputs[0].shape[-1]
    if isinstance(width, int) and width != len(expected):
        raise ModelLoadError(
            f"{onnx_path.name} takes {width} features but tier {tier} declares "
            f"{len(expected)}"
        )

    return LoadedModel(
        name=str(card["name"]),
        tier=tier,
        version=str(card["version"]),
        mode=str(card["mode"]),
        threshold=float(card["threshold"]),
        feature_order=expected,
        calibration=calibration,
        session=session,
        input_name=inputs[0].name,
    )


def _first_difference(left: tuple[str, ...], right: tuple[str, ...]) -> str:
    for index, (a, b) in enumerate(zip(left, right)):
        if a != b:
            return f"index {index}: card has {a!r}, contract has {b!r}"
    if len(left) != len(right):
        longer, label = (left, "card") if len(left) > len(right) else (right, "contract")
        return f"index {min(len(left), len(right))}: only the {label} has {longer[min(len(left), len(right))]!r}"
    return "nowhere"
