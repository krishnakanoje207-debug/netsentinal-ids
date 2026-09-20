"""D6 Tier D: unsupervised anomaly detection over flow aggregates.

    python -m netsentinel_training.models.tier_d --data data/processed --out artefacts/tier_d

Trained on **benign flows only**, so it needs no attack labels and can be retrained
on the lab's own traffic. That is the point of having it: the supervised tiers can
only recognise attacks resembling their training data, and this one objects to
anything unfamiliar.

M2 pairs an Isolation Forest with an autoencoder. This module is the forest half. The
autoencoder needs PyTorch, which is not installed on the laptop by design, so it
belongs in the Kaggle notebook alongside tiers B and C.

**Calibration.** ``decision_function`` is an arbitrary scale, so the benign score
distribution is stored as quantiles and a flow's score becomes the fraction of benign
traffic that looks more normal than it. That reading is directly meaningful to an
analyst, and it makes the decision threshold analytic: benign scores map to a uniform
distribution, so flagging at ``1 - target_fpr`` yields exactly that false-positive
rate by construction rather than by search.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_a import LABEL_COLUMN, sha256

#: Share of benign traffic we accept flagging, matching Tier A's budget.
TARGET_MAX_FPR = 0.01

#: Resolution of the stored benign distribution. 101 points is every percentile,
#: which is ample for interpolation and keeps the model card small.
QUANTILE_COUNT = 101

#: skl2onnx and onnxruntime disagree about ai.onnx.ml v4, so the domain is pinned.
TARGET_OPSET = {"": 15, "ai.onnx.ml": 3}

ONNX_TOLERANCE = 1e-4

FOREST_PARAMS = dict(
    n_estimators=200,
    max_samples=256,  # the value the Isolation Forest paper recommends
    contamination="auto",
    random_state=1337,
    n_jobs=-1,
)


def load_benign(data_dir: Path, name: str) -> np.ndarray:
    """Read one split and keep only the benign rows."""
    frame = pl.read_parquet(data_dir / f"{name}.parquet")
    missing = [f for f in TIER_A_FEATURES if f not in frame.columns]
    if missing:
        raise ValueError(f"{name}.parquet is missing features {missing}")
    benign = frame.filter(pl.col(LABEL_COLUMN) == 0)
    if benign.height == 0:
        raise ValueError(f"{name}.parquet contains no benign rows to learn from")
    return benign.select(TIER_A_FEATURES).to_numpy().astype(np.float32)


def load_labelled(data_dir: Path, name: str) -> tuple[np.ndarray, np.ndarray]:
    """Read one split whole, for measuring recall on attacks we never trained on."""
    frame = pl.read_parquet(data_dir / f"{name}.parquet")
    x = frame.select(TIER_A_FEATURES).to_numpy().astype(np.float32)
    y = frame.get_column(LABEL_COLUMN).to_numpy().astype(np.int8)
    return x, y


def fit_quantiles(benign_scores: np.ndarray) -> tuple[list[float], list[float]]:
    """Describe the benign score distribution as (levels, scores).

    Levels are the cumulative probabilities; scores are the matching
    decision_function values, ascending.
    """
    levels = np.linspace(0.0, 1.0, QUANTILE_COUNT)
    scores = np.quantile(benign_scores, levels)
    return levels.tolist(), scores.tolist()


def anomaly_probability(
    raw_scores: np.ndarray, levels: list[float], quantiles: list[float]
) -> np.ndarray:
    """Map decision_function values onto "more anomalous than this share of benign".

    ``decision_function`` is higher for more normal points, so the result is
    ``1 - ECDF(score)``: near 1 for a flow stranger than almost all benign traffic.
    """
    ecdf = np.interp(raw_scores, quantiles, levels)
    return 1.0 - ecdf


def evaluate(probabilities: np.ndarray, y: np.ndarray, threshold: float) -> dict[str, float]:
    from sklearn.metrics import average_precision_score, roc_auc_score

    flagged = probabilities >= threshold
    benign, attack = y == 0, y == 1
    metrics = {
        "false_positive_rate": float(flagged[benign].mean()) if benign.any() else 0.0,
        "recall": float(flagged[attack].mean()) if attack.any() else 0.0,
        "flagged_share": float(flagged.mean()),
    }
    # Only meaningful when the evaluation split has both classes.
    if benign.any() and attack.any():
        metrics["pr_auc"] = float(average_precision_score(y, probabilities))
        metrics["roc_auc"] = float(roc_auc_score(y, probabilities))
    return metrics


def export_onnx(model, sample: np.ndarray, path: Path) -> None:
    from skl2onnx import to_onnx

    onnx_model = to_onnx(model, sample[:1], target_opset=TARGET_OPSET)
    path.write_bytes(onnx_model.SerializeToString())


def verify_onnx_parity(model, onnx_path: Path, x: np.ndarray) -> float:
    """Largest disagreement between the ONNX graph and scikit-learn."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    outputs = session.run(None, {session.get_inputs()[0].name: x.astype(np.float32)})
    # Two outputs: the label, then the decision_function scores.
    onnx_scores = np.asarray(outputs[-1]).ravel()
    return float(np.max(np.abs(onnx_scores - model.decision_function(x))))


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0") -> dict:
    from sklearn.ensemble import IsolationForest

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    x_train = load_benign(data_dir, "train")
    x_val_benign = load_benign(data_dir, "val")
    x_test, y_test = load_labelled(data_dir, "test")
    print(f"training on {len(x_train):,} benign flows")

    model = IsolationForest(**FOREST_PARAMS).fit(x_train)

    # Calibrated on validation, never on the data the forest was fitted to: training
    # scores are optimistic and would put the threshold in the wrong place.
    levels, quantiles = fit_quantiles(model.decision_function(x_val_benign))

    threshold = 1.0 - TARGET_MAX_FPR
    probabilities = anomaly_probability(model.decision_function(x_test), levels, quantiles)
    metrics = evaluate(probabilities, y_test, threshold)

    onnx_path = out_dir / "tier_d.onnx"
    export_onnx(model, x_train, onnx_path)
    max_drift = verify_onnx_parity(model, onnx_path, x_test[:5000])
    if max_drift > ONNX_TOLERANCE:
        raise RuntimeError(
            f"ONNX export disagrees with scikit-learn by {max_drift:.3e} "
            f"(tolerance {ONNX_TOLERANCE:.0e})"
        )

    card = {
        "name": "tier_d_isolation_forest",
        "tier": "D",
        "version": version,
        "onnx_sha256": sha256(onnx_path),
        "threshold": threshold,
        "mode": "shadow",
        "pr_auc": metrics.get("pr_auc"),
        "feature_order": list(TIER_A_FEATURES),
        "calibration": {
            "method": "empirical_quantiles",
            "levels": levels,
            "scores": quantiles,
        },
        "target_max_fpr": TARGET_MAX_FPR,
        "trees": FOREST_PARAMS["n_estimators"],
        "rows": {"train_benign": len(x_train), "val_benign": len(x_val_benign),
                 "test": len(x_test)},
        "metrics_test": metrics,
        "onnx_max_abs_drift": max_drift,
        # Recorded because it is the honest caveat: the forest never saw an attack,
        # so this number is what unfamiliarity alone achieves.
        "trained_on": "benign flows only",
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"threshold {threshold:.4f} (analytic, from a {TARGET_MAX_FPR:.1%} budget)")
    print(f"on test: FPR {metrics['false_positive_rate']:.4f}  recall {metrics['recall']:.4f}")
    if "pr_auc" in metrics:
        print(f"PR-AUC {metrics['pr_auc']:.4f}  ROC-AUC {metrics['roc_auc']:.4f}")
    print(f"ONNX max drift {max_drift:.2e}")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Tier D Isolation Forest")
    parser.add_argument("--data", default="data/processed")
    parser.add_argument("--out", default="artefacts/tier_d")
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    train(args.data, args.out, args.version)


if __name__ == "__main__":
    main()
