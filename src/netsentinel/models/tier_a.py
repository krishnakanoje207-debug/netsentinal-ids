"""D5 Tier A: gradient-boosted trees over flow aggregates.

    python -m netsentinel.models.tier_a --data data/processed --out artefacts/tier_a

Produces the two things the schedule asks of D5 - a PR-AUC report and an ONNX
model whose predictions match the native ones - plus the model card that fills
an ml_models row.

Design notes worth knowing before changing anything here:

* PR-AUC is the headline metric, not accuracy or ROC-AUC. Attack flows are a
  small minority, and on a heavily imbalanced problem accuracy is flattering and
  ROC-AUC is optimistic; precision-recall is what a SOC actually feels.
* Calibration is Platt scaling on the raw margin, two floats stored in the model
  card, rather than an sklearn calibration wrapper. It keeps the exported ONNX
  graph to just the tree ensemble, and two floats travel into the ml_models row
  and get applied at inference in one line.
* The decision threshold is chosen on validation to respect a false-positive
  budget, not to maximise F1. An IDS that cries wolf gets muted, so the
  constraint that matters is how much noise an analyst will tolerate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel.features.contract import TIER_A_FEATURES

#: Share of benign flows we are willing to raise as alerts. The threshold is the
#: strictest one meeting this budget on validation data.
TARGET_MAX_FPR = 0.01

#: ONNX runs the tree ensemble in float32 while LightGBM scores in float64, so
#: exact equality is not achievable; this is the "ONNX == native" tolerance.
ONNX_TOLERANCE = 1e-4

LABEL_COLUMN = "Label"

LGBM_PARAMS = dict(
    objective="binary",
    n_estimators=600,
    learning_rate=0.05,
    num_leaves=63,
    min_child_samples=50,
    subsample=0.8,
    subsample_freq=1,
    colsample_bytree=0.8,
    reg_lambda=1.0,
    n_jobs=-1,
    verbose=-1,
)


def load_split(data_dir: Path, name: str) -> tuple[np.ndarray, np.ndarray]:
    """Read one split as (X, y), columns in contract order."""
    frame = pl.read_parquet(data_dir / f"{name}.parquet")
    missing = [f for f in TIER_A_FEATURES if f not in frame.columns]
    if missing:
        raise ValueError(f"{name}.parquet is missing Tier A features {missing}")
    x = frame.select(TIER_A_FEATURES).to_numpy().astype(np.float32)
    y = frame.get_column(LABEL_COLUMN).to_numpy().astype(np.int8)
    return x, y


def fit_platt(margins: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    """Platt scaling: logistic regression of the label on the raw margin."""
    from sklearn.linear_model import LogisticRegression

    scaler = LogisticRegression(C=1e10, solver="lbfgs")
    scaler.fit(margins.reshape(-1, 1), y)
    return float(scaler.coef_[0][0]), float(scaler.intercept_[0])


def apply_platt(margins: np.ndarray, a: float, b: float) -> np.ndarray:
    """The one line that reproduces calibration at inference time.

    Clipped because a confident tree ensemble emits margins large enough to
    overflow exp(); the clip is far outside any range that changes a probability.
    """
    return 1.0 / (1.0 + np.exp(-np.clip(a * margins + b, -500.0, 500.0)))


def choose_threshold(probs: np.ndarray, y: np.ndarray,
                     target_max_fpr: float = TARGET_MAX_FPR) -> float:
    """Highest recall available within the false-positive budget."""
    from sklearn.metrics import roc_curve

    fpr, tpr, thresholds = roc_curve(y, probs)
    affordable = fpr <= target_max_fpr
    if not affordable.any():
        return 1.0
    best = int(np.argmax(np.where(affordable, tpr, -1.0)))
    return float(thresholds[best])


def evaluate(probs: np.ndarray, y: np.ndarray, threshold: float) -> dict[str, float]:
    from sklearn.metrics import (
        average_precision_score,
        brier_score_loss,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
        roc_auc_score,
    )

    predicted = (probs >= threshold).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y, predicted, labels=[0, 1]).ravel()
    return {
        "pr_auc": float(average_precision_score(y, probs)),
        "roc_auc": float(roc_auc_score(y, probs)),
        "brier": float(brier_score_loss(y, probs)),
        "precision": float(precision_score(y, predicted, zero_division=0)),
        "recall": float(recall_score(y, predicted, zero_division=0)),
        "f1": float(f1_score(y, predicted, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_negatives": int(tn),
    }


def global_shap(model, x: np.ndarray, sample: int = 2000) -> dict[str, float]:
    """Mean absolute TreeSHAP value per feature, on a capped sample.

    Capped because SHAP is the memory-hungry step and this has to stay runnable
    on a small host; global importance is stable well before the full test set.
    """
    import shap

    subset = x[: min(sample, len(x))]
    explainer = shap.TreeExplainer(model.booster_)
    values = explainer.shap_values(subset)
    if isinstance(values, list):  # older SHAP returns one array per class
        values = values[1]
    importance = np.abs(values).mean(axis=0)
    ranked = sorted(zip(TIER_A_FEATURES, importance), key=lambda kv: -kv[1])
    return {name: float(value) for name, value in ranked}


def export_onnx(model, n_features: int, path: Path) -> None:
    from onnxmltools import convert_lightgbm
    from onnxmltools.convert.common.data_types import FloatTensorType

    # target_opset is left to the converter: it caps at what the installed onnx
    # supports, and pinning a higher number fails outright. Kaggle and the VM will
    # not carry identical versions.
    onnx_model = convert_lightgbm(
        model,
        initial_types=[("input", FloatTensorType([None, n_features]))],
        zipmap=False,
    )
    path.write_bytes(onnx_model.SerializeToString())


def verify_onnx_parity(model, onnx_path: Path, x: np.ndarray) -> float:
    """Return the largest probability disagreement between ONNX and LightGBM.

    This is the D5 exit criterion. A regression here means the served model is
    not the model that was evaluated.
    """
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    outputs = session.run(None, {"input": x.astype(np.float32)})
    # Output 0 is the label, output 1 the probabilities.
    onnx_probs = np.asarray(outputs[1])
    if onnx_probs.ndim == 2:
        onnx_probs = onnx_probs[:, 1]
    native_probs = model.predict_proba(x)[:, 1]
    return float(np.max(np.abs(onnx_probs - native_probs)))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0") -> dict:
    """Train, calibrate, evaluate, explain and export. Returns the model card."""
    import lightgbm as lgb

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    x_train, y_train = load_split(data_dir, "train")
    x_val, y_val = load_split(data_dir, "val")
    x_test, y_test = load_split(data_dir, "test")

    positives = int(y_train.sum())
    negatives = int(len(y_train) - positives)
    if positives == 0 or negatives == 0:
        raise ValueError(
            f"training split has only one class (pos={positives}, neg={negatives}); "
            "the split is unusable"
        )
    print(f"train {len(y_train):,} rows ({positives:,} attack / {negatives:,} benign)")

    model = lgb.LGBMClassifier(
        **LGBM_PARAMS,
        # Rebalance rather than resample: keeps every benign flow in training,
        # which matters because benign variety is what suppresses false positives.
        scale_pos_weight=negatives / positives,
    )
    model.fit(
        x_train,
        y_train,
        # eval_set rather than the newer eval_X / eval_y: it works on every
        # LightGBM 4.x, and Kaggle will not be on the same version as this venv.
        eval_set=[(x_val, y_val)],
        eval_metric="average_precision",
        callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(0)],
    )
    print(f"stopped at {model.best_iteration_ or model.n_estimators} trees")

    margin_val = model.booster_.predict(x_val, raw_score=True)
    margin_test = model.booster_.predict(x_test, raw_score=True)
    a, b = fit_platt(margin_val, y_val)

    probs_val = apply_platt(margin_val, a, b)
    probs_test = apply_platt(margin_test, a, b)
    threshold = choose_threshold(probs_val, y_val)

    metrics = evaluate(probs_test, y_test, threshold)
    uncalibrated = evaluate(model.predict_proba(x_test)[:, 1], y_test, threshold)

    onnx_path = out_dir / "tier_a.onnx"
    export_onnx(model, x_train.shape[1], onnx_path)
    max_drift = verify_onnx_parity(model, onnx_path, x_test[:5000])
    if max_drift > ONNX_TOLERANCE:
        raise RuntimeError(
            f"ONNX export disagrees with LightGBM by {max_drift:.3e} "
            f"(tolerance {ONNX_TOLERANCE:.0e}); the served model would not be "
            "the model that was evaluated"
        )

    card = {
        "name": "tier_a_lightgbm",
        "tier": "A",
        "version": version,
        "onnx_sha256": sha256(onnx_path),
        "threshold": threshold,
        "mode": "shadow",
        "pr_auc": metrics["pr_auc"],
        "feature_order": list(TIER_A_FEATURES),
        "calibration": {"method": "platt", "a": a, "b": b},
        "target_max_fpr": TARGET_MAX_FPR,
        "trees": int(model.best_iteration_ or model.n_estimators),
        "rows": {"train": len(y_train), "val": len(y_val), "test": len(y_test)},
        "class_balance_train": {"attack": positives, "benign": negatives},
        "metrics_test": metrics,
        "metrics_test_uncalibrated": uncalibrated,
        "onnx_max_abs_drift": max_drift,
        "shap_global": global_shap(model, x_test),
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"PR-AUC {metrics['pr_auc']:.4f}  ROC-AUC {metrics['roc_auc']:.4f}")
    print(f"at threshold {threshold:.4f}: precision {metrics['precision']:.4f} "
          f"recall {metrics['recall']:.4f} FPR {metrics['false_positive_rate']:.4f}")
    print(f"Brier {uncalibrated['brier']:.4f} -> {metrics['brier']:.4f} after calibration")
    print(f"ONNX max drift {max_drift:.2e} (tolerance {ONNX_TOLERANCE:.0e})")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Tier A LightGBM model")
    parser.add_argument("--data", default="data/processed", help="dir with the split Parquet files")
    parser.add_argument("--out", default="artefacts/tier_a", help="artefact output dir")
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    train(args.data, args.out, args.version)


if __name__ == "__main__":
    main()
