"""D6 Tier D, second half: a dense autoencoder over flow aggregates (M2 F9).

    python -m netsentinel_training.models.tier_d_ae --data data/processed --out artefacts/tier_d_ae

Like the Isolation Forest in ``tier_d``, it is trained on **benign flows only** and
scores how unfamiliar a flow is; the two differ in what they call unfamiliar. The forest
isolates flows that are rare in some subset of features. The autoencoder learns to
compress and rebuild benign flows through a six-unit bottleneck, so it objects to flows
whose features do not hang together the way benign ones do, even when each value is
common on its own.

It follows the forest's conventions exactly, so the registry serves it with no special
case:

* **The log is inside the graph**, applied as ``Log(Max(x, 0) + 1)`` like the forest's,
  and the standardisation after it is stored as buffers. The ONNX model takes the raw
  contract features.
* **The output is the negated reconstruction error**, the mean squared difference
  between the standardised input and its reconstruction. Negated so that higher means
  more normal, which is the convention of the forest's ``decision_function`` and what
  the ``empirical_quantiles`` calibration in the registry assumes.
* **Calibration and threshold are the forest's**: benign validation scores stored as
  quantiles, flagged at ``1 - TARGET_MAX_FPR``.

Validation benign flows are kept for calibration alone. Early stopping watches a
holdout carved from the training sample instead, so the flows that set the threshold
never influenced the weights.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.data.nf_mapping import LABEL_ATTACK
from netsentinel_training.models.tier_a import LABEL_COLUMN, sha256
from netsentinel_training.models.tier_d import (
    TARGET_MAX_FPR,
    anomaly_probability,
    evaluate,
    fit_quantiles,
    load_benign,
    log_scale,
)

HIDDEN = 32
BOTTLENECK = 6

EPOCHS = 20
BATCH_SIZE = 1024
LEARNING_RATE = 1e-3
#: Stop when the holdout reconstruction error has not improved for this many epochs.
PATIENCE = 3
#: Share of the training sample held out for early stopping.
HOLDOUT_SHARE = 0.1

#: Benign training flows are sampled down to this many. Memory is not the reason - 1.6M
#: rows of 13 float32 features is 83 MB - but epoch time on a laptop CPU is, and a
#: network with a few thousand weights does not need more examples than this.
MAX_TRAIN_ROWS = 1_000_000

#: Both sides compute in float32; reconstruction errors of extreme flows reach the
#: hundreds, where float32 rounding alone is around 1e-5.
ONNX_TOLERANCE = 1e-4

#: Flows timed one per call, as the sensor runs the graph (NFR-01), as in the benchmark.
LATENCY_CALLS = 2000

SEED = 1337


def input_statistics(x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per-feature mean and standard deviation of the log-scaled training flows."""
    logged = log_scale(x)
    mean = logged.mean(axis=0).astype(np.float32)
    std = logged.std(axis=0).astype(np.float32)
    # A constant feature would divide by zero; 1.0 leaves it unscaled.
    std[std < 1e-6] = 1.0
    return mean, std


def build_model(mean: np.ndarray, std: np.ndarray):
    import torch
    from torch import nn

    width = len(TIER_A_FEATURES)

    class FlowAutoencoder(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.register_buffer("mean", torch.tensor(mean, dtype=torch.float32).view(1, -1))
            self.register_buffer("std", torch.tensor(std, dtype=torch.float32).view(1, -1))
            self.encoder = nn.Sequential(
                nn.Linear(width, HIDDEN), nn.ReLU(), nn.Linear(HIDDEN, BOTTLENECK), nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(BOTTLENECK, HIDDEN), nn.ReLU(), nn.Linear(HIDDEN, width)
            )

        def standardise(self, raw: "torch.Tensor") -> "torch.Tensor":
            # tier_d.log_scale, in float32 like the forest graph; the clamp exports as Clip.
            logged = torch.log(torch.clamp(raw, min=0.0) + 1.0)
            return (logged - self.mean) / self.std

        def forward(self, raw: "torch.Tensor") -> "torch.Tensor":
            z = self.standardise(raw)
            error = ((z - self.decoder(self.encoder(z))) ** 2).mean(dim=1)
            return -error

    return FlowAutoencoder()


def _predict(model, x: np.ndarray, batch_size: int = 65536) -> np.ndarray:
    import torch

    model.eval()
    out: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(x), batch_size):
            out.append(model(torch.from_numpy(x[start : start + batch_size])).numpy())
    return np.concatenate(out) if out else np.array([], dtype=np.float32)


def export_onnx(model, path: Path) -> None:
    import torch

    model.eval()
    example = torch.zeros(1, len(TIER_A_FEATURES), dtype=torch.float32)
    torch.onnx.export(
        model,
        (example,),
        str(path),
        input_names=["input"],
        output_names=["score"],
        dynamic_axes={"input": {0: "batch"}, "score": {0: "batch"}},
        # 18 is what the exporter emits; asking for 17 fails to down-convert ReduceMean
        # and leaves the file at 18 anyway.
        opset_version=18,
        # One file: weights in a side .data file would sit outside onnx_sha256.
        external_data=False,
    )


def verify_onnx_parity(model, onnx_path: Path, x: np.ndarray) -> float:
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_out = np.asarray(
        session.run(None, {session.get_inputs()[0].name: x.astype(np.float32)})[0]
    ).ravel()
    return float(np.max(np.abs(onnx_out - _predict(model, x))))


def onnx_latency(onnx_path: Path, x: np.ndarray, calls: int = LATENCY_CALLS) -> dict:
    """NFR-01: milliseconds per call with one flow per call."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    name = session.get_inputs()[0].name
    timings = []
    for row in x[:calls]:
        started = time.perf_counter()
        session.run(None, {name: row.reshape(1, -1)})
        timings.append((time.perf_counter() - started) * 1000)
    return {"p50": float(np.percentile(timings, 50)), "p99": float(np.percentile(timings, 99)),
            "calls": len(timings)}


def per_family(families: np.ndarray, y: np.ndarray, flagged: np.ndarray) -> dict[str, float]:
    """Recall within each attack family."""
    attack = y == 1
    return {
        str(family): float(flagged[attack & (families == family)].mean())
        for family in sorted(set(families[attack]))
    }


def fit_autoencoder(x_train: np.ndarray, epochs: int = EPOCHS):
    """Fit on log-scaled, standardised benign flows; early-stop on a training holdout."""
    import torch

    rng = np.random.default_rng(SEED)
    order = rng.permutation(len(x_train))
    cut = max(1, int(len(order) * HOLDOUT_SHARE))
    x_fit, x_hold = x_train[order[cut:]], x_train[order[:cut]]

    torch.manual_seed(SEED)
    model = build_model(*input_statistics(x_fit))
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    fit_x = torch.from_numpy(x_fit)

    best_loss, best_state, since_best = float("inf"), None, 0
    for epoch in range(epochs):
        model.train()
        permutation = torch.randperm(len(fit_x))
        for start in range(0, len(permutation), BATCH_SIZE):
            optimiser.zero_grad()
            # The forward pass is already the per-flow error, negated.
            loss = -model(fit_x[permutation[start : start + BATCH_SIZE]]).mean()
            loss.backward()
            optimiser.step()

        hold_loss = float(-_predict(model, x_hold).mean())
        print(f"  epoch {epoch + 1}: holdout reconstruction error {hold_loss:.4f}")
        if hold_loss < best_loss:
            best_loss, since_best = hold_loss, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            since_best += 1
            if since_best >= PATIENCE:
                break

    model.load_state_dict(best_state)
    model.eval()
    return model, {"fit": len(x_fit), "holdout": len(x_hold), "epochs_run": epoch + 1}


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0",
          epochs: int = EPOCHS) -> dict:
    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    x_available = load_benign(data_dir, "train")
    if len(x_available) > MAX_TRAIN_ROWS:
        keep = np.random.default_rng(SEED).choice(len(x_available), MAX_TRAIN_ROWS, replace=False)
        x_train = x_available[np.sort(keep)]
    else:
        x_train = x_available
    x_val_benign = load_benign(data_dir, "val")
    test = pl.read_parquet(data_dir / "test.parquet")
    x_test = test.select(TIER_A_FEATURES).to_numpy().astype(np.float32)
    y_test = test.get_column(LABEL_COLUMN).to_numpy().astype(np.int8)
    print(f"training on {len(x_train):,} of {len(x_available):,} benign flows")

    model, fit_rows = fit_autoencoder(x_train, epochs)

    # Calibrated on validation benign flows, which neither fitted nor early-stopped it.
    levels, quantiles = fit_quantiles(_predict(model, x_val_benign))
    threshold = 1.0 - TARGET_MAX_FPR
    probabilities = anomaly_probability(_predict(model, x_test), levels, quantiles)
    metrics = evaluate(probabilities, y_test, threshold)
    family_recall = (
        per_family(test.get_column(LABEL_ATTACK).to_numpy(), y_test, probabilities >= threshold)
        if LABEL_ATTACK in test.columns else {}
    )

    # Named for the tier, as the registry looks for tier_<tier>.onnx beside the card.
    onnx_path = out_dir / "tier_d.onnx"
    export_onnx(model, onnx_path)
    max_drift = verify_onnx_parity(model, onnx_path, x_test[:5000])
    if max_drift > ONNX_TOLERANCE:
        raise RuntimeError(
            f"ONNX export disagrees with PyTorch by {max_drift:.3e} "
            f"(tolerance {ONNX_TOLERANCE:.0e})"
        )
    latency = onnx_latency(onnx_path, x_test)

    card = {
        "name": "tier_d_autoencoder",
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
        "architecture": {"hidden": HIDDEN, "bottleneck": BOTTLENECK,
                         "output": "negated mean squared reconstruction error"},
        "input": "log1p",
        "epochs_run": fit_rows["epochs_run"],
        "rows": {"train_benign": len(x_train), "train_benign_available": len(x_available),
                 "early_stop_holdout": fit_rows["holdout"], "val_benign": len(x_val_benign),
                 "test": len(x_test)},
        "metrics_test": metrics,
        "family_recall_test": family_recall,
        "latency_ms": latency,
        "onnx_max_abs_drift": max_drift,
        "trained_on": "benign flows only",
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"threshold {threshold:.4f} (analytic, from a {TARGET_MAX_FPR:.1%} budget)")
    print(f"on test: FPR {metrics['false_positive_rate']:.4f}  recall {metrics['recall']:.4f}")
    if "pr_auc" in metrics:
        print(f"PR-AUC {metrics['pr_auc']:.4f}  ROC-AUC {metrics['roc_auc']:.4f}")
    print(f"ONNX max drift {max_drift:.2e}; latency p50 {latency['p50']:.3f} ms "
          f"p99 {latency['p99']:.3f} ms")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Tier D autoencoder")
    parser.add_argument("--data", default="data/processed")
    parser.add_argument("--out", default="artefacts/tier_d_ae")
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    train(args.data, args.out, args.version)


if __name__ == "__main__":
    main()
