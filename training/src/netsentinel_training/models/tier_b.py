"""D6 Tier B: a 1D-CNN + BiLSTM over the packet sequence.

    python -m netsentinel_training.models.tier_b --data data/pcap --out artefacts/tier_b

Where Tier A reads flow aggregates - totals, rates, durations - this tier reads the shape
of the first twenty packets: how big each was, which direction it went, and how long the
gap was. That is what separates a port scan from a page load when both are short and
small, and it is available before a flow finishes, which is the point of early detection.

Trained on capture-derived data from ``pcap_prep``, never on NF-* CSVs: those are
pre-aggregated and carry no per-packet detail at all.

Three decisions worth knowing before changing anything:

* **Normalisation lives inside the model.** Packet lengths reach ~1500 and inter-arrival
  gaps are unbounded, so the inputs must be scaled - but a scaler applied outside the
  graph is a second artefact to ship, version and get wrong. Here the statistics are
  buffers, so they export into the ONNX file and the serving path does nothing special.
* **Padding is masked.** A flow shorter than twenty packets is zero-padded, and an LSTM
  fed those zeros ends with a hidden state describing the padding. Pooling is over real
  packets only.
* **The model outputs a probability, not a logit**, so Platt calibration at serving time
  works exactly as it does for Tier A and the registry needs no per-tier special case.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import (
    SPLT_IAT_FIELDS,
    SPLT_LEN_FIELDS,
    SPLT_N,
    TIER_B_FEATURES,
)
from netsentinel_training.models.tier_a import (
    LABEL_COLUMN,
    TARGET_MAX_FPR,
    apply_platt,
    choose_threshold,
    evaluate,
    fit_platt,
    sha256,
)

#: Two channels: signed packet length, and inter-arrival time in milliseconds.
CHANNELS = 2

ONNX_TOLERANCE = 1e-4

EPOCHS = 40
BATCH_SIZE = 256
LEARNING_RATE = 1e-3
#: Stop when validation average precision has not improved for this many epochs.
PATIENCE = 6


def load_split(data_dir: Path, name: str) -> tuple[np.ndarray, np.ndarray]:
    """Read one split as (X, y) with columns in TIER_B_FEATURES order."""
    frame = pl.read_parquet(data_dir / f"{name}.parquet")
    missing = [f for f in TIER_B_FEATURES if f not in frame.columns]
    if missing:
        raise ValueError(
            f"{name}.parquet is missing sequence features {missing}. Tier B needs "
            "capture-derived data; NF-* CSVs cannot supply it."
        )
    x = frame.select(TIER_B_FEATURES).to_numpy().astype(np.float32)
    y = frame.get_column(LABEL_COLUMN).to_numpy().astype(np.float32)
    return x, y


def build_model(mean: np.ndarray, std: np.ndarray):
    """The network, with normalisation statistics baked in as buffers."""
    import torch
    from torch import nn

    class EarlyFlowClassifier(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            # (1, CHANNELS, 1) so they broadcast over batch and time.
            self.register_buffer("mean", torch.tensor(mean, dtype=torch.float32).view(1, CHANNELS, 1))
            self.register_buffer("std", torch.tensor(std, dtype=torch.float32).view(1, CHANNELS, 1))

            self.conv = nn.Sequential(
                nn.Conv1d(CHANNELS, 32, kernel_size=3, padding=1),
                nn.ReLU(),
                nn.Conv1d(32, 64, kernel_size=3, padding=1),
                nn.ReLU(),
            )
            self.lstm = nn.LSTM(64, 64, batch_first=True, bidirectional=True)
            self.head = nn.Sequential(nn.Dropout(0.2), nn.Linear(128, 1))

        def forward(self, flat: "torch.Tensor") -> "torch.Tensor":
            # (B, 40) -> (B, 2, 20): first SPLT_N are lengths, the rest inter-arrivals.
            lengths = flat[:, :SPLT_N]
            gaps = flat[:, SPLT_N:]
            x = torch.stack([lengths, gaps], dim=1)

            # A padded slot has length exactly zero; a real IPv4 packet never does.
            mask = (lengths != 0).to(x.dtype).unsqueeze(-1)  # (B, T, 1)

            x = (x - self.mean) / self.std
            x = self.conv(x)
            x = x.transpose(1, 2)  # (B, T, 64)
            x, _ = self.lstm(x)  # (B, T, 128)

            # Mean over real packets only, so a three-packet flow is not described by
            # seventeen slots of padding.
            pooled = (x * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
            logit = self.head(pooled).squeeze(-1)
            return torch.sigmoid(logit)

    return EarlyFlowClassifier()


def channel_statistics(x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per-channel mean and standard deviation, over real packets only.

    Fitted on the training split alone. Including validation would leak, and including
    padding would drag both statistics toward zero for short flows.
    """
    lengths = x[:, :SPLT_N]
    gaps = x[:, SPLT_N:]
    real = lengths != 0

    def stats(values: np.ndarray) -> tuple[float, float]:
        selected = values[real]
        if selected.size == 0:
            return 0.0, 1.0
        deviation = float(selected.std())
        # A constant channel would divide by zero; 1.0 leaves it unscaled.
        return float(selected.mean()), deviation if deviation > 1e-6 else 1.0

    length_mean, length_std = stats(lengths)
    gap_mean, gap_std = stats(gaps)
    return (
        np.array([length_mean, gap_mean], dtype=np.float32),
        np.array([length_std, gap_std], dtype=np.float32),
    )


def _predict(model, x: np.ndarray, batch_size: int = 1024) -> np.ndarray:
    import torch

    model.eval()
    out: list[np.ndarray] = []
    with torch.no_grad():
        for start in range(0, len(x), batch_size):
            batch = torch.from_numpy(x[start : start + batch_size])
            out.append(model(batch).cpu().numpy())
    return np.concatenate(out) if out else np.array([], dtype=np.float32)


def export_onnx(model, path: Path) -> None:
    import torch

    model.eval()
    example = torch.zeros(1, len(TIER_B_FEATURES), dtype=torch.float32)
    torch.onnx.export(
        model,
        (example,),
        str(path),
        input_names=["input"],
        output_names=["probability"],
        # Batch is dynamic; the feature width is not, and the registry checks it.
        dynamic_axes={"input": {0: "batch"}, "probability": {0: "batch"}},
        opset_version=17,
    )


def verify_onnx_parity(model, onnx_path: Path, x: np.ndarray) -> float:
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_out = np.asarray(
        session.run(None, {session.get_inputs()[0].name: x.astype(np.float32)})[0]
    ).ravel()
    return float(np.max(np.abs(onnx_out - _predict(model, x))))


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0",
          epochs: int = EPOCHS) -> dict:
    import torch
    from torch import nn

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    x_train, y_train = load_split(data_dir, "train")
    x_val, y_val = load_split(data_dir, "val")
    x_test, y_test = load_split(data_dir, "test")

    positives = int(y_train.sum())
    negatives = len(y_train) - positives
    if positives == 0 or negatives == 0:
        raise ValueError(
            f"training split has only one class (pos={positives}, neg={negatives}); "
            "the split is unusable"
        )
    print(f"train {len(y_train):,} flows ({positives:,} attack / {negatives:,} benign)")

    mean, std = channel_statistics(x_train)
    print(f"channel means {mean.tolist()}, stds {std.tolist()}")

    torch.manual_seed(1337)
    model = build_model(mean, std)
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    # Rebalance in the loss rather than by resampling, so every benign flow stays in
    # training - benign variety is what suppresses false positives.
    loss_fn = nn.BCELoss(reduction="none")
    positive_weight = negatives / max(positives, 1)

    train_x = torch.from_numpy(x_train)
    train_y = torch.from_numpy(y_train)

    from sklearn.metrics import average_precision_score

    best_score, best_state, since_best = -1.0, None, 0
    for epoch in range(epochs):
        model.train()
        order = torch.randperm(len(train_x))
        for start in range(0, len(order), BATCH_SIZE):
            index = order[start : start + BATCH_SIZE]
            batch_x, batch_y = train_x[index], train_y[index]

            optimiser.zero_grad()
            predicted = model(batch_x).clamp(1e-7, 1 - 1e-7)
            weights = torch.where(batch_y > 0.5, positive_weight, 1.0)
            loss = (loss_fn(predicted, batch_y) * weights).mean()
            loss.backward()
            optimiser.step()

        val_score = float(average_precision_score(y_val, _predict(model, x_val)))
        if val_score > best_score:
            best_score, since_best = val_score, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            since_best += 1
            if since_best >= PATIENCE:
                print(f"early stop at epoch {epoch + 1}")
                break

    if best_state is not None:
        model.load_state_dict(best_state)
    print(f"best validation PR-AUC {best_score:.4f}")

    # Calibrate on validation, as Tier A does. The model emits a probability, so the
    # margin is recovered by its logit - the same path the registry uses at serving time.
    probs_val = np.clip(_predict(model, x_val), 1e-7, 1 - 1e-7)
    margin_val = np.log(probs_val / (1 - probs_val))
    a, b = fit_platt(margin_val, y_val.astype(np.int8))

    calibrated_val = apply_platt(margin_val, a, b)
    threshold = choose_threshold(calibrated_val, y_val.astype(np.int8))

    probs_test = np.clip(_predict(model, x_test), 1e-7, 1 - 1e-7)
    margin_test = np.log(probs_test / (1 - probs_test))
    metrics = evaluate(apply_platt(margin_test, a, b), y_test.astype(np.int8), threshold)
    uncalibrated = evaluate(probs_test, y_test.astype(np.int8), threshold)

    onnx_path = out_dir / "tier_b.onnx"
    export_onnx(model, onnx_path)
    max_drift = verify_onnx_parity(model, onnx_path, x_test[:2000])
    if max_drift > ONNX_TOLERANCE:
        raise RuntimeError(
            f"ONNX export disagrees with PyTorch by {max_drift:.3e} "
            f"(tolerance {ONNX_TOLERANCE:.0e}); the served model would not be the model "
            "that was evaluated"
        )

    card = {
        "name": "tier_b_cnn_bilstm",
        "tier": "B",
        "version": version,
        "onnx_sha256": sha256(onnx_path),
        "threshold": threshold,
        "mode": "shadow",
        "pr_auc": metrics["pr_auc"],
        "feature_order": list(TIER_B_FEATURES),
        "calibration": {"method": "platt", "a": a, "b": b},
        "target_max_fpr": TARGET_MAX_FPR,
        "rows": {"train": len(y_train), "val": len(y_val), "test": len(y_test)},
        "class_balance_train": {"attack": positives, "benign": negatives},
        "normalisation": {"mean": mean.tolist(), "std": std.tolist()},
        "metrics_test": metrics,
        "metrics_test_uncalibrated": uncalibrated,
        "onnx_max_abs_drift": max_drift,
        "sequence_length": SPLT_N,
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"PR-AUC {metrics['pr_auc']:.4f}  ROC-AUC {metrics['roc_auc']:.4f}")
    print(f"at threshold {threshold:.4f}: precision {metrics['precision']:.4f} "
          f"recall {metrics['recall']:.4f} FPR {metrics['false_positive_rate']:.4f}")
    print(f"ONNX max drift {max_drift:.2e}")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Tier B sequence model")
    parser.add_argument("--data", default="data/pcap", help="output of pcap_prep")
    parser.add_argument("--out", default="artefacts/tier_b")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    args = parser.parse_args()
    train(args.data, args.out, args.version, args.epochs)


if __name__ == "__main__":
    main()


__all__ = ["build_model", "channel_statistics", "load_split", "train", "SPLT_LEN_FIELDS", "SPLT_IAT_FIELDS"]
