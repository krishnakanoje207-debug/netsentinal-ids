"""D7 Tier C: E-GraphSAGE over the flow graph.

    python -m netsentinel_training.models.tier_c --data data/pcap --out artefacts/tier_c

Tiers A and B judge a flow on its own evidence. This one judges it by its company: hosts
are nodes, flows are edges, and a flow is classified from the neighbourhood it sits in. That
catches what per-flow models cannot - one connection to one port looks ordinary, but the
same source touching forty hosts is a scan, and the difference lives in the graph rather
than in any single flow.

**Node features are deliberately constant.** Following the E-GraphSAGE paper, every node
starts as a vector of ones. The temptation is to embed the IP address, and it must be
resisted: an address is an identifier, not a behaviour, and a model that learns which hosts
are attackers on this testbed has learned nothing that transfers off it. All the signal
comes from edge features and topology.

**Message passing is implemented here rather than with torch-geometric.** PyG's layers do
not export to ONNX cleanly, and E-GraphSAGE's aggregation is a scatter-mean and two linear
layers. Taking the dependency would have cost more than it saved.

**This tier scores a window, not a flow.** A graph model needs neighbours, so there is no
meaningful score for one flow in isolation - which is why it is exported with a dynamic
edge count and run over a time window rather than plugged into the per-flow fusion path.
See `score_window`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_a import (
    LABEL_COLUMN,
    TARGET_MAX_FPR,
    apply_platt,
    choose_threshold,
    evaluate,
    fit_platt,
    sha256,
)

#: Edge features: the same flow aggregates Tier A uses. The sequence features belong to
#: Tier B, and a graph over them would be a different model.
EDGE_FEATURES = TIER_A_FEATURES

#: Hidden width per layer, and how many rounds of message passing. Two hops is enough to
#: see "my neighbour also talks to many hosts", which is the scan signal; more hops on a
#: dense flow graph mostly smooths everything toward the average.
HIDDEN = 64
LAYERS = 2

ONNX_TOLERANCE = 1e-4

EPOCHS = 60
LEARNING_RATE = 5e-3
PATIENCE = 10

SRC_COLUMN = "src_ip"
DST_COLUMN = "dst_ip"
TIME_COLUMN = "ts_ms"

#: Flows per training graph. The deployed unit is a window (see score_window), and
#: training on windows is also what fits in memory: one graph of 1.6M edges needs
#: several GB of activations, a 20k-flow window a few MB.
WINDOW_FLOWS = 20_000


class GraphBuildError(RuntimeError):
    """The split could not be turned into a graph."""


def build_graph(frame: pl.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray, int]:
    """Turn flows into (edge_index, edge_features, labels, node_count).

    ``edge_index`` is (2, E) holding source and destination node ids. Nodes are interned
    per graph, so an address never becomes a stable identity the model could memorise
    across graphs.
    """
    for column in (SRC_COLUMN, DST_COLUMN):
        if column not in frame.columns:
            raise GraphBuildError(
                f"{column} is absent; the graph needs endpoints, so Tier C requires the "
                "capture-derived data from pcap_prep rather than a feature-only table"
            )
    missing = [f for f in EDGE_FEATURES if f not in frame.columns]
    if missing:
        raise GraphBuildError(f"missing edge features {missing}")
    if frame.height == 0:
        raise GraphBuildError("no flows to build a graph from")

    hosts = frame.get_column(SRC_COLUMN).to_list() + frame.get_column(DST_COLUMN).to_list()
    ids = {host: index for index, host in enumerate(dict.fromkeys(hosts))}

    source = np.array([ids[h] for h in frame.get_column(SRC_COLUMN).to_list()], dtype=np.int64)
    target = np.array([ids[h] for h in frame.get_column(DST_COLUMN).to_list()], dtype=np.int64)
    edge_index = np.stack([source, target])

    edge_features = frame.select(EDGE_FEATURES).to_numpy().astype(np.float32)
    labels = (
        frame.get_column(LABEL_COLUMN).to_numpy().astype(np.float32)
        if LABEL_COLUMN in frame.columns
        else np.zeros(frame.height, dtype=np.float32)
    )
    return edge_index, edge_features, labels, len(ids)


def windows(frame: pl.DataFrame, size: int = WINDOW_FLOWS) -> list[tuple]:
    """Consecutive windows of flows, in time order when the split has a time column.

    Each window is its own graph with its own interned node ids, as a live window is.
    """
    if TIME_COLUMN in frame.columns:
        frame = frame.sort(TIME_COLUMN)
    return [build_graph(frame[start:start + size]) for start in range(0, frame.height, size)]


def _predict_windows(model, graphs: list[tuple]) -> np.ndarray:
    return np.concatenate([_predict(model, g[0], g[1], g[3]) for g in graphs])


def edge_statistics(edge_features: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Per-feature mean and std, fitted on the training graph only."""
    mean = edge_features.mean(axis=0)
    std = edge_features.std(axis=0)
    # A constant feature would divide by zero; 1.0 leaves it unscaled.
    std = np.where(std > 1e-6, std, 1.0)
    return mean.astype(np.float32), std.astype(np.float32)


def build_model(mean: np.ndarray, std: np.ndarray):
    """E-GraphSAGE with the aggregation written out."""
    import torch
    from torch import nn

    feature_count = len(EDGE_FEATURES)

    class EGraphSAGE(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.register_buffer("mean", torch.tensor(mean).view(1, -1))
            self.register_buffer("std", torch.tensor(std).view(1, -1))

            # Layer input is the node's own state concatenated with the aggregated
            # (neighbour state, edge feature) message.
            self.layers = nn.ModuleList()
            node_width = 1  # nodes start as a single constant
            for _ in range(LAYERS):
                self.layers.append(nn.Linear(node_width + node_width + feature_count, HIDDEN))
                node_width = HIDDEN

            # An edge is classified from both endpoints plus its own features.
            self.head = nn.Sequential(
                nn.Linear(2 * HIDDEN + feature_count, HIDDEN),
                nn.ReLU(),
                nn.Dropout(0.2),
                nn.Linear(HIDDEN, 1),
            )

        def forward(
            self,
            edge_index: "torch.Tensor",
            edge_features: "torch.Tensor",
            node_count: "torch.Tensor",
        ) -> "torch.Tensor":
            features = (edge_features - self.mean) / self.std
            count = node_count.to(torch.int64).reshape(())

            source, target = edge_index[0], edge_index[1]
            # Ones, not an embedding: see the module docstring on why an address must not
            # become a feature.
            h = torch.ones(count, 1, dtype=features.dtype, device=features.device)

            for layer in self.layers:
                # Undirected for aggregation: a flow informs both endpoints. Direction is
                # preserved where it matters, in the edge features and the head.
                senders = torch.cat([source, target])
                receivers = torch.cat([target, source])
                doubled = torch.cat([features, features], dim=0)

                messages = torch.cat([h[senders], doubled], dim=1)

                summed = torch.zeros(count, messages.shape[1], dtype=features.dtype,
                                     device=features.device)
                summed = summed.index_add(0, receivers, messages)

                degree = torch.zeros(count, 1, dtype=features.dtype, device=features.device)
                degree = degree.index_add(
                    0, receivers, torch.ones(receivers.shape[0], 1, dtype=features.dtype,
                                             device=features.device)
                )
                # Mean, so a hub is not simply louder than a leaf; clamped because an
                # isolated node has no incident edges.
                aggregated = summed / degree.clamp(min=1.0)

                h = torch.relu(layer(torch.cat([h, aggregated], dim=1)))

            edge_embedding = torch.cat([h[source], h[target], features], dim=1)
            return torch.sigmoid(self.head(edge_embedding).squeeze(-1))

    return EGraphSAGE()


def _predict(model, edge_index: np.ndarray, edge_features: np.ndarray, node_count: int) -> np.ndarray:
    import torch

    model.eval()
    with torch.no_grad():
        return model(
            torch.from_numpy(edge_index),
            torch.from_numpy(edge_features),
            torch.tensor(node_count, dtype=torch.int64),
        ).cpu().numpy()


def score_window(model, frame: pl.DataFrame) -> np.ndarray:
    """Score every flow in one window, as the live path would.

    A graph model has no verdict for a flow in isolation, so the deployed unit of work is a
    window of flows rather than a single one.
    """
    edge_index, edge_features, _labels, node_count = build_graph(frame)
    return _predict(model, edge_index, edge_features, node_count)


def export_onnx(model, edge_index: np.ndarray, edge_features: np.ndarray,
                node_count: int, path: Path) -> None:
    import torch

    model.eval()
    torch.onnx.export(
        model,
        (
            torch.from_numpy(edge_index),
            torch.from_numpy(edge_features),
            torch.tensor(node_count, dtype=torch.int64),
        ),
        str(path),
        input_names=["edge_index", "edge_features", "node_count"],
        output_names=["probability"],
        # Both the edge count and the node count vary per window, so both are dynamic.
        dynamic_axes={
            "edge_index": {1: "edges"},
            "edge_features": {0: "edges"},
            "probability": {0: "edges"},
        },
        opset_version=17,
        # The legacy TorchScript exporter maps index_add to a ScatterND that overwrites
        # instead of accumulating, and every node here receives from many edges. It
        # produced a silently wrong graph - 0.34 absolute drift - which the parity gate
        # caught. The dynamo exporter emits a scatter with add reduction.
        dynamo=True,
    )


def verify_onnx_parity(model, onnx_path: Path, edge_index: np.ndarray,
                       edge_features: np.ndarray, node_count: int) -> float:
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    onnx_out = np.asarray(
        session.run(
            None,
            {
                "edge_index": edge_index,
                "edge_features": edge_features,
                "node_count": np.array(node_count, dtype=np.int64),
            },
        )[0]
    ).ravel()
    return float(np.max(np.abs(onnx_out - _predict(model, edge_index, edge_features, node_count))))


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0",
          epochs: int = EPOCHS) -> dict:
    import torch
    from sklearn.metrics import average_precision_score
    from torch import nn

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    graphs = {
        name: windows(pl.read_parquet(data_dir / f"{name}.parquet"))
        for name in ("train", "val", "test")
    }
    labels = {name: np.concatenate([g[2] for g in graphs[name]]) for name in graphs}

    train_labels = labels["train"]
    positives = int(train_labels.sum())
    negatives = len(train_labels) - positives
    if positives == 0 or negatives == 0:
        raise ValueError(
            f"training graph has only one class (pos={positives}, neg={negatives}); "
            "the split is unusable"
        )
    train_nodes = max(g[3] for g in graphs["train"])
    print(f"train: {len(graphs['train'])} windows of up to {WINDOW_FLOWS:,} flows, "
          f"{len(train_labels):,} flows ({positives:,} attack)")

    mean, std = edge_statistics(np.concatenate([g[1] for g in graphs["train"]]))
    torch.manual_seed(1337)
    rng = np.random.default_rng(1337)
    model = build_model(mean, std)
    optimiser = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    loss_fn = nn.BCELoss(reduction="none")
    positive_weight = negatives / max(positives, 1)

    best_score, best_state, since_best = -1.0, None, 0
    for epoch in range(epochs):
        model.train()
        # One optimiser step per window, in a fresh order each epoch.
        for index in rng.permutation(len(graphs["train"])):
            edge_index, edge_features, window_labels, node_count = graphs["train"][index]
            optimiser.zero_grad()
            predicted = model(
                torch.from_numpy(edge_index),
                torch.from_numpy(edge_features),
                torch.tensor(node_count, dtype=torch.int64),
            ).clamp(1e-7, 1 - 1e-7)
            target = torch.from_numpy(window_labels)
            weights = torch.where(target > 0.5, positive_weight, 1.0)
            loss = (loss_fn(predicted, target) * weights).mean()
            loss.backward()
            optimiser.step()

        val_score = float(average_precision_score(labels["val"], _predict_windows(model, graphs["val"])))
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

    val_labels, test_labels = labels["val"], labels["test"]
    probs_val = np.clip(_predict_windows(model, graphs["val"]), 1e-7, 1 - 1e-7)
    margin_val = np.log(probs_val / (1 - probs_val))
    a, b = fit_platt(margin_val, val_labels.astype(np.int8))
    threshold = choose_threshold(apply_platt(margin_val, a, b), val_labels.astype(np.int8))

    probs_test = np.clip(_predict_windows(model, graphs["test"]), 1e-7, 1 - 1e-7)
    margin_test = np.log(probs_test / (1 - probs_test))
    metrics = evaluate(apply_platt(margin_test, a, b), test_labels.astype(np.int8), threshold)
    uncalibrated = evaluate(probs_test, test_labels.astype(np.int8), threshold)

    train_index, train_features, _, first_nodes = graphs["train"][0]
    test_index, test_features, _, test_nodes = graphs["test"][0]
    onnx_path = out_dir / "tier_c.onnx"
    export_onnx(model, train_index, train_features, first_nodes, onnx_path)
    max_drift = verify_onnx_parity(model, onnx_path, test_index, test_features, test_nodes)
    if max_drift > ONNX_TOLERANCE:
        raise RuntimeError(
            f"ONNX export disagrees with PyTorch by {max_drift:.3e} "
            f"(tolerance {ONNX_TOLERANCE:.0e})"
        )

    card = {
        "name": "tier_c_egraphsage",
        "tier": "C",
        "version": version,
        "onnx_sha256": sha256(onnx_path),
        "threshold": threshold,
        "mode": "shadow",
        "pr_auc": metrics["pr_auc"],
        "feature_order": list(EDGE_FEATURES),
        "calibration": {"method": "platt", "a": a, "b": b},
        "target_max_fpr": TARGET_MAX_FPR,
        "graph": {
            "layers": LAYERS,
            "hidden": HIDDEN,
            "node_features": "constant ones",
            "train_hosts": train_nodes,
        },
        "rows": {name: int(len(labels[name])) for name in graphs},
        "window_flows": WINDOW_FLOWS,
        "class_balance_train": {"attack": positives, "benign": negatives},
        "normalisation": {"mean": mean.tolist(), "std": std.tolist()},
        "metrics_test": metrics,
        "metrics_test_uncalibrated": uncalibrated,
        "onnx_max_abs_drift": max_drift,
        # Recorded because it changes how this model is deployed: it scores a window of
        # flows, not one flow, so it does not join the per-flow fusion path.
        "scoring_unit": "window",
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"PR-AUC {metrics['pr_auc']:.4f}  ROC-AUC {metrics['roc_auc']:.4f}")
    print(f"at threshold {threshold:.4f}: precision {metrics['precision']:.4f} "
          f"recall {metrics['recall']:.4f} FPR {metrics['false_positive_rate']:.4f}")
    print(f"ONNX max drift {max_drift:.2e}")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the Tier C graph model")
    parser.add_argument("--data", default="data/pcap", help="output of pcap_prep")
    parser.add_argument("--out", default="artefacts/tier_c")
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    args = parser.parse_args()
    train(args.data, args.out, args.version, args.epochs)


if __name__ == "__main__":
    main()
