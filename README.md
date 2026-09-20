# NetSentinel-AI

Intrusion detection and cyber security monitoring using machine learning.
Design and requirements live in [`deliverables/`](deliverables).

## Layout

A uv workspace. Folders follow the deployment boundaries in the M2 design rather
than language conventions — each one ends up on a different node.

| Package | Runs on | Contains |
|---|---|---|
| [`core/`](core) | everywhere | The feature contract and flow extraction. Imported by every other package. |
| [`training/`](training) | Kaggle GPU | Dataset preparation and the four model tiers. Exports ONNX. |
| [`backend/`](backend) | cloud VM | FastAPI, PostgreSQL, the approval gate. Built D9. |
| [`frontend/`](frontend) | browser | React SOC dashboard. Built D10. |
| [`sensors/`](sensors) | cloud VM | Live capture agent, Suricata, Zeek, Wazuh config. Built D3/D8. |
| [`infra/`](infra) | cloud VM | Compose files, ClickHouse DDL, Grafana. Built D2 onwards. |

`core` is deliberately the only shared dependency, and it is deliberately tiny —
`dpkt` and nothing else. The API must not be able to import LightGBM by accident,
and the sensor has to stay installable on a constrained host.

## The feature contract

`netsentinel_core.features.contract.FEATURE_ORDER` is the single source of truth
for the model input vector. Nothing else may hardcode a feature name, index or
count.

This exists because the largest risk in the design (M2 §5.4, High) is the
training features drifting away from the live ones. Two things hold the line:

- one extractor serves both paths — `extract_from_pcap` for training data and
  `FlowTracker.update` for the live sensor,
- `test_offline_and_live_paths_agree` pushes the same packets through both and
  fails if the vectors differ by a bit.

If a contract test fails, that is the alarm working. Bump the model version;
do not relax the test.

## Setup

Requires Python 3.11 and [uv](https://docs.astral.sh/uv/). Not 3.14 — LightGBM,
PyTorch Geometric and ONNX Runtime have no reliable wheels for it yet.

```bash
uv sync                  # creates .venv and installs every workspace member
uv run pytest            # 43 tests
```

On a machine with a full system drive, point the cache elsewhere first:

```bash
export UV_CACHE_DIR=D:/uv-cache
```

## Pipeline so far

```bash
# D4 - NF-* CSV to leakage-safe train/val/test Parquet
uv run netsentinel-prep --csv NF-UNSW-NB15-v3.csv --out data/processed

# D5 - Tier A gradient-boosted trees, calibrated, explained, exported to ONNX
uv run netsentinel-train-tier-a --data data/processed --out artefacts/tier_a
```

Training refuses to emit artefacts unless the ONNX export agrees with LightGBM to
within 1e-4, so the served model is always the model that was evaluated. It
writes `model_card.json`, whose fields map onto the `ml_models` table, and every
new model is born in `shadow` mode.
