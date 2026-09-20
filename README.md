# NetSentinel-AI

Intrusion detection and cyber security monitoring using machine learning.
Design and requirements live in [`deliverables/`](deliverables).

## Layout

A uv workspace. Folders follow the deployment boundaries in the M2 design rather
than language conventions — each one ends up on a different node.

| Package | Runs on | Contains | State |
|---|---|---|---|
| [`core/`](core) | everywhere | Feature contract and flow extraction | built |
| [`training/`](training) | Kaggle GPU | Dataset prep, Tier A, Tier D | built |
| [`scoring/`](scoring) | cloud VM | Model loader and fusion scorer | built |
| [`writer/`](writer) | cloud VM | Bus consumer: explained detections into PostgreSQL | built |
| [`backend/`](backend) | cloud VM | FastAPI, PostgreSQL, the approval gate | built |
| [`frontend/`](frontend) | browser | React SOC dashboard | D10 |
| [`sensors/`](sensors) | cloud VM | Capture agent, Suricata, Zeek, Wazuh config | D3/D8 |
| [`infra/`](infra) | cloud VM | Compose files, ClickHouse DDL, Grafana | D2 onwards |

Dependencies run one way only. `core` is the single shared package and is
deliberately tiny — `dpkt` and nothing else — so the sensor stays installable on a
constrained host and the API cannot import LightGBM by accident. `writer` is the one
exception: it imports `backend` for the ORM models, because the schema should be
defined once and a writer with its own copy of the table definitions is a column
that means two things.

## The feature contract

`netsentinel_core.features.contract.FEATURE_ORDER` is the single source of truth for
the model input vector. Nothing else may hardcode a feature name, index or count.

This exists because the largest risk in the design (M2 §5.4, High) is training
features drifting away from live ones. Three things hold the line:

- one extractor serves both paths — `extract_from_pcap` for training data and
  `FlowTracker.update` for the live sensor;
- `test_offline_and_live_paths_agree` pushes the same packets through both and fails
  if the vectors differ by a bit;
- the scoring registry refuses to load a model whose card declares a different
  feature order, naming the index where they diverge.

A model also cannot load unless its ONNX file matches the SHA-256 in its card, so the
served model is always the one that was evaluated.

If a contract test fails, that is the alarm working. Bump the model version; do not
relax the test.

## Setup

Requires Python 3.11 and [uv](https://docs.astral.sh/uv/). Not 3.14 — LightGBM,
PyTorch Geometric and ONNX Runtime have no reliable wheels for it yet.

```bash
uv sync                  # creates .venv and installs every workspace member
uv run pytest            # 319 tests, no database or network needed
```

On a machine with a full system drive, redirect the package cache first:

```bash
export UV_CACHE_DIR=D:/uv-cache
```

## Pipeline

```bash
# D4 — NF-* CSV to leakage-safe train/val/test Parquet
uv run netsentinel-prep --csv NF-UNSW-NB15-v3.csv --out data/processed

# D5 — Tier A gradient-boosted trees: calibrated, explained, exported to ONNX
uv run netsentinel-train-tier-a --data data/processed --out artefacts/tier_a

# D6 — Tier D Isolation Forest, trained on benign flows only
uv run python -m netsentinel_training.models.tier_d --data data/processed --out artefacts/tier_d
```

Training refuses to emit artefacts unless the ONNX export agrees with the native
model to within 1e-4. Each run writes a `model_card.json` whose fields map onto the
`ml_models` table, and every model is born in `shadow` mode.

Tiers B (1D-CNN + BiLSTM), C (E-GraphSAGE) and the Tier D autoencoder need PyTorch and
belong in the Kaggle notebooks; they are not installed locally by design.

## From the wire to the dashboard

```bash
# the sensor scores flows and publishes them (see sensors/)
uv run netsentinel-sensor --interface netsentinel-lab     --models artefacts/tier_a/model_card.json --brokers localhost:9092

# a model needs a row before a detection can point at it
uv run netsentinel-register-model artefacts/tier_a/model_card.json

# the writer consumes that topic, explains each verdict and stores it
uv run netsentinel-writer --card artefacts/tier_a/model_card.json     --sensor-id 1 --brokers localhost:9092
```

The split exists because TreeSHAP needs the tree structure and an ONNX graph does not
carry it. The sensor scores through ONNX and publishes the feature vector; the writer
holds the native booster and produces the explanation. That is also why LightGBM lives
in `writer` and in `training`, and nowhere near the API.

Not every flow becomes a row. ClickHouse holds every scored flow; PostgreSQL holds the
ones at or above the deciding threshold. A shadow verdict is stored — against the
shadow tier's own score and threshold, so the shadow period can be evaluated
afterwards — and never raises an alert.

Delivery is at-least-once: the bus offset is committed after the database transaction,
so a crash replays a message rather than losing a detection.

## Backend

```bash
export NETSENTINEL_DATABASE_URL="postgresql+psycopg://user:pass@host:5432/netsentinel"
export NETSENTINEL_JWT_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"

cd backend && uv run alembic upgrade head   # create the schema
uv run netsentinel-bootstrap                # seed roles, create the admin
uv run uvicorn netsentinel_api.app:app      # serve; docs at /api/v1/docs
```

`bootstrap` is idempotent and never resets an existing password, so it is safe to
re-run from a deployment script. If no admin password is supplied one is generated
and printed once.

Every automated response passes a human gate. `services/response.mark_executed` is
the only path to execution and refuses without an approval, so if it raises, nothing
on the network changed. Approving does not execute — it moves the action to
`approved` for the D12 executors to pick up.

## Design decisions that deviate from M2 §4

| Document says | Built with | Why |
|---|---|---|
| python-jose, passlib | PyJWT, bcrypt | python-jose is effectively unmaintained with a CVE history; passlib predates Python 3.11 |
| Tier A on full NetFlow features | Tier A on the 15-feature intersection | NF-* datasets cannot supply SPLT, per-direction spread, IAT statistics or flag counts; training on them would recreate train/serve skew |
