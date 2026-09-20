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
uv run pytest            # 406 tests, no database or network needed
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

## Threat intelligence and SOAR

```bash
export NETSENTINEL_MISP_URL="https://misp.local"
export NETSENTINEL_MISP_API_KEY="..."
uv run netsentinel-sync-intel --since 7d    # MISP attributes into the iocs table
```

Both are optional, and the profile that runs them is separate for a reason: they
enrich alerts rather than produce them. With MISP and Keep down the pipeline still
detects, explains, stores and shows — what it loses is the known-bad label on an alert
and the de-duplication in front of the analyst.

The sync asks MISP for `to_ids` attributes with the warninglists enforced. Without
those two flags a public feed hands over addresses like 8.8.8.8, and an afternoon later
every DNS lookup in the lab is an alert with intelligence behind it.

Enrichment runs inside the writer's transaction — a local query belongs with the write
— and forwarding to Keep runs after the commit, because a network round trip should
never hold a row lock. A match links the alert to the indicator; a match on a
high-threat indicator also raises the severity one band, once, however many indicators
matched.

Keep de-duplicates on a fingerprint covering the source, the two addresses and the
technique. Severity, score and time are deliberately outside it: a scan that resumes an
hour later with a higher score is the same finding, and at-least-once delivery means
the same alert can legitimately be written twice.

## Active response

```bash
export NETSENTINEL_CROWDSEC_URL="http://127.0.0.1:8080"
export NETSENTINEL_CROWDSEC_MACHINE_ID="netsentinel-api"
export NETSENTINEL_CROWDSEC_PASSWORD="..."
uv run netsentinel-respond --interval 10   # execute what analysts have approved
```

Approving still does not execute. The API moves an action to `approved` and stops;
this worker is what turns that into a ban at the edge or a command on a host. The
split is the reason a route handler never holds a database transaction open across a
network round trip, and an analyst clicking approve never waits on CrowdSec.

The order inside the worker is the part worth reading. `mark_executed` runs first,
uncommitted, so the gate refuses an unapproved action *before* anything leaves the
process; then the request goes out; only an accepted request is committed. A refusal
rolls the transaction back and records the action as `failed`, so the row and the
network never disagree. A crash between the accepted request and the commit leaves the
action `approved` and the next pass applies it again — banning an address twice is the
same address banned, while a ban recorded but never applied is not recoverable.

Two enforcement points, because they enforce in different places: CrowdSec owns the
edge (its bouncer writes the nftables set, which is why nothing here shells out to
`nft`), and Wazuh Active Response owns the host. Both are optional in the same sense
MISP and Keep are — with neither configured the queue still fills and nothing on the
network can change, which is the safe way for a deployment to be incomplete. Approved
actions then wait instead of failing, so configuring the backend later executes them
rather than sending the analyst back to approve a second time.

Bans expire (four hours by default). A decision that lapses fails open: a mistaken
block costs an afternoon rather than leaving a permanent hole in the lab that nobody
remembers punching.

Lifting one goes back through the same gate. `POST /actions/{id}/rollback` records
that a named analyst asked for it and why, and moves the action to
`rollback_requested` — the ban is still in force in that state, which is why it has
its own name rather than an early move to `rolled_back`. The worker drains that queue
too: it deletes the CrowdSec decision or runs the undo command, and only then is the
action `rolled_back`. Approvals are drained first, because a block that has not been
applied is an attacker still reaching the network while an undo that waits one
interval is a ban that lasts ten seconds longer.

The asymmetry between the two queues is deliberate. A refused execution is recorded as
`failed` and left; a refused undo is retried indefinitely. What the database would
otherwise claim is the difference: `failed` means nothing is blocked, which is true
after a failed execution and a dangerous lie after a failed unban.

An action the system cannot reverse is refused at the click rather than in a worker
log an hour later — a killed process has nothing to restore, and the analyst is owed
that answer while they can still do something else about the host.

## Design decisions that deviate from M2 §4

| Document says | Built with | Why |
|---|---|---|
| python-jose, passlib | PyJWT, bcrypt | python-jose is effectively unmaintained with a CVE history; passlib predates Python 3.11 |
| Tier A on full NetFlow features | Tier A on the 15-feature intersection | NF-* datasets cannot supply SPLT, per-direction spread, IAT statistics or flag counts; training on them would recreate train/serve skew |
