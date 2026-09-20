# backend

`netsentinel-api` — FastAPI application: REST + WebSocket API, PostgreSQL via
SQLAlchemy/Alembic, JWT auth with RBAC, the audit log, and the approval gate that
every response action must pass through.

Depends on `netsentinel-core` for the feature contract, and deliberately never on
`netsentinel-training`, so the API image does not carry LightGBM.

Runs on the cloud VM.

## Built so far

| Module | What it is |
|---|---|
| `db/models.py` | The 15 tables of M2 §3.2. PostgreSQL-specific (JSONB, INET). |
| `services/response.py` | The human-in-the-loop gate in front of CrowdSec and Wazuh Active Response. |

Three invariants live in the schema rather than in service code:

- `detections.shap_values` is NOT NULL — an unexplained ML verdict is
  unrepresentable.
- `approvals.action_id` is UNIQUE — an action cannot accumulate approvals until
  one says yes.
- an action cannot claim to have executed without recording when.

The rule the schema *cannot* express — refuse to execute without an approval —
spans two tables and lives in `services/response.py`. `mark_executed` is the only
path to execution; if it raises, nothing on the network changed.

Tests compile the DDL against the PostgreSQL dialect and exercise the gate with a
stub session, so the whole suite runs with no database server.

## Still to build (D9)

Alembic migrations, JWT auth and RBAC dependencies, the alert and approval REST
routes, and the WebSocket alert feed. A live-PostgreSQL integration test suite
belongs on the VM.
