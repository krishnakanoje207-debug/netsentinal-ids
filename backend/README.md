# backend

FastAPI application: REST + WebSocket API, PostgreSQL via SQLAlchemy/Alembic,
JWT auth with RBAC, the audit log, and the approval gate that every response
action must pass through.

Built on **D9**. Will be a workspace member (`netsentinel-api`) depending on
`netsentinel-core` for the feature contract — never on `netsentinel-training`,
so the API image does not carry LightGBM.

Runs on the cloud VM.
