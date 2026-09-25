"""Application factory.

A factory rather than a module-level ``app``, so tests can build an instance with
overridden dependencies and no import-time database or settings requirement.
"""

from __future__ import annotations

from fastapi import FastAPI

from netsentinel_api.routes import (
    actions,
    activity,
    alerts,
    assets,
    auth,
    models,
    stream,
    system,
)

API_PREFIX = "/api/v1"

DESCRIPTION = """
Alert triage and response API for NetSentinel-AI.

Every automated response passes a human gate: an action reaches execution only
after an analyst decision, and every transition is recorded in the audit log.
"""


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetSentinel-AI API",
        version=system.API_VERSION,
        description=DESCRIPTION,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
    )

    app.include_router(system.router, prefix=API_PREFIX)
    app.include_router(auth.router, prefix=API_PREFIX)
    app.include_router(alerts.router, prefix=API_PREFIX)
    app.include_router(activity.router, prefix=API_PREFIX)
    app.include_router(assets.router, prefix=API_PREFIX)
    app.include_router(actions.router, prefix=API_PREFIX)
    app.include_router(models.router, prefix=API_PREFIX)
    app.include_router(stream.router, prefix=API_PREFIX)

    # No CORS middleware on purpose. The dashboard reaches the API through an SSH
    # tunnel, so it is same-origin; adding permissive CORS would open the API to
    # any page the analyst's browser happens to load.
    return app


app = create_app()
