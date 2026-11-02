"""Application factory.

A factory rather than a module-level ``app``, so tests can build an instance with
overridden dependencies and no import-time database or settings requirement.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netsentinel_api.config import cors_origins, database_url
from netsentinel_api.events import get_broadcaster
from netsentinel_api.notify import AlertListener
from netsentinel_api.routes import (
    actions,
    activity,
    admin,
    alerts,
    assets,
    auth,
    browser_audit,
    endpoint,
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


def create_app(*, listen_for_alerts: bool = True) -> FastAPI:
    """``listen_for_alerts=False`` leaves out the database listener behind the live
    feed, for tests that run with no PostgreSQL."""

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        listener = None
        if listen_for_alerts:
            listener = AlertListener(
                database_url(), get_broadcaster(), asyncio.get_running_loop()
            )
            listener.start()
        try:
            yield
        finally:
            if listener is not None:
                listener.stop()

    app = FastAPI(
        title="NetSentinel-AI API",
        version=system.API_VERSION,
        description=DESCRIPTION,
        openapi_url=f"{API_PREFIX}/openapi.json",
        docs_url=f"{API_PREFIX}/docs",
        lifespan=lifespan,
    )

    app.include_router(system.router, prefix=API_PREFIX)
    app.include_router(browser_audit.router, prefix=API_PREFIX)
    app.include_router(endpoint.router, prefix=API_PREFIX)
    app.include_router(auth.router, prefix=API_PREFIX)
    app.include_router(alerts.router, prefix=API_PREFIX)
    app.include_router(activity.router, prefix=API_PREFIX)
    app.include_router(assets.router, prefix=API_PREFIX)
    app.include_router(actions.router, prefix=API_PREFIX)
    app.include_router(models.router, prefix=API_PREFIX)
    app.include_router(admin.router, prefix=API_PREFIX)
    app.include_router(stream.router, prefix=API_PREFIX)

    origins = cors_origins()
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Authorization", "Content-Type"],
            expose_headers=["Content-Disposition", "X-Export-Truncated"],
        )
    return app


app = create_app()
