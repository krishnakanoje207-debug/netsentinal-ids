"""Health and version.

Reports the feature dimension it was built against, because a sensor or a model
compiled against a different contract is the failure this project most wants to
notice early.
"""

from __future__ import annotations

from fastapi import APIRouter

from netsentinel_core.features.contract import FEATURE_DIM
from netsentinel_api.schemas import HealthOut

router = APIRouter(tags=["system"])

API_VERSION = "0.1.0"


@router.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    # Deliberately does not touch the database: this endpoint answers "is the
    # process up", and a readiness probe that fails on a slow query restarts a
    # healthy API.
    return HealthOut(status="ok", version=API_VERSION, feature_dim=FEATURE_DIM)
