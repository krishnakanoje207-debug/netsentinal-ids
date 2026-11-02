"""Write-only telemetry credential, separate from every dashboard permission."""
import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from netsentinel_api.deps import SettingsDep, SessionDep, UNAUTHENTICATED, sensor_bearer
from netsentinel_api.services.telemetry import TelemetryBatch, receive

router = APIRouter(prefix="/telemetry", tags=["telemetry"])


def telemetry_token(
    settings: SettingsDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(sensor_bearer)],
) -> None:
    expected = settings.telemetry_token
    if expected is None:
        raise HTTPException(status_code=503, detail="telemetry ingestion is disabled")
    presented = credentials.credentials if credentials else ""
    if not hmac.compare_digest(presented.encode(), expected.get_secret_value().encode()):
        raise UNAUTHENTICATED


@router.post("/alerts", dependencies=[Depends(telemetry_token)])
def import_alerts(batch: TelemetryBatch, session: SessionDep) -> dict[str, int]:
    added = receive(session, batch)
    session.commit()
    return {"accepted": len(batch.alerts), "added": added}
