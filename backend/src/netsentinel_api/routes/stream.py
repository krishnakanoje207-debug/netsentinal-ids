"""WebSocket alert feed.

The token arrives as a query parameter, not a header: browsers cannot set headers
on a WebSocket handshake. That puts it in server logs by default, so the tokens are
short-lived and this endpoint is reached through the SSH tunnel rather than the open
internet.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect, status
from sqlalchemy import select

from netsentinel_api.config import Settings, get_settings
from netsentinel_api.db.models import User
from netsentinel_api.db.session import get_sessionmaker
from netsentinel_api.events import AlertBroadcaster, get_broadcaster
from netsentinel_api.rbac import ALERTS_READ, permissions_for
from netsentinel_api.security import TokenError, decode_access_token, subject_id

router = APIRouter(tags=["stream"])


def _authorise(settings: Settings, token: str) -> User | None:
    """Resolve the token to a user holding alerts:read, or None."""
    try:
        payload = decode_access_token(settings, token)
        user_id = subject_id(payload)
    except TokenError:
        return None

    with get_sessionmaker()() as session:
        user = session.scalar(select(User).where(User.user_id == user_id))
        if user is None or not user.is_active:
            return None
        if ALERTS_READ not in permissions_for(user.role.permissions if user.role else None):
            return None
        return user


@router.websocket("/alerts/stream")
async def alert_stream(
    websocket: WebSocket,
    token: Annotated[str, Query()],
    settings: Annotated[Settings, Depends(get_settings)],
    broadcaster: Annotated[AlertBroadcaster, Depends(get_broadcaster)],
) -> None:
    if _authorise(settings, token) is None:
        # Closed before accept, so an unauthorised client never joins the fan-out.
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    await broadcaster.register(websocket)
    try:
        while True:
            # Nothing is expected from the client; this await is how a disconnect
            # is noticed.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await broadcaster.unregister(websocket)
