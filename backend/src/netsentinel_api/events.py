"""Live alert fan-out over WebSocket.

In-process and intentionally so: one API instance serves one SOC dashboard, and a
Redis pub/sub hop would be infrastructure bought for a problem that does not exist
yet. If the API is ever scaled past one process, this is the seam to replace.

A dead socket must not take a broadcast down with it, so a failing send removes
that client and the rest still receive the alert.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class Sender(Protocol):
    """The slice of a WebSocket this module uses, so tests need no real socket."""

    async def send_json(self, data: Any) -> None: ...


class AlertBroadcaster:
    def __init__(self) -> None:
        self._clients: set[Sender] = set()
        self._lock = asyncio.Lock()

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def register(self, client: Sender) -> None:
        async with self._lock:
            self._clients.add(client)

    async def unregister(self, client: Sender) -> None:
        async with self._lock:
            self._clients.discard(client)

    async def broadcast(self, message: dict) -> int:
        """Send to every client. Returns how many received it.

        Clients that raise are dropped, because a browser tab closed mid-send must
        not stop the other analysts seeing the alert.
        """
        async with self._lock:
            targets = list(self._clients)

        delivered = 0
        dead: list[Sender] = []
        for client in targets:
            try:
                await client.send_json(message)
                delivered += 1
            except Exception:  # noqa: BLE001 - any failure means this client is gone
                logger.debug("dropping a websocket client that failed to receive")
                dead.append(client)

        if dead:
            async with self._lock:
                for client in dead:
                    self._clients.discard(client)
        return delivered


#: One broadcaster per process, resolved through a dependency so tests can swap it.
_broadcaster = AlertBroadcaster()


def get_broadcaster() -> AlertBroadcaster:
    return _broadcaster
