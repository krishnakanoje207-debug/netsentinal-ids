"""Alert fan-out.

Driven with asyncio.run rather than an async test plugin, so the suite needs no
extra dependency for four tests.
"""

from __future__ import annotations

import asyncio

from netsentinel_api.events import AlertBroadcaster

ALERT = {"alert_id": 100, "severity": "high"}


class RecordingClient:
    def __init__(self) -> None:
        self.received: list[dict] = []

    async def send_json(self, data: dict) -> None:
        self.received.append(data)


class BrokenClient:
    """A browser tab that closed mid-send."""

    async def send_json(self, data: dict) -> None:
        raise ConnectionResetError("socket is gone")


def test_broadcast_reaches_every_client():
    async def scenario():
        broadcaster = AlertBroadcaster()
        clients = [RecordingClient(), RecordingClient()]
        for client in clients:
            await broadcaster.register(client)

        delivered = await broadcaster.broadcast(ALERT)
        return delivered, clients

    delivered, clients = asyncio.run(scenario())
    assert delivered == 2
    assert all(client.received == [ALERT] for client in clients)


def test_one_dead_client_does_not_stop_the_others():
    """The reason broadcast catches: an analyst must still see the alert."""

    async def scenario():
        broadcaster = AlertBroadcaster()
        healthy = RecordingClient()
        await broadcaster.register(BrokenClient())
        await broadcaster.register(healthy)

        delivered = await broadcaster.broadcast(ALERT)
        return delivered, healthy, broadcaster.client_count

    delivered, healthy, remaining = asyncio.run(scenario())
    assert delivered == 1
    assert healthy.received == [ALERT]
    # The broken one is dropped rather than retried forever.
    assert remaining == 1


def test_unregister_stops_delivery():
    async def scenario():
        broadcaster = AlertBroadcaster()
        client = RecordingClient()
        await broadcaster.register(client)
        await broadcaster.unregister(client)

        delivered = await broadcaster.broadcast(ALERT)
        return delivered, client

    delivered, client = asyncio.run(scenario())
    assert delivered == 0
    assert client.received == []


def test_broadcast_with_no_clients_is_harmless():
    assert asyncio.run(AlertBroadcaster().broadcast(ALERT)) == 0


def test_registering_twice_delivers_once():
    async def scenario():
        broadcaster = AlertBroadcaster()
        client = RecordingClient()
        await broadcaster.register(client)
        await broadcaster.register(client)
        return await broadcaster.broadcast(ALERT), client

    delivered, client = asyncio.run(scenario())
    assert delivered == 1
    assert client.received == [ALERT]
