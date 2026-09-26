"""The listener that turns a committed alert into a frame on the live feed.

Driven with a fake connection, so the suite still needs no PostgreSQL. The trigger
itself is SQL and is checked by rendering the migration.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import psycopg

from netsentinel_api.events import AlertBroadcaster
from netsentinel_api.notify import (
    CHANNEL,
    MAX_RETRY_SECONDS,
    AlertListener,
    alert_message,
    conninfo,
    retry_delay,
)

URL = "postgresql+psycopg://netsentinel:s3cret@127.0.0.1:5433/netsentinel_demo"


class RecordingClient:
    def __init__(self) -> None:
        self.received: list[dict] = []
        self.arrived = threading.Event()

    async def send_json(self, data: dict) -> None:
        self.received.append(data)
        self.arrived.set()


class FakeConnection:
    """Delivers its payloads on the first poll, then goes quiet."""

    def __init__(self, payloads: list[str]) -> None:
        self.payloads = payloads
        self.executed: list[str] = []

    def __enter__(self) -> FakeConnection:
        return self

    def __exit__(self, *exc) -> None:
        return None

    def execute(self, sql: str) -> None:
        self.executed.append(sql)

    def notifies(self, timeout: float):
        while self.payloads:
            yield SimpleNamespace(payload=self.payloads.pop(0))


def run_listener(connect, client: RecordingClient, wait_for: int) -> None:
    """Start a listener on a live loop and stop it once ``wait_for`` frames arrived."""

    async def scenario() -> None:
        broadcaster = AlertBroadcaster()
        await broadcaster.register(client)
        listener = AlertListener(URL, broadcaster, asyncio.get_running_loop(), connect=connect)
        listener.start()
        try:
            for _ in range(200):
                if len(client.received) >= wait_for:
                    break
                await asyncio.sleep(0.01)
        finally:
            listener.stop()

    asyncio.run(scenario())


def test_conninfo_drops_the_driver_and_keeps_the_password():
    assert conninfo(URL) == "postgresql://netsentinel:s3cret@127.0.0.1:5433/netsentinel_demo"


def test_an_alert_id_becomes_the_frame_the_dashboard_reads():
    assert alert_message("42") == {"alert_id": 42}


def test_a_payload_that_is_not_an_id_is_not_sent():
    assert alert_message("hello") is None


def test_retries_back_off_and_then_hold():
    assert retry_delay(0) < retry_delay(1) < retry_delay(2)
    assert retry_delay(50) == MAX_RETRY_SECONDS


def test_each_notification_reaches_the_dashboards():
    connection = FakeConnection(["7", "8"])
    client = RecordingClient()

    run_listener(lambda *a, **k: connection, client, wait_for=2)

    assert connection.executed == [f"LISTEN {CHANNEL}"]
    assert client.received == [{"alert_id": 7}, {"alert_id": 8}]


def test_a_bad_payload_is_skipped_and_the_next_still_arrives():
    client = RecordingClient()

    run_listener(lambda *a, **k: FakeConnection(["oops", "9"]), client, wait_for=1)

    assert client.received == [{"alert_id": 9}]


def test_a_database_that_is_down_is_retried_not_fatal():
    """The feed's timer still refreshes the dashboard, so the listener keeps trying."""
    attempts: list[int] = []
    connection = FakeConnection(["5"])

    def connect(*args, **kwargs):
        attempts.append(1)
        if len(attempts) == 1:
            raise psycopg.OperationalError("connection refused")
        return connection

    client = RecordingClient()
    run_listener(connect, client, wait_for=1)

    assert len(attempts) >= 2
    assert client.received == [{"alert_id": 5}]
