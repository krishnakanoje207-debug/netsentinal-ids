"""New alerts, from whichever process wrote them, to the dashboards watching.

Alerts are stored by other processes - the detection writer, the Suricata importer -
so the API cannot see one arrive. A trigger on the alerts table (migration 0004)
raises a PostgreSQL NOTIFY carrying the new alert's id once the row is committed.
This module listens on its own connection and hands each id to the broadcaster.

A thread with a blocking connection rather than an asyncio one: psycopg's async mode
cannot run on the Proactor event loop that uvicorn uses on Windows, and the laptop the
demo runs on is Windows.

Losing the connection loses no alert. The dashboard refetches on a timer as well, so a
notification missed while reconnecting costs a few seconds of latency and nothing more.
That is why a failure here is logged and retried rather than taking the API down.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any, Callable

import psycopg
from sqlalchemy.engine import make_url

from netsentinel_api.events import AlertBroadcaster

logger = logging.getLogger(__name__)

#: The channel migration 0004's trigger notifies on.
CHANNEL = "netsentinel_alerts"

#: How often the listening thread looks up from the socket to check it should stop.
POLL_SECONDS = 1.0
FIRST_RETRY_SECONDS = 1.0
MAX_RETRY_SECONDS = 30.0


def conninfo(database_url: str) -> str:
    """libpq's form of the SQLAlchemy URL: the same database, without the driver name."""
    return make_url(database_url).set(drivername="postgresql").render_as_string(
        hide_password=False
    )


def retry_delay(attempt: int) -> float:
    """Doubles per failed attempt and then holds, like the dashboard's own reconnect."""
    return min(FIRST_RETRY_SECONDS * 2**attempt, MAX_RETRY_SECONDS)


def alert_message(payload: str) -> dict[str, int] | None:
    """The frame sent to the dashboards, or None for a payload that is not an alert id."""
    try:
        return {"alert_id": int(payload)}
    except ValueError:
        return None


class AlertListener:
    def __init__(
        self,
        database_url: str,
        broadcaster: AlertBroadcaster,
        loop: asyncio.AbstractEventLoop,
        connect: Callable[..., Any] = psycopg.connect,
    ) -> None:
        self._conninfo = conninfo(database_url)
        self._broadcaster = broadcaster
        self._loop = loop
        self._connect = connect
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="alert-listener", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=POLL_SECONDS * 2)

    def _run(self) -> None:
        attempt = 0
        while not self._stop.is_set():
            try:
                with self._connect(self._conninfo, autocommit=True) as connection:
                    connection.execute(f"LISTEN {CHANNEL}")
                    logger.info("listening for new alerts on %s", CHANNEL)
                    attempt = 0
                    while not self._stop.is_set():
                        for notification in connection.notifies(timeout=POLL_SECONDS):
                            self._deliver(notification.payload)
            except psycopg.Error as exc:
                delay = retry_delay(attempt)
                attempt += 1
                logger.warning(
                    "not listening for new alerts (%s); the dashboard still refreshes on "
                    "its timer. Retrying in %.0fs",
                    exc,
                    delay,
                )
                self._stop.wait(delay)

    def _deliver(self, payload: str) -> None:
        message = alert_message(payload)
        if message is None:
            logger.warning("ignoring a notification that is not an alert id: %r", payload)
            return
        asyncio.run_coroutine_threadsafe(self._broadcaster.broadcast(message), self._loop)
