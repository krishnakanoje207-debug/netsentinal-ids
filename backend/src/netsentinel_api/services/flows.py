"""Scored flows per minute, from ClickHouse ``network_flows``, for the activity strip.

The only place the API reads ClickHouse, and deliberately small. It asks one question
over the HTTP interface with the standard library, as the flow sink writes to it, so
the API gains no driver for a table it only counts.

The question is asked with a GET, which ClickHouse runs read-only, and the window's
start travels as a query parameter (``param_since``) rather than inside the SQL. The
start is the API's own, not ClickHouse's ``now()``: the minutes are the API's, and
two clocks either side of a minute boundary would leave the oldest minute counted
from part of its flows.

Counting is best effort, as opening an IRIS case is. ``per_minute`` raises
``FlowCountError`` rather than deciding anything, and the route serves the alert
counts it already has with the flow counts left null. A null is "not known"; a zero
would claim a quiet network.
"""

from __future__ import annotations

import http.client
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from netsentinel_api.config import Settings

#: Short, because the dashboard waits on it. The limit is per socket operation, and
#: the answer is at most one short line per minute of the window.
REQUEST_TIMEOUT_SECONDS = 2.0

#: Minutes as Unix seconds, so the answer does not depend on the server's time zone.
#: ``ts`` is when the flow started, which is the only time the table records.
FLOWS_PER_MINUTE = (
    "SELECT toUnixTimestamp(toStartOfMinute(toDateTime(ts))) AS bucket, count() "
    "FROM netsentinel.network_flows "
    "WHERE ts >= fromUnixTimestamp({since:UInt32}) "
    "GROUP BY bucket "
    "FORMAT TabSeparated"
)


class FlowCountError(RuntimeError):
    """The flow counts could not be read."""


class FlowCounter:
    """Counts ``network_flows`` rows per minute over ClickHouse's HTTP interface."""

    def __init__(
        self,
        url: str,
        user: str,
        password: str,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        # urlopen also follows file:// and other schemes; only HTTP reaches ClickHouse.
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            raise ValueError(f"ClickHouse URL must be http or https: {url!r}")
        self._url = url.rstrip("/")
        self._headers = {"X-ClickHouse-User": user, "X-ClickHouse-Key": password}
        self._timeout = timeout

    def per_minute(self, since: datetime) -> dict[datetime, int]:
        """Flows in each minute from ``since`` on, keyed by the minute in UTC.

        Minutes with none are absent; the caller knows which minutes it asked about.
        """
        query = urllib.parse.urlencode(
            {"query": FLOWS_PER_MINUTE, "param_since": int(since.timestamp())}
        )
        request = urllib.request.Request(f"{self._url}/?{query}", headers=self._headers)
        try:
            # B310: the scheme is checked in __init__.
            with urllib.request.urlopen(request, timeout=self._timeout) as response:  # nosec B310
                body = response.read().decode("utf-8")
        # OSError covers a refusal, a timeout and an HTTP error status alike;
        # HTTPException a connection that broke mid-answer.
        except (OSError, http.client.HTTPException) as exc:
            raise FlowCountError(f"ClickHouse did not answer: {exc}") from exc

        counts: dict[datetime, int] = {}
        for line in body.splitlines():
            try:
                minute, flows = line.split("\t")
                counts[datetime.fromtimestamp(int(minute), timezone.utc)] = int(flows)
            except ValueError as exc:
                raise FlowCountError(
                    f"ClickHouse answered with something other than counts: {line!r}"
                ) from exc
        return counts


def counter_from(settings: Settings) -> FlowCounter | None:
    """A counter if ClickHouse is configured, otherwise nothing.

    Nothing is a valid answer: the strip then shows alerts alone. A URL that is not
    http or https raises ``ValueError`` here.
    """
    if not (settings.clickhouse_url and settings.clickhouse_user
            and settings.clickhouse_password):
        return None
    return FlowCounter(
        settings.clickhouse_url,
        settings.clickhouse_user,
        settings.clickhouse_password.get_secret_value(),
    )
