"""The activity strip: alerts and scored flows per minute, and what happens to the flow
counts when ClickHouse is not there to give them.

ClickHouse is stood in for at ``urllib.request.urlopen``, so the client's own request
building and parsing run for real and nothing leaves the machine. Times are taken from
the real clock and every bucket is looked up by its start, so a test that straddles a
minute boundary still reads the right bucket.
"""

from __future__ import annotations

import http.client
import io
import logging
import socket
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr
from sqlalchemy.dialects import postgresql

from netsentinel_api.config import Settings
from netsentinel_api.db.models import Alert, AlertStatus, Role, Severity, User
from netsentinel_api.db.repositories import AlertRepository
from netsentinel_api.rbac import MODELS_READ, as_column
from netsentinel_api.routes import activity as activity_route
from netsentinel_api.security import create_access_token
from netsentinel_api.services.flows import (
    REQUEST_TIMEOUT_SECONDS,
    FlowCounter,
    FlowCountError,
    counter_from,
)

URL = "/api/v1/activity"
MINUTE = timedelta(minutes=1)


def this_minute() -> datetime:
    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def raised_at(when: datetime, alert_id: int) -> Alert:
    return Alert(alert_id=alert_id, source="early_flow", severity=Severity.high,
                 status=AlertStatus.new, src_ip=None, dst_ip=None,
                 mitre_technique=None, created_at=when)


def by_start(body: dict) -> dict[datetime, dict]:
    return {datetime.fromisoformat(b["start"]): b for b in body["buckets"]}


def tsv(counts: dict[datetime, int]) -> bytes:
    """What ClickHouse sends for FORMAT TabSeparated: Unix minute, tab, count."""
    return "".join(f"{int(m.timestamp())}\t{n}\n" for m, n in counts.items()).encode()


class StandIn:
    """Answers in ClickHouse's place, and records what it was asked."""

    def __init__(self) -> None:
        self.answer: bytes | BaseException = b""
        self.requests: list[tuple[urllib.request.Request, float]] = []

    def __call__(self, request, timeout=None):
        self.requests.append((request, timeout))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return io.BytesIO(self.answer)


@pytest.fixture
def urlopen(monkeypatch) -> StandIn:
    stand_in = StandIn()
    monkeypatch.setattr(urllib.request, "urlopen", stand_in)
    return stand_in


@pytest.fixture
def clickhouse(settings: Settings, urlopen: StandIn) -> StandIn:
    """ClickHouse configured, and answered by the stand-in."""
    settings.clickhouse_url = "http://clickhouse:8123"
    settings.clickhouse_user = "netsentinel"
    settings.clickhouse_password = SecretStr("a-clickhouse-password")
    return urlopen


def warnings(caplog) -> list[str]:
    return [r.getMessage() for r in caplog.records
            if r.name == "netsentinel.activity" and r.levelno == logging.WARNING]


# --- the window --------------------------------------------------------------

def test_every_minute_of_the_window_is_a_bucket_ending_with_the_current_one(
    client, auth_header
):
    before = datetime.now(timezone.utc)
    response = client.get(URL, headers=auth_header)
    after = datetime.now(timezone.utc)

    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"minutes", "until", "buckets", "flows_available"}
    assert body["minutes"] == 60

    starts = [datetime.fromisoformat(b["start"]) for b in body["buckets"]]
    assert len(starts) == 60
    assert all(s.tzinfo is not None and s.utcoffset() == timedelta(0) for s in starts)
    assert all(s.second == 0 and s.microsecond == 0 for s in starts)
    # Oldest first, one minute apart, no gaps.
    assert all(b - a == MINUTE for a, b in zip(starts, starts[1:]))
    # The newest bucket is the minute the request was served in, still running.
    assert before.replace(second=0, microsecond=0) <= starts[-1]
    assert starts[-1] <= after.replace(second=0, microsecond=0)
    assert datetime.fromisoformat(body["until"]) == starts[-1] + MINUTE
    assert all(set(b) == {"start", "alerts", "flows"} for b in body["buckets"])


@pytest.mark.parametrize("minutes", [5, 240])
def test_minutes_sets_the_length_of_the_window(client, auth_header, minutes):
    body = client.get(f"{URL}?minutes={minutes}", headers=auth_header).json()

    assert body["minutes"] == minutes
    assert len(body["buckets"]) == minutes


@pytest.mark.parametrize("minutes", [-1, 0, 4, 241])
def test_a_window_outside_5_to_240_minutes_is_refused(client, auth_header, minutes):
    assert client.get(f"{URL}?minutes={minutes}", headers=auth_header).status_code == 422


# --- alerts ------------------------------------------------------------------

def test_alerts_are_counted_in_their_minute_and_every_other_minute_is_zero(
    client, auth_header, alerts
):
    busy = this_minute() - 3 * MINUTE
    quiet = this_minute() - 10 * MINUTE
    alerts += [
        raised_at(busy + timedelta(seconds=5), 201),
        raised_at(busy + timedelta(seconds=59), 202),
        raised_at(quiet + timedelta(seconds=30), 203),
    ]

    buckets = by_start(client.get(URL, headers=auth_header).json())

    assert buckets[busy]["alerts"] == 2
    assert buckets[quiet]["alerts"] == 1
    # Zero-filled, as integers: an alert count PostgreSQL gave is known, not missing.
    others = [b["alerts"] for start, b in buckets.items() if start not in (busy, quiet)]
    assert others == [0] * 58


def test_an_alert_older_than_the_window_is_not_counted(client, auth_header, alerts):
    # The conftest alert is days old already; this one is one minute too old.
    alerts.append(raised_at(this_minute() - 60 * MINUTE + timedelta(seconds=30), 201))

    body = client.get(URL, headers=auth_header).json()

    assert sum(b["alerts"] for b in body["buckets"]) == 0


def test_the_alert_counts_are_one_date_trunc_query_over_the_window():
    """The real query never runs in this suite, so it is compiled and read."""

    class Capturing:
        def execute(self, statement):
            self.statement = statement
            return self

        def all(self):
            return []

    session = Capturing()
    since = datetime(2026, 9, 25, 9, 0, tzinfo=timezone.utc)
    assert AlertRepository(session).per_minute(since) == {}  # type: ignore[arg-type]

    sql = str(session.statement.compile(dialect=postgresql.psycopg.dialect(),
                                        compile_kwargs={"literal_binds": True}))
    # The same expression selected and grouped on, or PostgreSQL refuses it.
    assert sql.count("date_trunc('minute', alerts.created_at)") == 2
    assert "GROUP BY date_trunc('minute', alerts.created_at)" in sql
    # On the column itself, so ix_alerts_created_at can serve the range.
    assert "WHERE alerts.created_at >= '2026-09-25 09:00:00+00:00'" in sql


# --- who may read it ---------------------------------------------------------

def test_the_strip_needs_a_signed_in_reader(client):
    assert client.get(URL).status_code == 401


def test_the_strip_needs_alerts_read(client, settings, session):
    session.user = User(user_id=9, username="modeller-only", email="m@example.test",
                        password_hash="x", role_id=9, is_active=True,
                        role=Role(role_id=9, name="models_only",
                                  permissions=as_column({MODELS_READ})))
    token = create_access_token(settings, 9, "models_only")

    response = client.get(URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 403
    assert "alerts:read" in response.json()["detail"]


# --- flows from ClickHouse ---------------------------------------------------

def test_flows_are_counted_per_minute_from_clickhouse(
    client, auth_header, alerts, clickhouse
):
    busy = this_minute() - 2 * MINUTE
    earlier = this_minute() - 5 * MINUTE
    clickhouse.answer = tsv({busy: 7, earlier: 3})
    alerts.append(raised_at(busy + timedelta(seconds=1), 201))

    body = client.get(URL, headers=auth_header).json()
    buckets = by_start(body)

    assert body["flows_available"] is True
    assert buckets[busy]["flows"] == 7
    assert buckets[earlier]["flows"] == 3
    assert buckets[busy]["alerts"] == 1
    # ClickHouse answered, so a minute it had nothing for is a real zero.
    others = [b["flows"] for start, b in buckets.items() if start not in (busy, earlier)]
    assert others == [0] * 58
    # Asked once, from the oldest minute on the strip.
    [(request, _)] = clickhouse.requests
    sent = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
    assert sent["param_since"] == [str(int(min(buckets).timestamp()))]


def test_the_query_is_parameterised_read_only_and_short():
    since = datetime(2026, 9, 21, 10, 0, tzinfo=timezone.utc)
    stand_in = StandIn()
    stand_in.answer = tsv({since: 12, since + MINUTE: 4})

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib.request, "urlopen", stand_in)
        counts = FlowCounter("http://clickhouse:8123/", "netsentinel", "pw").per_minute(since)

    assert counts == {since: 12, since + MINUTE: 4}
    [(request, timeout)] = stand_in.requests
    # A GET, which ClickHouse runs read-only.
    assert request.get_method() == "GET"
    assert request.full_url.startswith("http://clickhouse:8123/?")
    sent = urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query)
    assert sent["param_since"] == [str(int(since.timestamp()))]
    # The value is bound by ClickHouse, never written into the SQL.
    assert "{since:UInt32}" in sent["query"][0]
    assert str(int(since.timestamp())) not in sent["query"][0]
    assert request.get_header("X-clickhouse-user") == "netsentinel"
    assert request.get_header("X-clickhouse-key") == "pw"
    assert timeout == REQUEST_TIMEOUT_SECONDS == 2.0


def test_clickhouse_unset_gives_null_flows_not_zeros(
    client, auth_header, alerts, urlopen, caplog, monkeypatch
):
    monkeypatch.setattr(activity_route, "_said_unconfigured", False)
    busy = this_minute() - MINUTE
    alerts.append(raised_at(busy, 201))

    with caplog.at_level(logging.WARNING, logger="netsentinel.activity"):
        response = client.get(URL, headers=auth_header)

    assert response.status_code == 200
    body = response.json()
    assert body["flows_available"] is False
    assert [b["flows"] for b in body["buckets"]] == [None] * 60
    # The alerts are this system's own record and are served regardless.
    assert by_start(body)[busy]["alerts"] == 1
    assert urlopen.requests == []
    [warning] = warnings(caplog)
    assert "not configured" in warning

    # A feature that is off is said once, not on every dashboard poll.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="netsentinel.activity"):
        client.get(URL, headers=auth_header)
    assert warnings(caplog) == []


@pytest.mark.parametrize(
    "missing", ["clickhouse_url", "clickhouse_user", "clickhouse_password"]
)
def test_clickhouse_half_configured_is_unset(settings, clickhouse, missing):
    assert counter_from(settings) is not None

    # Compose passes a variable missing from .env through as an empty string.
    setattr(settings, missing, "")

    assert counter_from(settings) is None


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.URLError(ConnectionRefusedError("connection refused")),
        urllib.error.URLError(TimeoutError("timed out")),
        TimeoutError("timed out"),
        urllib.error.HTTPError("http://clickhouse:8123/", 404, "Not Found", None, None),
        http.client.RemoteDisconnected("closed without a response"),
        b"<html>not ClickHouse</html>",
    ],
    ids=["refused", "connect-timeout", "read-timeout", "http-error", "disconnected",
         "not-counts"],
)
def test_clickhouse_failing_leaves_flows_null_and_the_strip_up(
    client, auth_header, alerts, clickhouse, caplog, failure
):
    clickhouse.answer = failure
    busy = this_minute() - MINUTE
    alerts.append(raised_at(busy, 201))

    with caplog.at_level(logging.WARNING, logger="netsentinel.activity"):
        response = client.get(URL, headers=auth_header)

    assert response.status_code == 200
    body = response.json()
    assert body["flows_available"] is False
    assert [b["flows"] for b in body["buckets"]] == [None] * 60
    assert by_start(body)[busy]["alerts"] == 1
    [warning] = warnings(caplog)
    assert "ClickHouse" in warning


def test_a_clickhouse_that_never_answers_times_out():
    """Against a real socket that accepts the connection and never replies."""
    with socket.create_server(("127.0.0.1", 0)) as silent:
        port = silent.getsockname()[1]
        counter = FlowCounter(f"http://127.0.0.1:{port}", "netsentinel", "pw", timeout=0.2)
        started = datetime.now(timezone.utc)

        with pytest.raises(FlowCountError, match="did not answer"):
            counter.per_minute(started)

    assert datetime.now(timezone.utc) - started < timedelta(seconds=2)


# --- only HTTP ---------------------------------------------------------------

@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "ftp://clickhouse/", "clickhouse:8123"]
)
def test_a_url_that_is_not_http_is_refused(url):
    with pytest.raises(ValueError, match="http or https"):
        FlowCounter(url, "netsentinel", "pw")


def test_a_url_that_is_not_http_leaves_flows_null_without_asking(
    client, auth_header, clickhouse, settings, caplog
):
    settings.clickhouse_url = "file:///etc/passwd"

    with caplog.at_level(logging.WARNING, logger="netsentinel.activity"):
        response = client.get(URL, headers=auth_header)

    assert response.status_code == 200
    assert response.json()["flows_available"] is False
    assert clickhouse.requests == []
    [warning] = warnings(caplog)
    assert "http or https" in warning
