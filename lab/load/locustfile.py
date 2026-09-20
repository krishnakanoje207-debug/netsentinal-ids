"""Load test for the API, the D13 "Locust load test" exit item.

This measures the read path an analyst actually hammers - the alert feed and one
alert's detail - under concurrency, because that is where a SOC dashboard with a
dozen open tabs polling every few seconds will find the API's ceiling first. The
write paths (approve, propose) are deliberately left out: they change state, a load
run would flood the approval queue with junk, and their cost is a database round
trip that a read already exercises.

    # against the API reached through the SSH tunnel
    locust -f lab/load/locustfile.py --host http://127.0.0.1:8000

Authentication happens once per simulated user, in on_start, rather than per
request: a token lasts thirty minutes and re-issuing one per call would measure
bcrypt instead of the endpoints. That mirrors a real client, which logs in once and
reuses the token.
"""

from __future__ import annotations

import os

from locust import HttpUser, between, task

API = "/api/v1"

# Seeded by bootstrap; override for a run against a real deployment. Never a default
# password in the file - an unset variable fails the run rather than trying a guess.
USERNAME = os.environ.get("NETSENTINEL_LOAD_USER", "analyst")
PASSWORD = os.environ.get("NETSENTINEL_LOAD_PASSWORD")


class Analyst(HttpUser):
    """One analyst working the dashboard: mostly reading the feed, occasionally
    opening an alert."""

    # A human refreshing and clicking, not a tight loop: the interesting number is
    # the API's behaviour under realistic think time, not how fast a bot can spin.
    wait_time = between(1, 4)

    def on_start(self) -> None:
        if not PASSWORD:
            raise RuntimeError(
                "set NETSENTINEL_LOAD_PASSWORD; the load test will not guess one"
            )
        response = self.client.post(
            f"{API}/auth/token",
            data={"username": USERNAME, "password": PASSWORD},
            name="POST /auth/token",
        )
        response.raise_for_status()
        token = response.json()["access_token"]
        self.client.headers.update({"Authorization": f"Bearer {token}"})

    @task(5)
    def list_alerts(self) -> None:
        """The default view, and what the dashboard polls."""
        self.client.get(f"{API}/alerts?limit=50", name="GET /alerts")

    @task(2)
    def alert_detail(self) -> None:
        """Opening the newest alert, with its explanation. The heavier read: it
        joins the detection and the matched indicators."""
        feed = self.client.get(f"{API}/alerts?limit=1", name="GET /alerts")
        if feed.status_code != 200 or not feed.json():
            return
        alert_id = feed.json()[0]["alert_id"]
        self.client.get(f"{API}/alerts/{alert_id}", name="GET /alerts/{id}")

    @task(1)
    def pending_actions(self) -> None:
        """The approval queue the analyst keeps an eye on."""
        self.client.get(f"{API}/actions/pending", name="GET /actions/pending")

    @task(1)
    def health(self) -> None:
        self.client.get(f"{API}/health", name="GET /health")
