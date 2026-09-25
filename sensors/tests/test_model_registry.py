"""The sensor taking each model's mode from the model registry at start.

The rules under test are the safety ones. A model decides only when the registry says
it is active; a model the registry does not list runs in shadow; and a registry that
cannot be read stops the sensor, rather than letting it fall back to its cards or to
all-shadow and look healthy while running a posture nobody chose.

The models are stand-ins: what is under test is which mode each one ends up in, and
the ONNX loading around that has its own tests in scoring.
"""

from __future__ import annotations

import json
import logging
import socket
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError

import pytest

from netsentinel_sensor import agent
from netsentinel_sensor.agent import (
    REGISTRY_PATH,
    REGISTRY_TOKEN_ENV,
    RegistryUnavailable,
    build_scorer,
    read_registry,
    registry_fetcher,
)

TOKEN = "a-sensor-token-used-only-by-these-tests"

#: The registry as the demo leaves it: the autoencoder decides Tier D, the forest
#: observes beside it.
REGISTERED = [
    {"name": "tier_a_lightgbm", "version": "1.0.0", "tier": "A", "mode": "active"},
    {"name": "tier_d_autoencoder", "version": "1.1.0", "tier": "D", "mode": "active"},
    {"name": "tier_d_isolation_forest", "version": "1.0.2", "tier": "D", "mode": "shadow"},
]

MODES = {(row["name"], row["version"]): row["mode"] for row in REGISTERED}


@dataclass
class CardModel:
    """What build_scorer and FusionScorer read off a LoadedModel, mutable like one."""

    tier: str
    name: str
    version: str
    mode: str

    @property
    def is_active(self) -> bool:
        return self.mode == "active"


@pytest.fixture
def cards(monkeypatch) -> dict[str, CardModel]:
    """Card paths to stand-in models, every card saying shadow as the committed ones do."""
    loaded = {
        "tier_a": CardModel("A", "tier_a_lightgbm", "1.0.0", "shadow"),
        "tier_d_ae": CardModel("D", "tier_d_autoencoder", "1.1.0", "shadow"),
        "tier_d": CardModel("D", "tier_d_isolation_forest", "1.0.2", "shadow"),
    }
    monkeypatch.setattr(agent, "load_model", lambda path: loaded[path.name])
    return loaded


def modes_of(scorer) -> dict[str, str]:
    return {model.name: model.mode for model in scorer.models}


@pytest.fixture
def registry_api():
    """A stand-in API serving the modes endpoint, refusing any other token.

    Yields its base URL and the requests it received.
    """
    received: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            received.append((self.path, self.headers.get("Authorization")))
            if self.headers.get("Authorization") != f"Bearer {TOKEN}":
                self.send_error(401)
                return
            body = json.dumps(REGISTERED).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", received
    server.shutdown()
    server.server_close()


@pytest.fixture
def quiet_main(monkeypatch):
    """main() with no retry pauses and without replacing the test run's signal handlers."""
    monkeypatch.setattr(agent, "REGISTRY_RETRY_DELAYS", ())
    monkeypatch.setattr(agent.signal, "signal", lambda *_args: None)
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, TOKEN)


# --- resolving each model's mode ---------------------------------------------

def test_a_model_the_registry_lists_active_decides(cards):
    scorer = build_scorer(["tier_a", "tier_d_ae", "tier_d"], MODES)

    assert modes_of(scorer) == {
        "tier_a_lightgbm": "active",
        "tier_d_autoencoder": "active",
        "tier_d_isolation_forest": "shadow",
    }
    assert scorer.has_active_model


def test_a_model_the_registry_lists_as_shadow_does_not_decide_whatever_its_card_says(cards):
    cards["tier_d"].mode = "active"

    scorer = build_scorer(["tier_d"], MODES)

    assert modes_of(scorer) == {"tier_d_isolation_forest": "shadow"}
    assert not scorer.has_active_model


def test_an_unregistered_model_runs_in_shadow_with_a_warning(cards, caplog):
    """Even with a card that says active: an unregistered model must never decide."""
    cards["tier_a"].mode = "active"

    with caplog.at_level(logging.WARNING, logger="netsentinel.sensor"):
        scorer = build_scorer(["tier_a"], {})

    assert modes_of(scorer) == {"tier_a_lightgbm": "shadow"}
    assert "tier_a_lightgbm:1.0.0 is not in the model registry" in caplog.text


def test_a_retired_model_runs_in_shadow(cards, caplog):
    with caplog.at_level(logging.WARNING, logger="netsentinel.sensor"):
        scorer = build_scorer(["tier_d"], {("tier_d_isolation_forest", "1.0.2"): "retired"})

    assert modes_of(scorer) == {"tier_d_isolation_forest": "shadow"}
    assert "as retired" in caplog.text


def test_without_the_registry_each_card_decides(cards):
    """No --registry-url: the offline --pcap runs and the replay keep their behaviour."""
    cards["tier_a"].mode = "active"

    scorer = build_scorer(["tier_a", "tier_d"])

    assert modes_of(scorer) == {"tier_a_lightgbm": "active", "tier_d_isolation_forest": "shadow"}


def test_every_model_s_resolved_mode_is_logged(cards, caplog):
    with caplog.at_level(logging.INFO, logger="netsentinel.sensor"):
        build_scorer(["tier_d_ae", "tier_d"], MODES)

    assert "tier_d_autoencoder:1.1.0 in active mode, per the model registry" in caplog.text
    assert "tier_d_isolation_forest:1.0.2 in shadow mode, per the model registry" in caplog.text


# --- reading the registry -----------------------------------------------------

def test_the_registry_is_read_over_http_with_the_sensor_token(registry_api):
    url, received = registry_api

    modes = read_registry(registry_fetcher(url, TOKEN), delays=())

    assert modes == MODES
    assert received == [(REGISTRY_PATH, f"Bearer {TOKEN}")]


def test_a_registry_still_starting_is_waited_for():
    replies = iter([URLError(ConnectionRefusedError()), URLError(ConnectionRefusedError())])
    pauses: list[float] = []

    def fetch():
        reply = next(replies, None)
        if reply is not None:
            raise reply
        return REGISTERED

    assert read_registry(fetch, delays=(1.0, 2.0, 4.0), sleep=pauses.append) == MODES
    assert pauses == [1.0, 2.0]


def test_an_unreachable_registry_is_given_up_on_after_a_bounded_wait():
    attempts: list[int] = []
    pauses: list[float] = []

    def fetch():
        attempts.append(1)
        raise URLError(ConnectionRefusedError())

    with pytest.raises(RegistryUnavailable, match="after 3 attempts"):
        read_registry(fetch, delays=(1.0, 2.0), sleep=pauses.append)
    assert len(attempts) == 3
    assert pauses == [1.0, 2.0]


def test_a_reply_that_is_not_a_model_list_is_not_trusted():
    with pytest.raises(RegistryUnavailable):
        read_registry(lambda: {"detail": "not authenticated"}, delays=())


def test_only_http_urls_are_accepted():
    with pytest.raises(ValueError, match="http or https"):
        registry_fetcher("file:///etc/passwd", TOKEN)


# --- main ---------------------------------------------------------------------

def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_main_runs_each_model_in_its_registry_mode(
    quiet_main, monkeypatch, registry_api, scorer, pcap_path
):
    url, _received = registry_api
    passed: list = []

    def recording_build_scorer(card_paths, modes=None):
        passed.append(modes)
        return scorer

    monkeypatch.setattr(agent, "build_scorer", recording_build_scorer)

    code = agent.main(
        ["--pcap", pcap_path, "--models", "card.json", "--registry-url", url, "--dry-run"]
    )

    assert code == 0
    assert passed == [MODES]


def test_main_exits_when_the_registry_is_unreachable(quiet_main, monkeypatch, caplog):
    monkeypatch.setattr(
        agent, "build_scorer", lambda *_args: pytest.fail("started without the registry")
    )

    with caplog.at_level(logging.ERROR, logger="netsentinel.sensor"):
        code = agent.main(
            ["--pcap", "unused.pcap", "--models", "card.json",
             "--registry-url", f"http://127.0.0.1:{_closed_port()}"]
        )

    assert code == 1
    assert "could not read the model registry" in caplog.text


def test_main_exits_when_the_registry_refuses_the_token(
    quiet_main, monkeypatch, registry_api
):
    url, _received = registry_api
    monkeypatch.setenv(REGISTRY_TOKEN_ENV, "some-other-token")
    monkeypatch.setattr(
        agent, "build_scorer", lambda *_args: pytest.fail("started without the registry")
    )

    code = agent.main(["--pcap", "unused.pcap", "--models", "card.json", "--registry-url", url])

    assert code == 1


def test_main_refuses_a_non_http_registry_url(quiet_main):
    with pytest.raises(SystemExit) as exited:
        agent.main(
            ["--pcap", "unused.pcap", "--models", "card.json",
             "--registry-url", "file:///etc/passwd"]
        )
    assert exited.value.code == 2


def test_main_refuses_a_registry_url_without_a_token(quiet_main, monkeypatch):
    monkeypatch.delenv(REGISTRY_TOKEN_ENV)

    with pytest.raises(SystemExit) as exited:
        agent.main(
            ["--pcap", "unused.pcap", "--models", "card.json",
             "--registry-url", "http://127.0.0.1:8010"]
        )
    assert exited.value.code == 2
