"""Fixtures for the sensor agent.

A stub scorer rather than a real ONNX model: the scorer has its own tests, and what needs
proving here is that the agent publishes every flow it extracts - including the ones no
model would score.

The capture file is built here rather than imported from another package's tests. Test
directories are not packages, so a shared helper would have to be importable across them,
and that is exactly the collision that once broke a full-suite run.

For the same reason everything shared with the test modules is handed out as a fixture.
``from conftest import ...`` resolves through sys.path, where every tests directory is
prepended, so it silently binds to whichever package's conftest was added last.
"""

from __future__ import annotations

from dataclasses import dataclass

import dpkt
import pytest

from netsentinel_core.features.contract import SCALAR_FIELDS, SPLT_N
from netsentinel_scoring.engine import Verdict

CLIENT_IP, SERVER_IP = "10.0.0.5", "10.0.0.9"
CLIENT_MAC, SERVER_MAC = b"\xaa\xbb\xcc\x00\x00\x01", b"\xaa\xbb\xcc\x00\x00\x02"

TCP_SPORT, TCP_DPORT = 44321, 80
UDP_SPORT, UDP_DPORT = 51000, 53

#: TCP (closes cleanly), UDP, ICMP.
EXPECTED_FLOWS = 3


def _ip_bytes(dotted: str) -> bytes:
    return bytes(int(octet) for octet in dotted.split("."))


def _frame(src: str, dst: str, ttl: int, payload, to_server: bool) -> bytes:
    proto = (
        dpkt.ip.IP_PROTO_TCP
        if isinstance(payload, dpkt.tcp.TCP)
        else dpkt.ip.IP_PROTO_UDP
        if isinstance(payload, dpkt.udp.UDP)
        else dpkt.ip.IP_PROTO_ICMP
    )
    ip = dpkt.ip.IP(src=_ip_bytes(src), dst=_ip_bytes(dst), ttl=ttl, p=proto, data=payload)
    ip.len = len(ip)
    eth = dpkt.ethernet.Ethernet(
        src=CLIENT_MAC if to_server else SERVER_MAC,
        dst=SERVER_MAC if to_server else CLIENT_MAC,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def _to_server(payload) -> bytes:
    return _frame(CLIENT_IP, SERVER_IP, 64, payload, to_server=True)


def _to_client(payload) -> bytes:
    return _frame(SERVER_IP, CLIENT_IP, 128, payload, to_server=False)


def _tcp(sport, dport, flags, data=b"") -> dpkt.tcp.TCP:
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, ack=1, data=data)


@pytest.fixture(scope="session")
def frames() -> list[tuple[float, bytes]]:
    syn = dpkt.tcp.TH_SYN
    syn_ack = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
    fin_ack = dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK
    udp = dpkt.udp.UDP(sport=UDP_SPORT, dport=UDP_DPORT, data=b"\x00" * 30)
    udp.ulen = len(udp)
    echo = dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"p" * 16))

    return [
        (1000.000, _to_server(_tcp(TCP_SPORT, TCP_DPORT, syn))),
        (1000.010, _to_client(_tcp(TCP_DPORT, TCP_SPORT, syn_ack))),
        (1000.020, _to_server(_tcp(TCP_SPORT, TCP_DPORT, fin_ack))),
        (1000.100, _to_server(udp)),
        (1000.200, _to_server(echo)),
    ]


@pytest.fixture(scope="session")
def pcap_path(frames, tmp_path_factory) -> str:
    path = tmp_path_factory.mktemp("capture") / "sensor.pcap"
    with open(path, "wb") as handle:
        writer = dpkt.pcap.Writer(handle)
        for timestamp, frame in frames:
            writer.writepkt(frame, ts=timestamp)
    return str(path)


@pytest.fixture(scope="session")
def write_window():
    """Write packets as one pcapng capture window: ``write_window(path, packets)``.

    pcapng because that is what pktmon's capture loop drops into the folder.
    """

    def write(path, packets: list[tuple[float, bytes]]):
        with open(path, "wb") as handle:
            writer = dpkt.pcapng.Writer(handle)
            for timestamp, frame in packets:
                writer.writepkt(frame, ts=timestamp)
        return path

    return write


@dataclass(frozen=True)
class StubModel:
    """Just the identity fields the agent reads off a LoadedModel."""

    tier: str
    name: str
    version: str
    mode: str


class StubScorer:
    """Returns a canned verdict. Records what it was asked to score."""

    def __init__(self, risk: float | None = 0.8, threshold: float | None = 0.5) -> None:
        self.risk = risk
        self.threshold = threshold
        self.scored: list = []
        self.models = [
            StubModel("A", "stub", "0", "shadow" if risk is None else "active")
        ]

    def score(self, features):
        self.scored.append(features)
        missing = [name for name in SCALAR_FIELDS if name not in features.scalars]
        assert not missing, f"agent handed the scorer an incomplete flow: {missing}"
        assert len(features.splt_len) == SPLT_N
        return Verdict(
            flow_id=str(features.key),
            risk_score=self.risk,
            model_scores={"tier_a": self.risk if self.risk is not None else 0.0},
            decided_by=["stub:0"] if self.risk is not None else [],
            shadow=self.risk is None,
            threshold=self.threshold,
        )


@pytest.fixture(scope="session")
def expected_flows() -> int:
    return EXPECTED_FLOWS


@pytest.fixture(scope="session")
def tcp_dport() -> int:
    return TCP_DPORT


@pytest.fixture(scope="session")
def open_flow_frames() -> list[tuple[float, bytes]]:
    """A handshake that never closes: no FIN, and no idle timeout reached."""
    return [
        (1000.0, _to_server(_tcp(TCP_SPORT, TCP_DPORT, dpkt.tcp.TH_SYN))),
        (1000.01, _to_server(_tcp(TCP_SPORT, TCP_DPORT, dpkt.tcp.TH_ACK))),
    ]


@pytest.fixture(scope="session")
def tcp_frame():
    """Build one TCP frame of the test connection: ``tcp_frame(flags, to_server=True)``."""

    def build(flags: int, to_server: bool = True, sport: int = TCP_SPORT) -> bytes:
        if to_server:
            return _to_server(_tcp(sport, TCP_DPORT, flags))
        return _to_client(_tcp(TCP_DPORT, sport, flags))

    return build


@pytest.fixture
def scorer() -> StubScorer:
    return StubScorer()


@pytest.fixture
def shadow_scorer() -> StubScorer:
    """Every verdict undecided, which is the D8 starting posture."""
    return StubScorer(risk=None, threshold=None)
