"""Synthetic traffic fixtures.

The lab PCAPs are not in the repo (too large, and not reproducible on a clean
checkout), so the test suite builds its own deterministic capture: one TCP
conversation that closes cleanly, one UDP exchange and one ICMP echo pair.
"""

from __future__ import annotations

import dpkt
import pytest

CLIENT_MAC = b"\xaa\xbb\xcc\x00\x00\x01"
SERVER_MAC = b"\xaa\xbb\xcc\x00\x00\x02"

CLIENT_IP = "10.0.0.5"
SERVER_IP = "10.0.0.9"
CLIENT_TTL = 64
SERVER_TTL = 128


def _ip_bytes(dotted: str) -> bytes:
    return bytes(int(o) for o in dotted.split("."))


def _frame(src_ip: str, dst_ip: str, ttl: int, payload, to_server: bool) -> bytes:
    ip = dpkt.ip.IP(
        src=_ip_bytes(src_ip),
        dst=_ip_bytes(dst_ip),
        ttl=ttl,
        p=payload_proto(payload),
        data=payload,
    )
    ip.len = len(ip)  # dpkt leaves total length at 0 unless set explicitly
    eth = dpkt.ethernet.Ethernet(
        src=CLIENT_MAC if to_server else SERVER_MAC,
        dst=SERVER_MAC if to_server else CLIENT_MAC,
        type=dpkt.ethernet.ETH_TYPE_IP,
        data=ip,
    )
    return bytes(eth)


def payload_proto(payload) -> int:
    if isinstance(payload, dpkt.tcp.TCP):
        return dpkt.ip.IP_PROTO_TCP
    if isinstance(payload, dpkt.udp.UDP):
        return dpkt.ip.IP_PROTO_UDP
    return dpkt.ip.IP_PROTO_ICMP


def _tcp(sport: int, dport: int, flags: int, data: bytes = b"") -> dpkt.tcp.TCP:
    return dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, ack=1, data=data)


def _udp(sport: int, dport: int, data: bytes) -> dpkt.udp.UDP:
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=data)
    udp.ulen = len(udp)
    return udp


def _to_server(payload) -> bytes:
    return _frame(CLIENT_IP, SERVER_IP, CLIENT_TTL, payload, to_server=True)


def _to_client(payload) -> bytes:
    return _frame(SERVER_IP, CLIENT_IP, SERVER_TTL, payload, to_server=False)


#: Expected flow counts, asserted by the tests so a parser regression is loud.
EXPECTED_FLOWS = 3

TCP_SPORT, TCP_DPORT = 44321, 80
UDP_SPORT, UDP_DPORT = 51000, 53


@pytest.fixture(scope="session")
def frames() -> list[tuple[float, bytes]]:
    """A deterministic (timestamp, ethernet frame) list.

    Timestamps are spaced in tens of milliseconds so inter-arrival features come
    out as round numbers and the assertions stay readable.
    """
    syn, syn_ack, ack, psh_ack, fin_ack = (
        dpkt.tcp.TH_SYN,
        dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK,
        dpkt.tcp.TH_ACK,
        dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK,
        dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK,
    )
    return [
        # TCP: handshake, one request, one response, clean close (6 packets).
        (1000.000, _to_server(_tcp(TCP_SPORT, TCP_DPORT, syn))),
        (1000.010, _to_client(_tcp(TCP_DPORT, TCP_SPORT, syn_ack))),
        (1000.020, _to_server(_tcp(TCP_SPORT, TCP_DPORT, ack))),
        (1000.030, _to_server(_tcp(TCP_SPORT, TCP_DPORT, psh_ack, b"GET / HTTP/1.1\r\n\r\n"))),
        (1000.050, _to_client(_tcp(TCP_DPORT, TCP_SPORT, psh_ack, b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 100))),
        (1000.060, _to_server(_tcp(TCP_SPORT, TCP_DPORT, fin_ack))),
        # UDP: a DNS-shaped query and reply (2 packets).
        (1000.100, _to_server(_udp(UDP_SPORT, UDP_DPORT, b"\x00" * 30))),
        (1000.120, _to_client(_udp(UDP_DPORT, UDP_SPORT, b"\x00" * 60))),
        # ICMP: echo request and reply (2 packets).
        (1000.200, _to_server(dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"p" * 32)))),
        (1000.220, _to_client(dpkt.icmp.ICMP(type=0, data=dpkt.icmp.ICMP.Echo(id=1, seq=1, data=b"p" * 32)))),
    ]


@pytest.fixture(scope="session")
def pcap_path(frames, tmp_path_factory) -> str:
    """The same frames written out as a PCAP file, for the offline path."""
    path = tmp_path_factory.mktemp("captures") / "synthetic.pcap"
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for ts, frame in frames:
            writer.writepkt(frame, ts=ts)
    return str(path)
