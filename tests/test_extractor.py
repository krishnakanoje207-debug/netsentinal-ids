"""Extractor behaviour, plus the feature-parity test named in M2 s5.4.

The parity test is the one that matters most: it proves the offline path that
builds training data and the live path that scores production traffic compute
byte-identical vectors from the same packets.
"""

from __future__ import annotations

from conftest import EXPECTED_FLOWS, TCP_DPORT, TCP_SPORT, UDP_DPORT

from netsentinel.features.contract import FEATURE_DIM, SPLT_N
from netsentinel.features.extractor import FlowTracker, extract_from_pcap


def _by_port(flows, dst_port):
    matches = [f for f in flows if f.key.dst_port == dst_port]
    assert len(matches) == 1, f"expected one flow to port {dst_port}, got {len(matches)}"
    return matches[0]


def _run_live(frames):
    """Drive the streaming path exactly as the sensor will."""
    tracker = FlowTracker()
    out = []
    for ts, frame in frames:
        out.extend(tracker.update(ts, frame))
    out.extend(tracker.flush())
    return out


def test_pcap_yields_every_flow(pcap_path):
    flows = list(extract_from_pcap(pcap_path))
    assert len(flows) == EXPECTED_FLOWS


def test_bidirectional_packets_share_one_flow(pcap_path):
    tcp = _by_port(list(extract_from_pcap(pcap_path)), TCP_DPORT)
    # Client sent SYN, ACK, PSH-ACK, FIN-ACK; server sent SYN-ACK and a response.
    assert tcp.scalars["in_pkts"] == 4
    assert tcp.scalars["out_pkts"] == 2
    # Direction is decided by the first packet, so the client is always "in".
    assert tcp.key.src_port == TCP_SPORT
    assert tcp.key.dst_port == TCP_DPORT


def test_tcp_flags_are_counted(pcap_path):
    tcp = _by_port(list(extract_from_pcap(pcap_path)), TCP_DPORT)
    assert tcp.scalars["tcp_syn_count"] == 2  # SYN plus SYN-ACK
    assert tcp.scalars["tcp_fin_count"] == 1
    assert tcp.scalars["tcp_rst_count"] == 0
    assert tcp.scalars["tcp_psh_count"] == 2


def test_ttl_range_spans_both_hosts(pcap_path):
    tcp = _by_port(list(extract_from_pcap(pcap_path)), TCP_DPORT)
    assert tcp.scalars["min_ttl"] == 64
    assert tcp.scalars["max_ttl"] == 128


def test_splt_is_padded_and_signed(pcap_path):
    tcp = _by_port(list(extract_from_pcap(pcap_path)), TCP_DPORT)
    assert len(tcp.splt_len) == SPLT_N
    assert len(tcp.splt_iat) == SPLT_N
    assert tcp.splt_len[0] > 0, "first packet is client->server, so positive"
    assert tcp.splt_len[1] < 0, "second packet is the SYN-ACK, so negative"
    # Six real packets, the rest padding.
    assert all(v == 0 for v in tcp.splt_len[6:])
    assert tcp.splt_iat[0] == 0.0, "no inter-arrival time before the first packet"


def test_inter_arrival_times_in_milliseconds(pcap_path):
    tcp = _by_port(list(extract_from_pcap(pcap_path)), TCP_DPORT)
    # Gaps were 10, 10, 10, 20, 10 ms.
    assert round(tcp.scalars["iat_min_ms"], 3) == 10.0
    assert round(tcp.scalars["iat_max_ms"], 3) == 20.0
    assert round(tcp.scalars["duration_ms"], 3) == 60.0


def test_udp_and_icmp_are_tracked(pcap_path):
    flows = list(extract_from_pcap(pcap_path))
    udp = _by_port(flows, UDP_DPORT)
    assert udp.scalars["in_pkts"] == 1
    assert udp.scalars["out_pkts"] == 1
    assert udp.scalars["tcp_syn_count"] == 0

    icmp = [f for f in flows if f.key.proto == 1]
    assert len(icmp) == 1
    # ICMP has no ports; the 5-tuple shape is kept with zeros.
    assert icmp[0].key.src_port == 0


def test_fin_closes_the_flow_before_flush(frames):
    """The TCP flow must be emitted by update(), not held back until flush()."""
    tracker = FlowTracker()
    emitted = []
    for ts, frame in frames:
        emitted.extend(tracker.update(ts, frame))
    assert any(f.key.dst_port == TCP_DPORT for f in emitted), (
        "FIN should have expired the TCP flow during streaming"
    )


def test_every_flow_produces_a_full_vector(pcap_path):
    for flow in extract_from_pcap(pcap_path):
        assert len(flow.to_vector()) == FEATURE_DIM


def test_offline_and_live_paths_agree(frames, pcap_path):
    """Feature parity: the High risk in M2 s5.4, pinned by a test.

    Same packets, two code paths (PCAP reader vs streaming sensor) - the feature
    vectors must be identical, or every model trained offline is wrong online.
    """
    offline = {str(f.key): f.to_vector() for f in extract_from_pcap(pcap_path)}
    live = {str(f.key): f.to_vector() for f in _run_live(frames)}

    assert set(offline) == set(live), "the two paths disagree on which flows exist"
    for flow_id, vector in offline.items():
        assert vector == live[flow_id], f"feature drift on flow {flow_id}"
