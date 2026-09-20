"""Early-Flow Extractor: packets in, FlowFeatures out.

The same accumulation logic runs in both directions of the feature-parity risk
(M2 s5.4): ``extract_from_pcap`` for training data and captured lab PCAPs,
``FlowTracker.update`` for the live sensor. Neither path may compute a feature
the other does not.

Memory is O(1) per flow - packet lengths are folded into running sums rather
than kept in a list - because the sensor has to survive on a small host.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Iterator

import dpkt

from netsentinel_core.features.contract import SPLT_N, FlowFeatures, FlowKey

# A flow is closed after this much silence, or once it has been open this long,
# mirroring standard NetFlow idle/active timeouts.
IDLE_TIMEOUT_S = 15.0
ACTIVE_TIMEOUT_S = 120.0

_TCP_FLAGS = (
    ("tcp_syn_count", dpkt.tcp.TH_SYN),
    ("tcp_ack_count", dpkt.tcp.TH_ACK),
    ("tcp_fin_count", dpkt.tcp.TH_FIN),
    ("tcp_rst_count", dpkt.tcp.TH_RST),
    ("tcp_psh_count", dpkt.tcp.TH_PUSH),
    ("tcp_urg_count", dpkt.tcp.TH_URG),
)


@dataclass(slots=True)
class _Direction:
    """Running per-direction statistics, O(1) memory."""

    pkts: int = 0
    bytes: int = 0
    len_min: int = 0
    len_max: int = 0
    len_sum: int = 0
    len_sumsq: int = 0

    def add(self, length: int) -> None:
        if self.pkts == 0:
            self.len_min = self.len_max = length
        else:
            self.len_min = min(self.len_min, length)
            self.len_max = max(self.len_max, length)
        self.pkts += 1
        self.bytes += length
        self.len_sum += length
        self.len_sumsq += length * length

    @property
    def len_mean(self) -> float:
        return self.len_sum / self.pkts if self.pkts else 0.0

    @property
    def len_std(self) -> float:
        if self.pkts < 2:
            return 0.0
        var = self.len_sumsq / self.pkts - self.len_mean**2
        return math.sqrt(var) if var > 0 else 0.0


@dataclass(slots=True)
class _FlowState:
    """Everything accumulated for one flow before it is emitted."""

    key: FlowKey
    ts_start: float
    ts_last: float
    fwd: _Direction = field(default_factory=_Direction)
    bwd: _Direction = field(default_factory=_Direction)
    iat_min: float = 0.0
    iat_max: float = 0.0
    iat_sum: float = 0.0
    iat_sumsq: float = 0.0
    iat_count: int = 0
    flags: dict[str, int] = field(default_factory=lambda: {n: 0 for n, _ in _TCP_FLAGS})
    ttl_min: int = 0
    ttl_max: int = 0
    splt_len: list[int] = field(default_factory=list)
    splt_iat: list[float] = field(default_factory=list)
    closed: bool = False

    def add_packet(self, ts: float, length: int, is_forward: bool, ttl: int,
                   tcp_flags: int | None) -> None:
        first_packet = self.fwd.pkts + self.bwd.pkts == 0
        gap_ms = (ts - self.ts_last) * 1000.0

        if not first_packet:
            if self.iat_count == 0:
                self.iat_min = self.iat_max = gap_ms
            else:
                self.iat_min = min(self.iat_min, gap_ms)
                self.iat_max = max(self.iat_max, gap_ms)
            self.iat_sum += gap_ms
            self.iat_sumsq += gap_ms * gap_ms
            self.iat_count += 1

        if len(self.splt_len) < SPLT_N:
            # Direction is encoded in the sign, so one array carries both.
            self.splt_len.append(length if is_forward else -length)
            self.splt_iat.append(0.0 if first_packet else gap_ms)

        (self.fwd if is_forward else self.bwd).add(length)

        if first_packet:
            self.ttl_min = self.ttl_max = ttl
        else:
            self.ttl_min = min(self.ttl_min, ttl)
            self.ttl_max = max(self.ttl_max, ttl)

        if tcp_flags is not None:
            for name, bit in _TCP_FLAGS:
                if tcp_flags & bit:
                    self.flags[name] += 1
            # A FIN or RST ends the conversation; the tracker flushes it next sweep.
            if tcp_flags & (dpkt.tcp.TH_FIN | dpkt.tcp.TH_RST):
                self.closed = True

        self.ts_last = ts

    @property
    def iat_mean(self) -> float:
        return self.iat_sum / self.iat_count if self.iat_count else 0.0

    @property
    def iat_std(self) -> float:
        if self.iat_count < 2:
            return 0.0
        var = self.iat_sumsq / self.iat_count - self.iat_mean**2
        return math.sqrt(var) if var > 0 else 0.0

    def finalise(self) -> FlowFeatures:
        duration_ms = (self.ts_last - self.ts_start) * 1000.0
        duration_s = duration_ms / 1000.0
        pkts = self.fwd.pkts + self.bwd.pkts
        total_bytes = self.fwd.bytes + self.bwd.bytes

        scalars: dict[str, float] = {
            "proto": self.key.proto,
            "l4_src_port": self.key.src_port,
            "l4_dst_port": self.key.dst_port,
            "duration_ms": duration_ms,
            "in_pkts": self.fwd.pkts,
            "out_pkts": self.bwd.pkts,
            "in_bytes": self.fwd.bytes,
            "out_bytes": self.bwd.bytes,
            "pkt_rate": pkts / duration_s if duration_s > 0 else 0.0,
            "byte_rate": total_bytes / duration_s if duration_s > 0 else 0.0,
            "bytes_per_pkt_in": self.fwd.len_mean,
            "bytes_per_pkt_out": self.bwd.len_mean,
            "bytes_ratio_out_in": self.bwd.bytes / self.fwd.bytes if self.fwd.bytes else 0.0,
            "len_min_in": self.fwd.len_min,
            "len_max_in": self.fwd.len_max,
            "len_mean_in": self.fwd.len_mean,
            "len_std_in": self.fwd.len_std,
            "len_min_out": self.bwd.len_min,
            "len_max_out": self.bwd.len_max,
            "len_mean_out": self.bwd.len_mean,
            "len_std_out": self.bwd.len_std,
            "iat_min_ms": self.iat_min,
            "iat_max_ms": self.iat_max,
            "iat_mean_ms": self.iat_mean,
            "iat_std_ms": self.iat_std,
            "min_ttl": self.ttl_min,
            "max_ttl": self.ttl_max,
        }
        scalars.update({name: float(self.flags[name]) for name, _ in _TCP_FLAGS})

        pad = SPLT_N - len(self.splt_len)
        return FlowFeatures(
            key=self.key,
            ts_start=self.ts_start,
            ts_last=self.ts_last,
            scalars=scalars,
            splt_len=self.splt_len + [0] * pad,
            splt_iat=self.splt_iat + [0.0] * pad,
        )


class FlowTracker:
    """Stateful packet aggregator shared by the offline and live paths."""

    def __init__(self, idle_timeout: float = IDLE_TIMEOUT_S,
                 active_timeout: float = ACTIVE_TIMEOUT_S) -> None:
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self._flows: dict[tuple, _FlowState] = {}

    def update(self, ts: float, frame: bytes) -> list[FlowFeatures]:
        """Absorb one link-layer frame; return any flows it caused to expire."""
        parsed = _parse_frame(frame)
        if parsed is None:
            return []
        src_ip, dst_ip, src_port, dst_port, proto, ttl, tcp_flags, length = parsed

        fwd_id = (src_ip, dst_ip, src_port, dst_port, proto)
        bwd_id = (dst_ip, src_ip, dst_port, src_port, proto)

        if fwd_id in self._flows:
            state, is_forward = self._flows[fwd_id], True
        elif bwd_id in self._flows:
            state, is_forward = self._flows[bwd_id], False
        else:
            # First packet seen defines the initiator, so both directions of the
            # conversation share one canonical key.
            state = _FlowState(
                key=FlowKey(src_ip, dst_ip, src_port, dst_port, proto),
                ts_start=ts,
                ts_last=ts,
            )
            self._flows[fwd_id] = state
            is_forward = True

        state.add_packet(ts, length, is_forward, ttl, tcp_flags)
        return self._expire(ts)

    def _expire(self, now: float) -> list[FlowFeatures]:
        done = [
            fid
            for fid, st in self._flows.items()
            if st.closed
            or now - st.ts_last >= self.idle_timeout
            or now - st.ts_start >= self.active_timeout
        ]
        return [self._flows.pop(fid).finalise() for fid in done]

    def flush(self) -> list[FlowFeatures]:
        """Emit every flow still open. Called at end of capture or shutdown."""
        out = [st.finalise() for st in self._flows.values()]
        self._flows.clear()
        return out


def _parse_frame(frame: bytes) -> tuple | None:
    """Ethernet -> IPv4 -> TCP/UDP/ICMP. Returns None for anything else."""
    try:
        eth = dpkt.ethernet.Ethernet(frame)
    except dpkt.UnpackError:
        return None
    ip = eth.data
    if not isinstance(ip, dpkt.ip.IP):
        return None

    length = ip.len
    proto, ttl = ip.p, ip.ttl
    payload = ip.data
    if isinstance(payload, dpkt.tcp.TCP):
        return (_ip(ip.src), _ip(ip.dst), payload.sport, payload.dport,
                proto, ttl, payload.flags, length)
    if isinstance(payload, dpkt.udp.UDP):
        return (_ip(ip.src), _ip(ip.dst), payload.sport, payload.dport,
                proto, ttl, None, length)
    if isinstance(payload, dpkt.icmp.ICMP):
        # ICMP has no ports; 0/0 keeps the 5-tuple shape for scans and floods.
        return (_ip(ip.src), _ip(ip.dst), 0, 0, proto, ttl, None, length)
    return None


def _ip(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def extract_from_pcap(path: str) -> Iterator[FlowFeatures]:
    """Yield one FlowFeatures per flow in a PCAP. Used for training data."""
    tracker = FlowTracker()
    with open(path, "rb") as fh:
        # ValueError for a wrong magic number, NeedData for a file too short to hold a
        # header; a truncated capture must not surface as a raw dpkt traceback.
        try:
            reader = dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.UnpackError):
            fh.seek(0)
            reader = dpkt.pcapng.Reader(fh)
        for ts, frame in reader:
            yield from tracker.update(ts, frame)
    yield from tracker.flush()


__all__ = ["FlowTracker", "extract_from_pcap"]
