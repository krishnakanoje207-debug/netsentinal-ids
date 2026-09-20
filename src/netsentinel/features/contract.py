"""Single source of truth for the NetSentinel-AI flow feature vector.

Both paths import from here:

  * offline  - PCAP / dataset preprocessing that produces training data (Kaggle),
  * online   - the live Early-Flow Extractor feeding the fusion scorer.

If the two ever disagree, the models silently rot. Nothing else in the code base
may hardcode a feature name, an index or a count; import ``FEATURE_ORDER``
instead. ``tests/test_contract.py`` locks the order and the dimension.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Number of leading packets kept as a sequence (M2 s4: "first 10-20 packet
# features (SPLT)"). Also the width of ClickHouse network_flows.splt_len /
# .splt_iat. Changing this invalidates every trained Tier B model.
SPLT_N = 20

# Packet-length / inter-arrival sequence, signed by direction: a positive length
# is client->server, negative is server->client. Padded with 0 when a flow ends
# before SPLT_N packets.
SPLT_LEN_FIELDS = tuple(f"splt_len_{i}" for i in range(SPLT_N))
SPLT_IAT_FIELDS = tuple(f"splt_iat_{i}" for i in range(SPLT_N))

# Flow-level aggregates. Names in CAPS mirror the NetFlow v2 fields of
# NF-UNSW-NB15-v3 / NF-UQ-NIDS-v2 so dataset columns map straight onto them.
SCALAR_FIELDS = (
    "proto",
    "l4_src_port",
    "l4_dst_port",
    "duration_ms",
    "in_pkts",
    "out_pkts",
    "in_bytes",
    "out_bytes",
    "pkt_rate",
    "byte_rate",
    "bytes_per_pkt_in",
    "bytes_per_pkt_out",
    "bytes_ratio_out_in",
    "len_min_in",
    "len_max_in",
    "len_mean_in",
    "len_std_in",
    "len_min_out",
    "len_max_out",
    "len_mean_out",
    "len_std_out",
    "iat_min_ms",
    "iat_max_ms",
    "iat_mean_ms",
    "iat_std_ms",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_fin_count",
    "tcp_rst_count",
    "tcp_psh_count",
    "tcp_urg_count",
    "min_ttl",
    "max_ttl",
)

# THE contract. Index i of a model input vector is FEATURE_ORDER[i], for every
# model, in training and in production alike.
FEATURE_ORDER: tuple[str, ...] = SCALAR_FIELDS + SPLT_LEN_FIELDS + SPLT_IAT_FIELDS

FEATURE_DIM = len(FEATURE_ORDER)


@dataclass(slots=True)
class FlowKey:
    """Canonical bidirectional 5-tuple.

    Both directions of one conversation must land on the same key, so the
    initiator (the side of the first packet seen) is always stored as ``src``.
    """

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: int

    def __str__(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.proto}"


@dataclass(slots=True)
class FlowFeatures:
    """One scored unit: the feature vector plus the metadata around it.

    ``scalars`` holds SCALAR_FIELDS by name; ``splt_len`` / ``splt_iat`` are
    fixed-width SPLT_N lists. Metadata (key, timestamps, label) is deliberately
    kept out of the vector so it can never leak into a model.

    A plain slotted dataclass rather than a pydantic model: this sits in the
    per-flow hot path with a sub-5 ms budget (M2 s4), and validation belongs at
    the API boundary instead.
    """

    key: FlowKey
    ts_start: float
    ts_last: float
    scalars: dict[str, float] = field(default_factory=dict)
    splt_len: list[int] = field(default_factory=list)
    splt_iat: list[float] = field(default_factory=list)
    label: str | None = None  # ground truth, offline only; never an input

    def to_vector(self) -> list[float]:
        """Flatten to model input order. Raises on a contract violation."""
        if len(self.splt_len) != SPLT_N or len(self.splt_iat) != SPLT_N:
            raise ValueError(
                f"SPLT width mismatch: got len={len(self.splt_len)} "
                f"iat={len(self.splt_iat)}, contract is {SPLT_N}"
            )
        missing = [name for name in SCALAR_FIELDS if name not in self.scalars]
        if missing:
            raise ValueError(f"missing scalar features: {missing}")

        vector = [float(self.scalars[name]) for name in SCALAR_FIELDS]
        vector.extend(float(v) for v in self.splt_len)
        vector.extend(float(v) for v in self.splt_iat)
        return vector

    def as_row(self) -> dict[str, object]:
        """Flat dict for ClickHouse network_flows / Parquet training sets."""
        row: dict[str, object] = {
            "ts": self.ts_start,
            "flow_id": str(self.key),
            "src_ip": self.key.src_ip,
            "dst_ip": self.key.dst_ip,
            "src_port": self.key.src_port,
            "dst_port": self.key.dst_port,
            "label": self.label,
        }
        row.update({name: self.scalars[name] for name in SCALAR_FIELDS})
        row.update(dict(zip(SPLT_LEN_FIELDS, self.splt_len)))
        row.update(dict(zip(SPLT_IAT_FIELDS, self.splt_iat)))
        return row
