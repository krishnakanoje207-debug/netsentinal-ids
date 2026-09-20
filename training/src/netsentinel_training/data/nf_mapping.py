"""Map NetFlow dataset columns onto the NetSentinel feature contract.

Covers the NF-* family (NF-UNSW-NB15-v3, NF-UQ-NIDS-v2, NF-ToN-IoT), which
share a NetFlow v2/v3 column layout.

The mapping is declared, never inferred. If the real CSV header does not match
what is declared here, ``resolve_columns`` raises and names the columns it could
not find, so a schema surprise fails at prep time instead of quietly training a
model on the wrong data.
"""

from __future__ import annotations

import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES

#: Contract field -> NF column it is read from directly.
DIRECT: dict[str, str] = {
    "proto": "PROTOCOL",
    "l4_src_port": "L4_SRC_PORT",
    "l4_dst_port": "L4_DST_PORT",
    "duration_ms": "FLOW_DURATION_MILLISECONDS",
    "in_pkts": "IN_PKTS",
    "out_pkts": "OUT_PKTS",
    "in_bytes": "IN_BYTES",
    "out_bytes": "OUT_BYTES",
    "min_ttl": "MIN_TTL",
    "max_ttl": "MAX_TTL",
}

#: Contract fields computed from the direct ones. Every formula here must match
#: _FlowState.finalise() in features/extractor.py exactly.
DERIVED: tuple[str, ...] = (
    "pkt_rate",
    "byte_rate",
    "bytes_per_pkt_in",
    "bytes_per_pkt_out",
    "bytes_ratio_out_in",
)

#: Label columns in the NF-* family: binary flag plus attack family name.
LABEL_BINARY = "Label"
LABEL_ATTACK = "Attack"

#: Host columns, used for the leakage-safe holdout split and then dropped - they
#: are never model inputs, because an IP address is an identifier, not a
#: behaviour, and a model that learns it will not generalise off the testbed.
SRC_HOST = "IPV4_SRC_ADDR"
DST_HOST = "IPV4_DST_ADDR"

#: Candidate timestamp columns. NF-UNSW-NB15-v2 has none; some v3 exports carry
#: one. Presence decides which split strategy prep can use.
TIMESTAMP_CANDIDATES: tuple[str, ...] = (
    "FLOW_START_MILLISECONDS",
    "FLOW_START_MICROSECONDS",
    "Stime",
    "timestamp",
)


class SchemaMismatch(RuntimeError):
    """The CSV header does not carry the columns the mapping expects."""


def resolve_columns(header: list[str]) -> dict[str, str]:
    """Check a real CSV header against DIRECT, returning the usable mapping.

    Raises SchemaMismatch listing what is absent, rather than letting a renamed
    column become a silently wrong feature.
    """
    missing = {field: col for field, col in DIRECT.items() if col not in header}
    if missing:
        raise SchemaMismatch(
            "NF columns declared in nf_mapping.DIRECT are absent from the CSV: "
            + ", ".join(f"{col} (for {field})" for field, col in sorted(missing.items()))
            + f". Header has {len(header)} columns: {sorted(header)}. "
            "Update DIRECT to match this dataset variant."
        )
    if LABEL_BINARY not in header:
        raise SchemaMismatch(f"label column {LABEL_BINARY!r} is absent from the CSV")
    return dict(DIRECT)


def find_timestamp(header: list[str]) -> str | None:
    """Return the timestamp column if this dataset variant has one."""
    for candidate in TIMESTAMP_CANDIDATES:
        if candidate in header:
            return candidate
    return None


def to_contract(frame: pl.LazyFrame) -> pl.LazyFrame:
    """Rename NF columns to contract names and add the derived features.

    The derived formulas mirror features/extractor.py: rates are per second and
    guard against a zero duration, and a ratio with a zero denominator is 0.0
    rather than null, so trees never see a missing value where the extractor
    would emit a number.
    """
    renamed = frame.rename({col: field for field, col in DIRECT.items()})

    duration_s = pl.col("duration_ms") / 1000.0
    total_pkts = pl.col("in_pkts") + pl.col("out_pkts")
    total_bytes = pl.col("in_bytes") + pl.col("out_bytes")

    def per_second(numerator: pl.Expr) -> pl.Expr:
        return (
            pl.when(duration_s > 0)
            .then(numerator / duration_s)
            .otherwise(0.0)
            .cast(pl.Float64)
        )

    def safe_ratio(numerator: pl.Expr, denominator: pl.Expr) -> pl.Expr:
        return (
            pl.when(denominator > 0)
            .then(numerator / denominator)
            .otherwise(0.0)
            .cast(pl.Float64)
        )

    return renamed.with_columns(
        per_second(total_pkts).alias("pkt_rate"),
        per_second(total_bytes).alias("byte_rate"),
        safe_ratio(pl.col("in_bytes"), pl.col("in_pkts")).alias("bytes_per_pkt_in"),
        safe_ratio(pl.col("out_bytes"), pl.col("out_pkts")).alias("bytes_per_pkt_out"),
        safe_ratio(pl.col("out_bytes"), pl.col("in_bytes")).alias("bytes_ratio_out_in"),
    )


def check_tier_a_complete(columns: list[str]) -> None:
    """Fail if the mapped frame cannot feed Tier A."""
    missing = [f for f in TIER_A_FEATURES if f not in columns]
    if missing:
        raise SchemaMismatch(
            f"mapped frame is missing Tier A features {missing}; "
            "DIRECT and DERIVED do not cover the contract"
        )


__all__ = [
    "DIRECT",
    "DERIVED",
    "LABEL_ATTACK",
    "LABEL_BINARY",
    "SRC_HOST",
    "DST_HOST",
    "SchemaMismatch",
    "check_tier_a_complete",
    "find_timestamp",
    "resolve_columns",
    "to_contract",
]
