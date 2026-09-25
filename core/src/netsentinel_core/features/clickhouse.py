"""ClickHouse DDL for the telemetry tables, generated from the feature contract.

``network_flows`` holds exactly what ``FlowFeatures.as_row()`` produces, and it is
generated here rather than maintained by hand for the same reason the Alembic migration
is: a column added to the contract and forgotten in the DDL means the sensor silently
drops a feature, and nothing would fail until a model was retrained on data that had a
hole in it.

Stdlib only, so ``core`` keeps its single dependency.
"""

from __future__ import annotations

from netsentinel_core.features.contract import (
    SCALAR_FIELDS,
    SPLT_IAT_FIELDS,
    SPLT_LEN_FIELDS,
)

#: Retention for raw telemetry (M2 s3.3). Long enough to investigate an incident,
#: short enough that a 128 GB disk survives a fortnight of lab traffic.
FLOW_TTL_DAYS = 30

#: Every scalar is Float64, matching the contract's own type. Packing counts into
#: smaller integers would save space at the cost of a conversion on every write and a
#: class of silent truncation bugs; ClickHouse compresses repeated values well enough
#: that the trade is not worth making.
SCALAR_TYPE = "Float64"


def network_flows_columns() -> list[tuple[str, str]]:
    """(name, type) for every network_flows column, in table order.

    Shared by the DDL and the flow sink, so the rows written and the table they are
    written to come from the same list.
    """
    columns: list[tuple[str, str]] = [
        ("ts", "DateTime64(3)"),
        ("flow_id", "String"),
        ("sensor", "LowCardinality(String)"),
        ("src_ip", "IPv4"),
        ("dst_ip", "IPv4"),
        ("src_port", "UInt16"),
        ("dst_port", "UInt16"),
    ]
    columns += [(name, SCALAR_TYPE) for name in SCALAR_FIELDS]
    # Signed lengths: negative means server to client, so Int16 is required.
    columns += [(name, "Int16") for name in SPLT_LEN_FIELDS]
    columns += [(name, "Float32") for name in SPLT_IAT_FIELDS]
    columns += [
        # Ground truth, only ever set for replayed or labelled captures.
        ("label", "LowCardinality(Nullable(String))"),
        # Null until the scorer has decided. Nullable on purpose: an undecided flow
        # must not be storable as 0, which would read as "confidently benign".
        ("risk_score", "Nullable(Float64)"),
        ("shadow", "UInt8 DEFAULT 1"),
    ]
    return columns


def network_flows_ddl(database: str = "netsentinel") -> str:
    """CREATE TABLE for the scored-flow table."""
    columns = [f"{name} {type_}" for name, type_ in network_flows_columns()]

    body = ",\n    ".join(columns)
    return (
        f"CREATE TABLE IF NOT EXISTS {database}.network_flows\n"
        f"(\n    {body}\n)\n"
        "ENGINE = MergeTree\n"
        "PARTITION BY toYYYYMMDD(ts)\n"
        # Ordered for the two queries that actually run: a time window, and
        # everything involving one host.
        "ORDER BY (ts, src_ip)\n"
        f"TTL toDateTime(ts) + INTERVAL {FLOW_TTL_DAYS} DAY\n"
        "SETTINGS index_granularity = 8192;"
    )


def tier_c_scores_columns() -> list[tuple[str, str]]:
    """(name, type) for every tier_c_scores column, in table order.

    Shared by the DDL and the Tier C sink, like ``network_flows_columns``.
    """
    return [
        ("ts", "DateTime64(3)"),
        ("flow_id", "String"),
        ("sensor", "LowCardinality(String)"),
        ("src_ip", "IPv4"),
        ("dst_ip", "IPv4"),
        ("model_name", "LowCardinality(String)"),
        ("model_version", "LowCardinality(String)"),
        # Calibrated, as the scorer publishes it; an alert is probability >= threshold.
        ("probability", "Float64"),
        ("threshold", "Float64"),
        # The window the score came from: how many flows, and how many hosts they
        # joined. A score from a window of three flows means less than one of a thousand.
        ("window_flows", "UInt32"),
        ("window_hosts", "UInt32"),
        # Set by ClickHouse, not the sink: how far behind the flow the score landed.
        ("ingested_at", "DateTime64(3) DEFAULT now64(3)"),
    ]


def tier_c_scores_ddl(database: str = "netsentinel") -> str:
    """CREATE TABLE for Tier C's per-flow window scores (TIER_C_TOPIC)."""
    columns = [f"{name} {type_}" for name, type_ in tier_c_scores_columns()]
    body = ",\n    ".join(columns)
    return (
        f"CREATE TABLE IF NOT EXISTS {database}.tier_c_scores\n"
        f"(\n    {body}\n)\n"
        "ENGINE = MergeTree\n"
        "PARTITION BY toYYYYMMDD(ts)\n"
        # The same order as network_flows, so a flow and its Tier C score are found
        # by the same time-window and host queries.
        "ORDER BY (ts, src_ip)\n"
        f"TTL toDateTime(ts) + INTERVAL {FLOW_TTL_DAYS} DAY;"
    )


def suricata_events_ddl(database: str = "netsentinel") -> str:
    return (
        f"CREATE TABLE IF NOT EXISTS {database}.suricata_events\n"
        "(\n"
        "    ts DateTime64(3),\n"
        "    event_type LowCardinality(String),\n"
        "    signature_id UInt32,\n"
        "    signature String,\n"
        "    severity UInt8,\n"
        "    src_ip IPv4,\n"
        "    dst_ip IPv4,\n"
        "    flow_id String,\n"
        "    raw String\n"
        ")\n"
        "ENGINE = MergeTree\n"
        "PARTITION BY toYYYYMMDD(ts)\n"
        "ORDER BY (ts, signature_id)\n"
        f"TTL toDateTime(ts) + INTERVAL {FLOW_TTL_DAYS} DAY;"
    )


def zeek_logs_ddl(database: str = "netsentinel") -> str:
    return (
        f"CREATE TABLE IF NOT EXISTS {database}.zeek_logs\n"
        "(\n"
        "    ts DateTime64(3),\n"
        "    log_type LowCardinality(String),\n"
        "    uid String,\n"
        "    id_orig_h IPv4,\n"
        "    id_resp_h IPv4,\n"
        "    fields Map(String, String)\n"
        ")\n"
        "ENGINE = MergeTree\n"
        "PARTITION BY toYYYYMMDD(ts)\n"
        "ORDER BY (log_type, ts)\n"
        f"TTL toDateTime(ts) + INTERVAL {FLOW_TTL_DAYS} DAY;"
    )


def full_schema(database: str = "netsentinel") -> str:
    """Everything, in the order ClickHouse must run it."""
    header = (
        "-- Generated by netsentinel_core.features.clickhouse.\n"
        "-- Do not edit by hand: core/tests/test_clickhouse_ddl.py fails if this file\n"
        "-- and the feature contract disagree. Regenerate with\n"
        "--   python -m netsentinel_core.features.clickhouse > "
        "infra/clickhouse/init/01_schema.sql\n"
    )
    return "\n".join(
        [
            header,
            f"CREATE DATABASE IF NOT EXISTS {database};",
            "",
            network_flows_ddl(database),
            "",
            tier_c_scores_ddl(database),
            "",
            suricata_events_ddl(database),
            "",
            zeek_logs_ddl(database),
            "",
        ]
    )


if __name__ == "__main__":
    print(full_schema())
