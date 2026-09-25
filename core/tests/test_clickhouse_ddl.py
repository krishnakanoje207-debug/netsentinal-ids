"""The telemetry schema must not drift from the feature contract.

The failure this guards against is quiet: a feature is added to the contract, the
ClickHouse table is not regenerated, and the sensor writes flows with that column
missing. Nothing errors. It surfaces weeks later as a model trained on data with a hole
in it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from netsentinel_core.features.clickhouse import (
    FLOW_TTL_DAYS,
    full_schema,
    network_flows_ddl,
    tier_c_scores_ddl,
)
from netsentinel_core.features.contract import (
    FEATURE_ORDER,
    SCALAR_FIELDS,
    SPLT_IAT_FIELDS,
    SPLT_LEN_FIELDS,
    FlowFeatures,
    FlowKey,
    SPLT_N,
)

#: The committed file the VM actually runs.
SCHEMA_FILE = Path(__file__).resolve().parents[2] / "infra" / "clickhouse" / "init" / "01_schema.sql"


def test_every_contract_feature_has_a_column():
    ddl = network_flows_ddl()
    for feature in FEATURE_ORDER:
        assert f"    {feature} " in ddl, f"{feature} has no column in network_flows"


def test_splt_lengths_are_signed():
    """Direction is encoded in the sign, so an unsigned column would lose it."""
    ddl = network_flows_ddl()
    for name in SPLT_LEN_FIELDS:
        assert f"    {name} Int16" in ddl


def test_splt_inter_arrivals_are_floats():
    ddl = network_flows_ddl()
    for name in SPLT_IAT_FIELDS:
        assert f"    {name} Float32" in ddl


def test_scalars_keep_the_contract_type():
    ddl = network_flows_ddl()
    for name in SCALAR_FIELDS:
        assert f"    {name} Float64" in ddl


def test_risk_score_is_nullable():
    """Undecided must not be storable as zero, which would read as benign."""
    assert "risk_score Nullable(Float64)" in network_flows_ddl()


def test_flows_are_ordered_for_the_queries_that_run():
    ddl = network_flows_ddl()
    assert "ORDER BY (ts, src_ip)" in ddl
    assert "PARTITION BY toYYYYMMDD(ts)" in ddl


def test_retention_is_set():
    assert f"INTERVAL {FLOW_TTL_DAYS} DAY" in network_flows_ddl()


def test_as_row_matches_the_table_columns():
    """The writer and the table must agree on every name."""
    features = FlowFeatures(
        key=FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6),
        ts_start=0.0,
        ts_last=1.0,
        scalars={name: 0.0 for name in SCALAR_FIELDS},
        splt_len=[0] * SPLT_N,
        splt_iat=[0.0] * SPLT_N,
    )
    ddl = network_flows_ddl()
    for column in features.as_row():
        # as_row emits src_port/dst_port/flow_id/ts/label alongside the features.
        assert f"    {column} " in ddl, f"as_row writes {column}, which the table lacks"


def test_tier_c_scores_are_kept_as_long_as_the_flows():
    ddl = tier_c_scores_ddl()
    assert f"INTERVAL {FLOW_TTL_DAYS} DAY" in ddl
    assert "ORDER BY (ts, src_ip)" in ddl
    assert "PARTITION BY toYYYYMMDD(ts)" in ddl


def test_tier_c_scores_record_the_model_and_its_window():
    ddl = tier_c_scores_ddl()
    for column in ("model_name", "model_version", "probability Float64",
                   "threshold Float64", "window_flows", "window_hosts",
                   "ingested_at DateTime64(3) DEFAULT now64(3)"):
        assert f"    {column}" in ddl


def test_all_tables_are_created():
    schema = full_schema()
    for table in ("network_flows", "tier_c_scores", "suricata_events", "zeek_logs"):
        assert f"netsentinel.{table}" in schema
    assert "CREATE DATABASE IF NOT EXISTS netsentinel" in schema


def test_statements_are_terminated():
    """A missing semicolon makes the clickhouse init script fail silently mid-file."""
    statements = [s.strip() for s in full_schema().split(";") if s.strip()]
    assert len(statements) >= 4


@pytest.mark.skipif(not SCHEMA_FILE.exists(), reason="infra schema file not present")
def test_the_committed_file_is_current():
    """Regenerate with:

    python -m netsentinel_core.features.clickhouse > infra/clickhouse/init/01_schema.sql
    """
    committed = SCHEMA_FILE.read_text(encoding="utf-8").replace("\r\n", "\n")
    assert committed.strip() == full_schema().strip(), (
        "infra/clickhouse/init/01_schema.sql is stale; regenerate it (see this "
        "test's docstring)"
    )
