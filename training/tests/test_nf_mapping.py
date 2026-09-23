"""Dataset prep tests, run against a synthetic NF-shaped CSV.

The real NF-UNSW-NB15-v3 file is not in the repo, so these build a CSV with the
declared NF header instead. That is enough to pin the two things that can go
quietly wrong: the derived formulas drifting away from the live extractor, and a
split that leaks hosts across the train/test boundary.
"""

from __future__ import annotations

import csv

import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.data import nf_mapping as nf
from netsentinel_training.data.prep import host_holdout_split, prepare, temporal_split

NF_HEADER = [
    nf.SRC_HOST, "L4_SRC_PORT", nf.DST_HOST, "L4_DST_PORT", "PROTOCOL",
    "IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS",
    "FLOW_DURATION_MILLISECONDS", "MIN_TTL", "MAX_TTL", "TCP_FLAGS",
    nf.LABEL_BINARY, nf.LABEL_ATTACK,
]


def _row(src: str, dst: str, in_bytes: int, in_pkts: int, out_bytes: int,
         out_pkts: int, duration_ms: int, label: int, attack: str) -> list:
    return [src, 44321, dst, 80, 6, in_bytes, in_pkts, out_bytes, out_pkts,
            duration_ms, 64, 128, 27, label, attack]


def _write_csv(path, rows: list[list], header: list[str] = NF_HEADER) -> str:
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)
    return str(path)


@pytest.fixture
def nf_csv(tmp_path) -> str:
    """40 host pairs, so a 70/15/15 bucket split has something to work with."""
    rows = [
        _row(f"10.0.0.{i}", f"10.0.1.{i}", 1000, 10, 2000, 20, 500,
             i % 2, "Exploits" if i % 2 else "Benign")
        for i in range(40)
    ]
    return _write_csv(tmp_path / "nf.csv", rows)


# --- schema guards ---------------------------------------------------------

def test_resolve_columns_accepts_the_declared_header():
    assert nf.resolve_columns(NF_HEADER) == nf.DIRECT


def test_renamed_column_fails_loudly():
    header = [c for c in NF_HEADER if c != "IN_BYTES"] + ["IN_BYTES_TOTAL"]
    with pytest.raises(nf.SchemaMismatch, match="IN_BYTES"):
        nf.resolve_columns(header)


def test_missing_label_fails_loudly():
    header = [c for c in NF_HEADER if c != nf.LABEL_BINARY]
    with pytest.raises(nf.SchemaMismatch, match="label column"):
        nf.resolve_columns(header)


def test_timestamp_detected_only_when_present():
    assert nf.find_timestamp(NF_HEADER) is None
    assert nf.find_timestamp(NF_HEADER + ["FLOW_START_MILLISECONDS"]) == "FLOW_START_MILLISECONDS"


# --- derived features must match the live extractor ------------------------

def test_derived_formulas_match_the_extractor(nf_csv):
    mapped = nf.to_contract(pl.scan_csv(nf_csv)).collect()
    first = mapped.row(0, named=True)
    # 30 packets over 0.5 s; 3000 bytes over 0.5 s.
    assert first["pkt_rate"] == pytest.approx(60.0)
    assert first["byte_rate"] == pytest.approx(6000.0)
    assert first["bytes_per_pkt_in"] == pytest.approx(100.0)
    assert first["bytes_per_pkt_out"] == pytest.approx(100.0)
    assert first["bytes_ratio_out_in"] == pytest.approx(2.0)


def test_zero_duration_yields_zero_not_null(tmp_path):
    path = _write_csv(
        tmp_path / "zero.csv",
        [_row("10.0.0.1", "10.0.0.2", 100, 1, 0, 0, 0, 0, "Benign")],
    )
    row = nf.to_contract(pl.scan_csv(path)).collect().row(0, named=True)
    # A tree must never see a null where the extractor would emit a number.
    assert row["pkt_rate"] == 0.0
    assert row["byte_rate"] == 0.0
    assert row["bytes_per_pkt_out"] == 0.0
    assert row["bytes_ratio_out_in"] == 0.0


def test_mapped_frame_covers_every_tier_a_feature(nf_csv):
    columns = nf.to_contract(pl.scan_csv(nf_csv)).collect_schema().names()
    nf.check_tier_a_complete(columns)  # raises if not


# --- splits ---------------------------------------------------------------

def test_host_holdout_keeps_pairs_whole(nf_csv):
    mapped = nf.to_contract(pl.scan_csv(nf_csv))
    splits = host_holdout_split(mapped)
    seen: dict[str, str] = {}
    for name, frame in splits.items():
        for row in frame.collect().iter_rows(named=True):
            pair = f"{row[nf.SRC_HOST]}|{row[nf.DST_HOST]}"
            assert seen.setdefault(pair, name) == name, (
                f"host pair {pair} leaked across {seen[pair]} and {name}"
            )


def test_splits_partition_every_row(nf_csv):
    mapped = nf.to_contract(pl.scan_csv(nf_csv))
    total = mapped.select(pl.len()).collect().item()
    counts = {n: f.collect().height for n, f in host_holdout_split(mapped).items()}
    assert sum(counts.values()) == total


def test_host_holdout_is_deterministic(nf_csv):
    mapped = nf.to_contract(pl.scan_csv(nf_csv))
    first = {n: f.collect().height for n, f in host_holdout_split(mapped).items()}
    second = {n: f.collect().height for n, f in host_holdout_split(mapped).items()}
    assert first == second


def test_temporal_split_is_chronological(tmp_path):
    rows = [
        _row("10.0.0.1", "10.0.0.2", 1000, 10, 2000, 20, 500, i % 2, "Benign")
        + [1000 + i]
        for i in range(100)
    ]
    path = _write_csv(tmp_path / "ts.csv", rows, NF_HEADER + ["FLOW_START_MILLISECONDS"])
    mapped = nf.to_contract(pl.scan_csv(path))
    splits = temporal_split(mapped, "FLOW_START_MILLISECONDS")

    train_max = splits["train"].select(pl.col("FLOW_START_MILLISECONDS").max()).collect().item()
    test_min = splits["test"].select(pl.col("FLOW_START_MILLISECONDS").min()).collect().item()
    assert train_max < test_min, "training data must not come after test data"


# --- end to end -----------------------------------------------------------

def test_prepare_writes_parquet_with_contract_columns(nf_csv, tmp_path):
    out = tmp_path / "processed"
    counts = prepare(nf_csv, out)

    assert set(counts) == {"train", "val", "test"}
    assert sum(counts.values()) == 40

    for name in counts:
        columns = pl.scan_parquet(out / f"{name}.parquet").collect_schema().names()
        for feature in TIER_A_FEATURES:
            assert feature in columns
        assert nf.LABEL_BINARY in columns
        # Host addresses are identifiers, not behaviour: they must not survive
        # into the training file.
        assert nf.SRC_HOST not in columns
        assert nf.DST_HOST not in columns


# --- source formats --------------------------------------------------------

def test_parquet_source_prepares_like_csv(nf_csv, tmp_path):
    # The public mirrors of the NF-v3 family ship Parquet, not the UQ CSVs.
    parquet = tmp_path / "nf.parquet"
    pl.read_csv(nf_csv).write_parquet(parquet)

    from_csv = prepare(nf_csv, tmp_path / "csv")
    from_parquet = prepare(parquet, tmp_path / "parquet")

    assert from_parquet == from_csv


def test_prepared_splits_keep_fields_outside_tier_a(nf_csv, tmp_path):
    # TTL is out of Tier A but still written, so its exclusion can be measured.
    prepare(nf_csv, tmp_path / "out")
    columns = pl.read_parquet(tmp_path / "out" / "train.parquet").columns

    assert {"min_ttl", "max_ttl"} <= set(columns)
    assert set(TIER_A_FEATURES) <= set(columns)
