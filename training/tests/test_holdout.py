"""The held-out split is the whole point of the held-out test, so it is pinned exactly:
the attacker never appears in training or validation, and the test holds only normal
traffic plus that attacker."""

from __future__ import annotations

import polars as pl

from netsentinel_training.eval.holdout import attackers, held_out_splits


def _frame(rows):
    return pl.DataFrame(rows, schema=["src_ip", "Label"], orient="row")


def _write(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    rows = [("10.0.0.1", 0), ("10.0.0.2", 0), ("6.6.6.1", 1), ("6.6.6.2", 1), ("6.6.6.1", 1)]
    for name in ("train", "val", "test"):
        _frame(rows).write_parquet(data / f"{name}.parquet")
    return data


def test_attackers_are_the_sources_of_attack_flows(tmp_path):
    assert attackers(_write(tmp_path)) == ["6.6.6.1", "6.6.6.2"]


def test_the_held_out_attacker_is_absent_from_training_and_validation(tmp_path):
    data = _write(tmp_path)
    held_out_splits(data, "6.6.6.1", tmp_path / "split")
    for name in ("train", "val"):
        frame = pl.read_parquet(tmp_path / "split" / f"{name}.parquet")
        assert "6.6.6.1" not in frame.filter(pl.col("Label") == 1).get_column("src_ip").to_list()
        # Both of its flows go; the other attacker and all normal traffic stay.
        assert frame.height == 3


def test_the_test_split_is_normal_traffic_plus_that_attacker_only(tmp_path):
    data = _write(tmp_path)
    held_out_splits(data, "6.6.6.1", tmp_path / "split")
    test = pl.read_parquet(tmp_path / "split" / "test.parquet")
    attacks = test.filter(pl.col("Label") == 1).get_column("src_ip").unique().to_list()
    assert attacks == ["6.6.6.1"]
    assert test.filter(pl.col("Label") == 0).height == 2
