"""D4 dataset preparation: NF-* CSV in, leakage-safe train/val/test Parquet out.

Run on Kaggle (or anywhere the CSV fits on disk):

    python -m netsentinel_training.data.prep --csv NF-UNSW-NB15-v3.csv --out data/processed

Polars with a lazy scan rather than pandas, because NF-UQ-NIDS-v2 is far larger
than this laptop's 8 GB and larger than a Kaggle GPU session's ~13 GB; streaming
keeps peak memory near constant.

Two split strategies, because the NF-* variants differ:

  * temporal   - when the variant carries a timestamp. The honest default: train
                 on the past, test on the future, as the deployed model will run.
  * host holdout - when it does not (NF-UNSW-NB15-v2 has no timestamp). Whole
                 src/dst host pairs go to exactly one split, so the same testbed
                 conversation cannot appear in both train and test.

A plain random split is deliberately not offered. It is what inflates the
published accuracy figures this project set out to question (M2 s5.4).
"""

from __future__ import annotations

import argparse
from pathlib import Path

import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.data import nf_mapping as nf

#: train / val / test proportions.
RATIOS = (0.70, 0.15, 0.15)

#: Columns carried through alongside the features: the targets, plus the hosts
#: needed for the split. Hosts are dropped from model input, never trained on.
CARRIED = (nf.LABEL_BINARY, nf.LABEL_ATTACK)


def _split_bounds(ratios: tuple[float, float, float]) -> tuple[float, float]:
    train_end = ratios[0]
    val_end = ratios[0] + ratios[1]
    return train_end, val_end


def temporal_split(
    frame: pl.LazyFrame, time_col: str, ratios: tuple[float, float, float] = RATIOS
) -> dict[str, pl.LazyFrame]:
    """Cut chronologically at the ratio quantiles of the timestamp."""
    train_end, val_end = _split_bounds(ratios)
    bounds = (
        frame.select(
            pl.col(time_col).quantile(train_end).alias("t1"),
            pl.col(time_col).quantile(val_end).alias("t2"),
        )
        .collect()
        .row(0)
    )
    t1, t2 = bounds
    return {
        "train": frame.filter(pl.col(time_col) <= t1),
        "val": frame.filter((pl.col(time_col) > t1) & (pl.col(time_col) <= t2)),
        "test": frame.filter(pl.col(time_col) > t2),
    }


def host_holdout_split(
    frame: pl.LazyFrame,
    src_col: str = nf.SRC_HOST,
    dst_col: str = nf.DST_HOST,
    ratios: tuple[float, float, float] = RATIOS,
    seed: int = 1337,
) -> dict[str, pl.LazyFrame]:
    """Assign whole host pairs to one split via a stable hash.

    Hashing the unordered pair keeps both directions of a conversation together,
    so a flow and its reply can never straddle the train/test boundary.
    """
    train_end, val_end = _split_bounds(ratios)
    lo = pl.min_horizontal(src_col, dst_col)
    hi = pl.max_horizontal(src_col, dst_col)
    bucket = (
        pl.concat_str([lo, hi], separator="|").hash(seed=seed) % 1000
    ).alias("_bucket")

    tagged = frame.with_columns(bucket)
    return {
        "train": tagged.filter(pl.col("_bucket") < int(train_end * 1000)).drop("_bucket"),
        "val": tagged.filter(
            (pl.col("_bucket") >= int(train_end * 1000))
            & (pl.col("_bucket") < int(val_end * 1000))
        ).drop("_bucket"),
        "test": tagged.filter(pl.col("_bucket") >= int(val_end * 1000)).drop("_bucket"),
    }


def prepare(csv_path: str | Path, out_dir: str | Path) -> dict[str, int]:
    """Map, split and write Parquet. Returns row counts per split."""
    csv_path, out_dir = Path(csv_path), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    header = pl.read_csv(csv_path, n_rows=0).columns
    nf.resolve_columns(header)
    time_col = nf.find_timestamp(header)

    mapped = nf.to_contract(pl.scan_csv(csv_path))
    nf.check_tier_a_complete(mapped.collect_schema().names())

    if time_col:
        print(f"split: temporal on {time_col!r}")
        splits = temporal_split(mapped, time_col)
    else:
        print(
            f"split: host holdout on {nf.SRC_HOST}/{nf.DST_HOST} "
            "(this dataset variant carries no timestamp)"
        )
        splits = host_holdout_split(mapped)

    keep = list(TIER_A_FEATURES) + [c for c in CARRIED if c in header]
    counts: dict[str, int] = {}
    for name, frame in splits.items():
        target = out_dir / f"{name}.parquet"
        frame.select(keep).sink_parquet(target)
        counts[name] = pl.scan_parquet(target).select(pl.len()).collect().item()
        print(f"  {name:>5}: {counts[name]:>9,} rows -> {target}")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csv", required=True, help="path to an NF-* dataset CSV")
    parser.add_argument("--out", default="data/processed", help="output directory")
    args = parser.parse_args()
    prepare(args.csv, args.out)


if __name__ == "__main__":
    main()
