"""PCAP directories to training Parquet, via the live extractor.

    python -m netsentinel_training.data.pcap_prep --root captures --out data/pcap

Tiers B and C need the packet sequence, which the NF-* datasets cannot supply: they are
pre-aggregated NetFlow with no per-packet detail. So their training data comes from
captures, run through the same ``extract_from_pcap`` the sensor uses - which is the whole
point, and the reason the parity test exists.

Labels come from the directory name:

    captures/
      benign/            -> label 0, attack_type "Benign"
      portscan/          -> label 1, attack_type "portscan"
      bruteforce/        -> label 1, attack_type "bruteforce"

A directory named ``benign`` (case-insensitive) is the negative class and everything else
is an attack named after its folder. That keeps labelling a filesystem operation rather
than a spreadsheet nobody updates.

Splitting is by capture file, never by flow. Flows from one capture share a session, a
host pair and a clock; splitting them across train and test would leak, and the resulting
accuracy would be the inflated kind this project set out to question.

Public datasets ship one capture per day with benign and attack traffic interleaved, so
the directory rule cannot label them. For those, ``--labels`` takes the dataset's own
labelled-flow files (CIC-IDS2017 ``GeneratedLabelledFlows``) instead:

    python -m netsentinel_training.data.pcap_prep --captures window1.pcapng window2.pcapng \
        --labels labels/*.parquet --out data/pcap

Each extracted flow takes the label of the nearest labelled flow with the same 5-tuple,
either direction, within ``LABEL_TOLERANCE_S``; a flow with no such match is dropped
rather than guessed benign. Such a capture mixes both classes, so it cannot go to one
split whole; it is split by time instead: the first 70% of each capture's span trains,
the next 15% validates and the last 15% tests. The model is always tested on traffic
later than anything it learned from, and each capture has two cut points rather than
thousands of shuffled neighbours on either side.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterator

import polars as pl

from netsentinel_core.features.contract import FEATURE_ORDER
from netsentinel_core.features.extractor import IDLE_TIMEOUT_S, extract_from_pcap

#: Directory name that marks the negative class.
BENIGN_DIR = "benign"

#: Extensions treated as captures.
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")

RATIOS = (0.70, 0.15, 0.15)

LABEL_COLUMN = "Label"
ATTACK_COLUMN = "Attack"
SOURCE_COLUMN = "source_capture"

#: Flows buffered before a Parquet part is written, so a multi-GB capture never sits in
#: memory as rows.
CHUNK_ROWS = 50_000

#: How far apart an extracted flow and its labelled counterpart may start. The labelled
#: timestamps are floored to the minute, and the two flow meters cut flows differently.
LABEL_TOLERANCE_S = 120.0

#: The labelled-flow files name benign traffic this way; anything else is an attack.
BENIGN_LABEL = "BENIGN"


class NoCapturesFound(RuntimeError):
    """The root directory held nothing to read."""


def find_captures(root: str | Path) -> list[Path]:
    """Every capture under root, sorted so a run is reproducible."""
    root = Path(root)
    captures = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in CAPTURE_SUFFIXES
    )
    if not captures:
        raise NoCapturesFound(
            f"no {'/'.join(CAPTURE_SUFFIXES)} files under {root}. Expected "
            f"{root}/<label>/<capture>.pcap, with one directory named {BENIGN_DIR!r}."
        )
    return captures


def label_for(capture: Path, root: Path) -> tuple[int, str]:
    """(binary label, attack name) from the capture's directory."""
    try:
        relative = capture.relative_to(root)
    except ValueError:  # pragma: no cover - callers pass paths found under root
        relative = capture

    # The first directory below the root is the label; a capture directly in the root
    # has no label and is rejected rather than guessed at.
    parts = relative.parts
    if len(parts) < 2:
        raise ValueError(
            f"{capture} is not inside a label directory. Move it under "
            f"{root}/<label>/ - use {BENIGN_DIR!r} for normal traffic."
        )

    name = parts[0]
    if name.lower() == BENIGN_DIR:
        return 0, "Benign"
    return 1, name


def rows_from(capture: Path, root: Path) -> Iterator[dict]:
    """Extract one capture into labelled rows."""
    label, attack = label_for(capture, root)
    for features in extract_from_pcap(str(capture)):
        row = features.as_row()
        row[LABEL_COLUMN] = label
        row[ATTACK_COLUMN] = attack
        row[SOURCE_COLUMN] = str(capture.relative_to(root)).replace("\\", "/")
        yield row


def _bucket(capture_name: str, seed: str = "netsentinel") -> float:
    """Stable 0..1 position for a capture, so splits do not move between runs."""
    digest = hashlib.sha256(f"{seed}:{capture_name}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / float(1 << 64)


def assign_splits(captures: list[str], ratios: tuple[float, float, float] = RATIOS) -> dict[str, str]:
    """Map each capture to train/val/test.

    Hashed rather than shuffled so that adding a capture does not reshuffle the others,
    which would silently invalidate every model trained before it.
    """
    train_end = ratios[0]
    val_end = ratios[0] + ratios[1]
    assignment: dict[str, str] = {}
    for capture in captures:
        position = _bucket(capture)
        if position < train_end:
            assignment[capture] = "train"
        elif position < val_end:
            assignment[capture] = "val"
        else:
            assignment[capture] = "test"
    return assignment


def prepare(root: str | Path, out_dir: str | Path) -> dict[str, int]:
    """Extract every capture, split by file, write Parquet. Returns row counts."""
    root, out_dir = Path(root), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    captures = find_captures(root)
    rows: list[dict] = []
    for capture in captures:
        before = len(rows)
        rows.extend(rows_from(capture, root))
        print(f"  {capture.relative_to(root)}: {len(rows) - before:,} flows")

    if not rows:
        raise NoCapturesFound(
            f"{len(captures)} capture(s) read but no flows extracted; the files may hold "
            "no IPv4 TCP/UDP/ICMP traffic"
        )

    frame = pl.DataFrame(rows)
    splits = assign_splits(sorted({row[SOURCE_COLUMN] for row in rows}))
    frame = frame.with_columns(
        pl.col(SOURCE_COLUMN).replace_strict(splits, default="train").alias("_split")
    )

    counts: dict[str, int] = {}
    for name in ("train", "val", "test"):
        part = frame.filter(pl.col("_split") == name).drop("_split")
        target = out_dir / f"{name}.parquet"
        part.write_parquet(target)
        counts[name] = part.height
        attacks = part.filter(pl.col(LABEL_COLUMN) == 1).height
        print(f"  {name:>5}: {part.height:>8,} flows ({attacks:,} attack) -> {target}")

    missing = [f for f in FEATURE_ORDER if f not in frame.columns]
    if missing:  # pragma: no cover - as_row is generated from the same contract
        raise RuntimeError(f"extracted rows are missing contract features {missing}")
    return counts


def extract_in_chunks(capture: Path, parts_dir: Path, chunk_rows: int = CHUNK_ROWS) -> int:
    """Stream one capture's flows to Parquet parts. Returns the flow count."""
    parts_dir.mkdir(parents=True, exist_ok=True)
    buffer: list[dict] = []
    written = 0

    def write() -> None:
        # Features cast to one type, so parts inferred from different rows still concatenate.
        frame = pl.DataFrame(buffer, infer_schema_length=None).drop("label").with_columns(
            pl.col(FEATURE_ORDER).cast(pl.Float64)
        )
        frame.write_parquet(parts_dir / f"part-{written // chunk_rows:05d}.parquet")

    for features in extract_from_pcap(str(capture)):
        buffer.append(features.as_row())
        if len(buffer) == chunk_rows:
            write()
            written += len(buffer)
            buffer.clear()
            print(f"  {written:,} flows")
    if buffer:
        write()
        written += len(buffer)
    return written


def _conversation(src_ip: str, src_port: str, dst_ip: str, dst_port: str, proto: str) -> pl.Expr:
    """One key for both directions: two flow meters need not agree on who initiated."""
    a = pl.concat_str([pl.col(src_ip), pl.col(src_port).cast(pl.Int64)], separator=":")
    b = pl.concat_str([pl.col(dst_ip), pl.col(dst_port).cast(pl.Int64)], separator=":")
    return pl.concat_str(
        [pl.min_horizontal(a, b), pl.max_horizontal(a, b), pl.col(proto).cast(pl.Int64)],
        separator="|",
    )


def label_flows(flows: pl.DataFrame, labels: pl.DataFrame,
                tolerance_s: float = LABEL_TOLERANCE_S) -> pl.DataFrame:
    """Give each flow the label of the nearest labelled flow on the same 5-tuple.

    ``labels`` holds CIC-IDS2017 labelled-flow columns with ``Timestamp`` as a UTC
    datetime. Flows with no match within the tolerance are dropped. An attack label
    within the tolerance beats a nearer benign one: CICFlowMeter also writes the
    server's side of an attacked conversation as a reversed flow labelled BENIGN
    (Engelen et al., 2021), which would otherwise unlabel the attack.
    """
    labels = (
        labels.rename({c: c.strip() for c in labels.columns})
        .select(
            _conversation("Source IP", "Source Port", "Destination IP", "Destination Port",
                          "Protocol").alias("_key"),
            # Floored to the minute, so the middle of that minute is the best estimate.
            (pl.col("Timestamp").dt.epoch("ms") / 1000 + 30.0).alias("_t"),
            pl.col("Label").str.strip_chars().alias("_label"),
        )
        .sort("_t")
    )
    attacks = labels.filter(pl.col("_label").str.to_uppercase() != BENIGN_LABEL).rename(
        {"_t": "_t_attack", "_label": "_attack"}
    )
    matched = (
        flows.with_columns(
            _conversation("src_ip", "src_port", "dst_ip", "dst_port", "proto").alias("_key"),
            pl.col("ts").cast(pl.Float64),
        )
        .sort("ts")
        .join_asof(labels, left_on="ts", right_on="_t", by="_key", strategy="nearest",
                   tolerance=tolerance_s, check_sortedness=False)  # both sorted above
        .join_asof(attacks, left_on="ts", right_on="_t_attack", by="_key", strategy="nearest",
                   tolerance=tolerance_s, check_sortedness=False)
        .filter(pl.col("_label").is_not_null())
        .with_columns(pl.coalesce("_attack", "_label").alias("_label"))
        .drop("_t_attack", "_attack")
    )
    benign = pl.col("_label").str.to_uppercase() == BENIGN_LABEL
    return matched.with_columns(
        (~benign).cast(pl.Int8).alias(LABEL_COLUMN),
        pl.when(benign).then(pl.lit("Benign")).otherwise(pl.col("_label")).alias(ATTACK_COLUMN),
    ).drop("_key", "_t", "_label")


def chronological_split(ts: pl.Expr, by: str) -> pl.Expr:
    """train/val/test by where a flow starts within its own capture's span."""
    start = ts.min().over(by)
    position = (ts - start) / (ts.max().over(by) - start)
    return (
        pl.when(position < RATIOS[0]).then(pl.lit("train"))
        .when(position < RATIOS[0] + RATIOS[1]).then(pl.lit("val"))
        .otherwise(pl.lit("test"))
    )


def prepare_labelled(captures: list[str | Path], label_files: list[str | Path],
                     out_dir: str | Path) -> dict[str, int]:
    """Captures plus their labelled-flow files to split Parquet. Returns row counts."""
    out_dir = Path(out_dir)
    frames = []
    for capture in map(Path, captures):
        parts = out_dir / "flows" / capture.stem
        # Extraction is the slow step, so its output is kept and reused; it is written
        # under another name first, so an interrupted run never passes for a finished one.
        if not parts.is_dir():
            partial = parts.with_name(parts.name + ".partial")
            print(f"extracting {capture}")
            extract_in_chunks(capture, partial)
            partial.rename(parts)
        frames.append(
            pl.read_parquet(parts / "*.parquet").with_columns(pl.lit(capture.name).alias(SOURCE_COLUMN))
        )

    flows = pl.concat(frames)
    labels = pl.concat(
        [pl.read_parquet(path) for path in label_files], how="vertical_relaxed"
    )
    # A capture cut from a longer one opens mid-conversation: a flow seen in its first
    # idle timeout may be the tail of an older one, whose "first twenty packets" are not.
    # After that, every flow is cut exactly as the full capture would have cut it.
    extracted = flows.height
    flows = flows.filter(
        pl.col("ts") >= pl.col("ts").min().over(SOURCE_COLUMN) + IDLE_TIMEOUT_S
    )
    frame = label_flows(flows, labels)
    print(f"{extracted:,} flows extracted; {extracted - flows.height:,} skipped as possible "
          f"tails; {frame.height:,} matched a labelled flow; {flows.height - frame.height:,} "
          "unmatched and dropped")

    frame = frame.with_columns(chronological_split(pl.col("ts"), SOURCE_COLUMN).alias("_split"))
    counts: dict[str, int] = {}
    for name in ("train", "val", "test"):
        part = frame.filter(pl.col("_split") == name).drop("_split")
        part.write_parquet(out_dir / f"{name}.parquet")
        counts[name] = part.height
        per_class = dict(part.group_by(ATTACK_COLUMN).len().sort(ATTACK_COLUMN).iter_rows())
        print(f"  {name:>5}: {part.height:>8,} flows {per_class}")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", help="directory of <label>/<capture>.pcap")
    parser.add_argument("--captures", nargs="+", help="captures labelled by --labels")
    parser.add_argument("--labels", nargs="+", help="labelled-flow Parquet files for --captures")
    parser.add_argument("--out", default="data/pcap", help="output directory")
    args = parser.parse_args()
    if args.captures:
        if not args.labels:
            parser.error("--captures needs --labels")
        prepare_labelled(args.captures, args.labels, args.out)
    elif args.root:
        prepare(args.root, args.out)
    else:
        parser.error("give --root, or --captures with --labels")


if __name__ == "__main__":
    main()
