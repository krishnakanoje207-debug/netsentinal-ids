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
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from typing import Iterator

import polars as pl

from netsentinel_core.features.contract import FEATURE_ORDER
from netsentinel_core.features.extractor import extract_from_pcap

#: Directory name that marks the negative class.
BENIGN_DIR = "benign"

#: Extensions treated as captures.
CAPTURE_SUFFIXES = (".pcap", ".pcapng", ".cap")

RATIOS = (0.70, 0.15, 0.15)

LABEL_COLUMN = "Label"
ATTACK_COLUMN = "Attack"
SOURCE_COLUMN = "source_capture"


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, help="directory of <label>/<capture>.pcap")
    parser.add_argument("--out", default="data/pcap", help="output directory")
    args = parser.parse_args()
    prepare(args.root, args.out)


if __name__ == "__main__":
    main()
