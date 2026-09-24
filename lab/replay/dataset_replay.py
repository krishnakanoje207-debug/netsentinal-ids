"""Replay labelled dataset flows through the real scoring path, into a JSONL file.

    uv run python lab/replay/dataset_replay.py \
        --dataset data/raw/NF-UNSW-NB15-v3.parquet \
        --models artefacts/tier_a/model_card.json --mode active \
        --out lab/replay/out/flows.jsonl

    uv run netsentinel-writer --card artefacts/tier_a/model_card.json \
        --sensor-id 1 --replay lab/replay/out/flows.jsonl

The offline half of the lab. The attack scenarios in ``lab/scenarios`` need the VM's
lab bridge and a sensor watching it; this needs neither. It takes flows from the
dataset's **test window** - the final 15% by time, which no model or threshold was
fitted to - scores each one with ``FusionScorer`` exactly as the sensor does, and
writes the message the sensor would have published. The writer then explains and
stores them as it would off the bus, so every alert on the dashboard is a real model's
verdict on a real labelled flow.

What is not real, stated so nobody mistakes it: NetFlow records carry no packets, so
the contract fields a NetFlow exporter cannot supply (SPLT, per-direction length
spread, inter-arrival statistics, flag counts) are zero. Tier A reads none of them.
The dataset label travels in ``flow.label``, which the contract keeps out of every
model input, so the dashboard can be checked against the ground truth.

``--mode active`` overrides the cards' ``shadow`` for this replay only, and has to be
typed, for the reason ``netsentinel-register-model --mode active`` does: a shadow
model raises no alerts, and a demo database has no shadow period to promote on.
``--shadow-models`` are exempt from it: they score beside the active tiers and are
recorded, but move no verdict.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
from pathlib import Path

import polars as pl

from netsentinel_core.features.contract import SCALAR_FIELDS, SPLT_N, FlowFeatures, FlowKey
from netsentinel_scoring.engine import FusionScorer
from netsentinel_scoring.registry import load_model
from netsentinel_sensor.agent import flow_payload, model_index
from netsentinel_training.data import nf_mapping as nf
from netsentinel_training.data.prep import temporal_split

MAPPED = list(nf.DIRECT) + list(nf.DERIVED)


def test_window(dataset: Path) -> pl.LazyFrame:
    """The flows no model was trained, tuned or thresholded on."""
    lazy = pl.scan_parquet(dataset) if dataset.suffix == ".parquet" else pl.scan_csv(dataset)
    header = lazy.collect_schema().names()
    nf.resolve_columns(header)
    time_col = nf.find_timestamp(header)
    if time_col is None:
        raise SystemExit(f"{dataset} has no timestamp; the test window cannot be found")
    mapped = nf.to_contract(lazy).with_columns(pl.col(time_col).alias("_ts"))
    return temporal_split(mapped, time_col)["test"]


def pick(window: pl.LazyFrame, benign: int, per_family: int, seed: int) -> pl.DataFrame:
    """A readable mix: every attack family, drowned in benign as a real feed is."""
    frame = window.select(
        MAPPED + [nf.SRC_HOST, nf.DST_HOST, nf.LABEL_BINARY, nf.LABEL_ATTACK, "_ts"]
    ).collect()
    parts = []
    for family, group in frame.group_by(nf.LABEL_ATTACK):
        want = benign if family[0] == "Benign" else per_family
        parts.append(group.sample(n=min(want, group.height), seed=seed))
    return pl.concat(parts).sort("_ts")


def features_of(row: dict) -> FlowFeatures:
    scalars = {name: 0.0 for name in SCALAR_FIELDS}
    scalars.update({name: float(row[name]) for name in MAPPED})
    return FlowFeatures(
        key=FlowKey(
            src_ip=row[nf.SRC_HOST], dst_ip=row[nf.DST_HOST],
            src_port=int(row["l4_src_port"]), dst_port=int(row["l4_dst_port"]),
            proto=int(row["proto"]),
        ),
        ts_start=row["_ts"] / 1000.0,
        ts_last=(row["_ts"] + row["duration_ms"]) / 1000.0,
        scalars=scalars,
        splt_len=[0] * SPLT_N,
        splt_iat=[0.0] * SPLT_N,
        label=row[nf.LABEL_ATTACK],
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--models", required=True, nargs="+", help="model cards to score with")
    parser.add_argument("--mode", choices=("card", "active"), default="card",
                        help="'active' overrides the cards' mode for this replay")
    parser.add_argument("--shadow-models", nargs="+", default=[],
                        help="model cards to score with in shadow mode, whatever --mode says")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--benign", type=int, default=400)
    parser.add_argument("--per-family", type=int, default=15)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    models = [load_model(card) for card in args.models]
    if args.mode == "active":
        models = [dataclasses.replace(model, mode="active") for model in models]
    models += [dataclasses.replace(load_model(card), mode="shadow") for card in args.shadow_models]
    scorer = FusionScorer(models)
    index = model_index(models)

    flows = pick(test_window(args.dataset), args.benign, args.per_family, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    alerts = caught = attacks = false_alarms = 0
    with open(args.out, "w", encoding="utf-8") as out:
        for row in flows.iter_rows(named=True):
            features = features_of(row)
            verdict = scorer.score(features)
            out.write(json.dumps(flow_payload(features, verdict, "nf-replay", index)) + "\n")
            is_attack = row[nf.LABEL_BINARY] == 1
            attacks += is_attack
            alerts += verdict.is_alert
            caught += verdict.is_alert and is_attack
            false_alarms += verdict.is_alert and not is_attack

    print(f"{flows.height} flows from the test window -> {args.out}")
    print(f"  {attacks} attacks, {alerts} alerts: {caught} caught, "
          f"{attacks - caught} missed, {false_alarms} false alarms")


if __name__ == "__main__":
    main()
