"""Re-baseline a Tier D model on the deployment's own benign traffic.

    python -m netsentinel_training.models.recalibrate artefacts/tier_d_ae/model_card.json \
        --flows lab_benign.parquet --version 1.2.0-lab --out artefacts/tier_d_ae_lab \
        --note "lab curl client, 04:47-05:20 UTC on 2026-09-27, attacker excluded"

Both Tier D models say how unfamiliar a flow is *relative to the benign traffic they
were calibrated on*, which was the benchmark's. A deployment whose normal traffic looks
nothing like CIC-IDS2017 or UNSW-NB15 then reads as anomalous flow after flow: the live
lab's plain HTTP scored 0.99 on both. The fix an anomaly detector expects is to measure
"normal" where it runs.

Only the calibration moves. The ONNX file is copied byte for byte, so ``onnx_sha256``
still holds and the registry loads it; the benign quantiles and the threshold are
refitted exactly as training fits them (``tier_d.fit_quantiles``,
``tier_d.decision_threshold``), on the flows given. The card gets a new version, so it
registers as a new model, born in shadow, that an operator can compare and promote.

**The risk is the input.** Whatever is in the flows file becomes normal, an attack
included, and the model will stop objecting to anything like it. Nothing here can tell
benign from malicious - that is why the file is needed - so the window is the
operator's to choose and is recorded in the card: the note, the row count, the time
span and the SHA-256 of the file, so the baseline can be audited and redone.
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_a import sha256
from netsentinel_training.models.tier_d import (
    anomaly_probability,
    decision_threshold,
    fit_quantiles,
)

#: Fewest flows to baseline on. At a 1% budget the threshold is the 99th percentile,
#: and below a thousand flows that is set by a handful of them.
MIN_FLOWS = 1000

#: Card entries measured under the old calibration. Kept, but moved under
#: ``recalibrated_from`` so nothing reads them as describing the new threshold.
MEASURED_FIELDS = ("pr_auc", "metrics_test", "family_recall_test")


def read_flows(path: Path) -> pl.DataFrame:
    """A Parquet or CSV export of flows carrying the contract's Tier D features."""
    frame = pl.read_csv(path) if path.suffix.lower() == ".csv" else pl.read_parquet(path)
    missing = [f for f in TIER_A_FEATURES if f not in frame.columns]
    if missing:
        raise ValueError(f"{path.name} is missing features {missing}")
    if frame.height < MIN_FLOWS:
        raise ValueError(
            f"{path.name} holds {frame.height} flows; at least {MIN_FLOWS} are needed "
            "for the threshold not to rest on a handful of them"
        )
    return frame


def raw_scores(onnx_path: Path, x: np.ndarray) -> np.ndarray:
    """The graph's own output, before any calibration, as the registry reads it."""
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    outputs = session.run(None, {session.get_inputs()[0].name: x.astype(np.float32)})
    return np.asarray(outputs[-1]).ravel().astype(np.float64)


def recalibrate(card_path: str | Path, flows_path: str | Path, out_dir: str | Path,
                version: str, note: str) -> dict:
    card_path, flows_path, out_dir = Path(card_path), Path(flows_path), Path(out_dir)
    card = json.loads(card_path.read_text(encoding="utf-8"))
    if card.get("tier") != "D" or card.get("calibration", {}).get("method") != "empirical_quantiles":
        raise ValueError(f"{card_path} is not a quantile-calibrated Tier D card")
    if version == card["version"]:
        raise ValueError(f"version {version} is the card's own; a new baseline needs a new one")
    if out_dir.resolve() == card_path.parent.resolve():
        raise ValueError("--out is the source card's directory, which would overwrite it")

    onnx_path = card_path.parent / "tier_d.onnx"
    if sha256(onnx_path) != card["onnx_sha256"]:
        raise ValueError(f"{onnx_path} does not match its card; refusing to baseline it")

    frame = read_flows(flows_path)
    x = frame.select(TIER_A_FEATURES).to_numpy().astype(np.float32)
    scores = raw_scores(onnx_path, x)
    levels, quantiles = fit_quantiles(scores)
    threshold = decision_threshold(anomaly_probability(scores, levels, quantiles))
    # What the old calibration made of these same flows: the problem being fixed.
    old = card["calibration"]
    flagged_before = float(
        (anomaly_probability(scores, old["levels"], old["scores"]) >= card["threshold"]).mean()
    )

    calibrated_on = {"note": note, "flows": frame.height, "flows_sha256": sha256(flows_path)}
    if "ts" in frame.columns:
        calibrated_on["from"] = str(frame.get_column("ts").min())
        calibrated_on["to"] = str(frame.get_column("ts").max())

    new_card = {key: value for key, value in card.items() if key not in MEASURED_FIELDS}
    new_card.update(
        version=version,
        mode="shadow",
        threshold=threshold,
        # Not measured under this calibration; registration takes a missing value.
        pr_auc=None,
        calibration={"method": "empirical_quantiles", "levels": levels, "scores": quantiles},
        calibrated_on=calibrated_on,
        recalibrated_from={
            "version": card["version"],
            "threshold": card["threshold"],
            "flagged_share_of_these_flows": flagged_before,
            **{key: card[key] for key in MEASURED_FIELDS if key in card},
        },
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    # The registry looks for tier_d.onnx beside the card; the bytes are unchanged.
    shutil.copyfile(onnx_path, out_dir / "tier_d.onnx")
    (out_dir / "model_card.json").write_text(json.dumps(new_card, indent=2), encoding="utf-8")

    flagged_after = float(
        (anomaly_probability(scores, levels, quantiles) >= threshold).mean()
    )
    print(f"{card['name']} {card['version']} -> {version} on {frame.height:,} flows")
    print(f"flagged {flagged_before:.1%} of them before, {flagged_after:.1%} after "
          f"(threshold {threshold:.7f})")
    print(f"artefacts -> {out_dir}")
    return new_card


def main() -> None:
    parser = argparse.ArgumentParser(description="Re-baseline a Tier D model on benign flows")
    parser.add_argument("card", help="the Tier D model_card.json to start from")
    parser.add_argument("--flows", required=True,
                        help="Parquet or CSV of benign flows from the deployment, window "
                             "chosen by the operator")
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--note", required=True,
                        help="where and when the flows came from, recorded in the card")
    args = parser.parse_args()
    recalibrate(args.card, args.flows, args.out, args.version, args.note)


if __name__ == "__main__":
    main()
