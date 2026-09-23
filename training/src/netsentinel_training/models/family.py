"""Which kind of attack: the family model behind an alert's MITRE technique.

    python -m netsentinel_training.models.family --data data/processed --out artefacts/family

Tier A decides *whether* a flow is an attack. This decides *which kind*, for flows Tier
A has already flagged, so it is trained on attack flows only: benign traffic is Tier
A's problem, and teaching this model to recognise it would spend its capacity on a
question already answered.

Two rules keep a guess from reading as a finding:

* **Only confident answers become a technique.** Below ``MIN_CONFIDENCE`` the alert
  keeps no technique at all. On NF-UNSW-NB15-v3 the model is right on 71% of attacks
  overall but on about 85% of those it is at least 70% sure of - and a wrong technique
  sends an analyst to the wrong playbook, which is worse than none.
* **Only families with a defensible ATT&CK technique are candidates.** UNSW-NB15's
  categories were not designed against ATT&CK. Five map onto one technique cleanly;
  Backdoor, Shellcode, Analysis and Generic each cover several unrelated behaviours
  and are left unmapped rather than forced onto the nearest ID.
* **A candidate has to earn its technique.** On the validation split, the model's
  confident predictions of that family must be right at least ``MIN_TECHNIQUE_PRECISION``
  of the time. On NF-UNSW-NB15-v3 that keeps Reconnaissance (89%), Exploits (93%) and
  DoS, and drops Fuzzers (79%) and Worms (61%): an analyst sent to the wrong playbook
  one time in five learns to ignore the column.

No class weights: they raise recall on the rare families at the cost of precision on
all of them, and here precision is what a technique label has to have.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.tier_a import sha256

ATTACK_COLUMN = "Attack"
BENIGN = "Benign"

#: Below this, the alert carries no technique rather than a guess.
MIN_CONFIDENCE = 0.7

#: How often a confident prediction of a family must be right, on validation, for that
#: family's technique to be claimed at all.
MIN_TECHNIQUE_PRECISION = 0.85

#: UNSW-NB15 attack family -> MITRE ATT&CK technique. Only families that correspond to
#: one technique are listed; see the module docstring for the ones left out.
TECHNIQUES: dict[str, str] = {
    "Reconnaissance": "T1046",  # Network Service Discovery
    "DoS": "T1499",  # Endpoint Denial of Service
    "Exploits": "T1190",  # Exploit Public-Facing Application
    "Fuzzers": "T1595.002",  # Active Scanning: Vulnerability Scanning
    "Worms": "T1210",  # Exploitation of Remote Services
}

LGBM_PARAMS = dict(
    objective="multiclass",
    n_estimators=400,
    learning_rate=0.05,
    num_leaves=63,
    min_child_samples=30,
    n_jobs=-1,
    verbose=-1,
)


def load_attacks(data_dir: Path, name: str) -> pl.DataFrame:
    frame = pl.read_parquet(data_dir / f"{name}.parquet")
    missing = [f for f in (*TIER_A_FEATURES, ATTACK_COLUMN) if f not in frame.columns]
    if missing:
        raise ValueError(f"{name}.parquet is missing {missing}")
    attacks = frame.filter(pl.col(ATTACK_COLUMN) != BENIGN)
    if attacks.height == 0:
        raise ValueError(f"{name}.parquet contains no attack flows to learn families from")
    return attacks


def encode(frame: pl.DataFrame, classes: list[str]) -> tuple[np.ndarray, np.ndarray]:
    index = {c: i for i, c in enumerate(classes)}
    x = frame.select(TIER_A_FEATURES).to_numpy().astype(np.float32)
    y = np.array([index.get(c, -1) for c in frame.get_column(ATTACK_COLUMN).to_list()])
    return x, y


def evaluate(probs: np.ndarray, y: np.ndarray, classes: list[str]) -> dict:
    """Overall quality, and quality on the answers that would become a technique."""
    from sklearn.metrics import f1_score

    predicted = probs.argmax(axis=1)
    confident = probs.max(axis=1) >= MIN_CONFIDENCE
    known = y >= 0
    per_class = f1_score(y[known], predicted[known], labels=range(len(classes)),
                         average=None, zero_division=0)
    return {
        "accuracy": float((predicted[known] == y[known]).mean()),
        "macro_f1": float(f1_score(y[known], predicted[known], average="macro", zero_division=0)),
        "confident_share": float(confident[known].mean()),
        "confident_accuracy": float((predicted[known & confident] == y[known & confident]).mean())
        if (known & confident).any()
        else 0.0,
        "f1_per_family": {c: float(v) for c, v in zip(classes, per_class)},
    }


def earned_techniques(probs: np.ndarray, y: np.ndarray, classes: list[str]) -> tuple[dict, dict]:
    """The candidate mappings whose confident predictions were right often enough.

    Returns the techniques kept and the measured precision of every candidate, so the
    card records why a family was dropped as well as that it was.
    """
    predicted = probs.argmax(axis=1)
    confident = probs.max(axis=1) >= MIN_CONFIDENCE
    precision: dict[str, float | None] = {}
    for index, family in enumerate(classes):
        if family not in TECHNIQUES:
            continue
        chosen = confident & (predicted == index)
        precision[family] = float((y[chosen] == index).mean()) if chosen.any() else None
    kept = {
        family: TECHNIQUES[family]
        for family, value in precision.items()
        if value is not None and value >= MIN_TECHNIQUE_PRECISION
    }
    return kept, precision


def train(data_dir: str | Path, out_dir: str | Path, version: str = "0.1.0") -> dict:
    import lightgbm as lgb

    data_dir, out_dir = Path(data_dir), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    train_frame = load_attacks(data_dir, "train")
    classes = sorted(train_frame.get_column(ATTACK_COLUMN).unique().to_list())
    x, y = encode(train_frame, classes)
    xv, yv = encode(load_attacks(data_dir, "val"), classes)
    xt, yt = encode(load_attacks(data_dir, "test"), classes)
    # A family absent from training cannot be predicted; drop it from early stopping
    # rather than let an unknown label crash the fit.
    xv, yv = xv[yv >= 0], yv[yv >= 0]
    print(f"training on {len(y):,} attack flows across {len(classes)} families")

    model = lgb.LGBMClassifier(**LGBM_PARAMS)
    model.fit(x, y, eval_set=[(xv, yv)],
              callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(0)])
    metrics = evaluate(model.predict_proba(xt), yt, classes)
    techniques, precision_val = earned_techniques(model.predict_proba(xv), yv, classes)

    booster_path = out_dir / "family.lgb.txt"
    model.booster_.save_model(str(booster_path))
    card = {
        "name": "family_lightgbm",
        "version": version,
        "booster_sha256": sha256(booster_path),
        "feature_order": list(TIER_A_FEATURES),
        "classes": classes,
        "min_confidence": MIN_CONFIDENCE,
        "techniques": techniques,
        "technique_precision_val": precision_val,
        "min_technique_precision": MIN_TECHNIQUE_PRECISION,
        "trained_on": "attack flows only",
        "rows": {"train": int(len(y)), "val": int(len(yv)), "test": int(len(yt))},
        "metrics_test": metrics,
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")

    print(f"accuracy {metrics['accuracy']:.4f}  macro-F1 {metrics['macro_f1']:.4f}")
    print(f"at >= {MIN_CONFIDENCE:.0%} confidence: {metrics['confident_share']:.1%} of attacks "
          f"labelled, {metrics['confident_accuracy']:.1%} of those correct")
    print(f"techniques kept: {techniques}")
    print(f"artefacts -> {out_dir}")
    return card


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the attack-family model")
    parser.add_argument("--data", default="data/processed")
    parser.add_argument("--out", default="artefacts/family")
    parser.add_argument("--version", default="0.1.0")
    args = parser.parse_args()
    train(args.data, args.out, args.version)


if __name__ == "__main__":
    main()
