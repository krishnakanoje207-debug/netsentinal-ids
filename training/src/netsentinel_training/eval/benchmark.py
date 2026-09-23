"""F12 evaluation: the benchmark report behind every accuracy figure this project quotes.

    python -m netsentinel_training.eval.benchmark \
        --data data/processed/nf-unsw-nb15-v3 \
        --cross data/raw/NF-ToN-IoT-v3.parquet data/raw/NF-CICIDS2018-v3.parquet \
        --out docs/evaluation

Five questions, each answered on the temporal test split, never on data a model or
threshold was fitted to:

1. **Which learner.** LightGBM against XGBoost, a random forest and a logistic
   baseline, on the same features, the same split and the same threshold rule.
2. **Is the score real.** A shortcut ablation: the same learner with TTL, without it,
   and with TTL alone. A feature that scores near-perfectly by itself is identifying
   the testbed, and the report says so rather than quoting the number.
3. **Which attacks get through.** Recall per attack family, for the served model and
   for the unsupervised Tier D, plus a multiclass family model for macro-F1.
4. **Can the probability be read as one.** Brier score and a reliability curve,
   before and after the Platt scaling Tier A ships.
5. **Does it transfer.** The UNSW-trained model scored on other networks' traffic,
   beside a model trained on that network itself. The gap between the two is the
   honest size of the claim.

Every threshold is the Tier A rule: the highest recall within a 1% false-positive
budget on validation, then frozen and applied to test.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import numpy as np
import polars as pl

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.data import nf_mapping as nf
from netsentinel_training.models import tier_a, tier_d

LABEL = tier_a.LABEL_COLUMN
ATTACK = nf.LABEL_ATTACK
TTL = ("min_ttl", "max_ttl")
FEATURES = list(TIER_A_FEATURES)

#: Rows sampled from each cross-dataset file. The largest is tens of millions of
#: flows; a systematic sample keeps the whole time range and fits in 8 GB.
CROSS_SAMPLE = 600_000

SEED = 1337


# --- data -------------------------------------------------------------------

def load(data_dir: Path) -> dict[str, pl.DataFrame]:
    return {name: pl.read_parquet(data_dir / f"{name}.parquet") for name in ("train", "val", "test")}


def xy(frame: pl.DataFrame, features: list[str]) -> tuple[np.ndarray, np.ndarray]:
    x = frame.select(features).to_numpy().astype(np.float32)
    y = frame.get_column(LABEL).to_numpy().astype(np.int8)
    return x, y


def sample_nf(path: Path, rows: int = CROSS_SAMPLE) -> pl.DataFrame:
    """Map an NF-* file onto the contract and take an evenly spaced sample in time order."""
    lazy = pl.scan_parquet(path) if path.suffix == ".parquet" else pl.scan_csv(path)
    header = lazy.collect_schema().names()
    nf.resolve_columns(header)
    time_col = nf.find_timestamp(header)
    total = lazy.select(pl.len()).collect().item()
    step = max(1, total // rows)
    keep = FEATURES + list(TTL) + [LABEL, ATTACK] + ([time_col] if time_col else [])
    frame = nf.to_contract(lazy).select(keep).gather_every(step).collect()
    if time_col:
        frame = frame.sort(time_col)
    return frame


# --- learners ---------------------------------------------------------------

def fit_lightgbm(x, y, xv, yv, **overrides):
    import lightgbm as lgb

    params = dict(tier_a.LGBM_PARAMS) | overrides
    model = lgb.LGBMClassifier(**params, scale_pos_weight=(y == 0).sum() / max(y.sum(), 1))
    model.fit(x, y, eval_set=[(xv, yv)], eval_metric="average_precision",
              callbacks=[lgb.early_stopping(50, verbose=False), lgb.log_evaluation(0)])
    return model


def fit_xgboost(x, y, xv, yv):
    from xgboost import XGBClassifier

    model = XGBClassifier(
        n_estimators=600, learning_rate=0.05, max_depth=8, subsample=0.8,
        colsample_bytree=0.8, tree_method="hist", eval_metric="aucpr",
        early_stopping_rounds=50, scale_pos_weight=(y == 0).sum() / max(y.sum(), 1),
        n_jobs=-1, random_state=SEED,
    )
    model.fit(x, y, eval_set=[(xv, yv)], verbose=False)
    return model


def fit_forest(x, y, xv, yv):
    from sklearn.ensemble import RandomForestClassifier

    # max_samples bounds each tree's size: a fully grown forest over 1.6M rows does
    # not fit beside everything else in 8 GB.
    return RandomForestClassifier(
        n_estimators=100, min_samples_leaf=5, max_samples=0.2,
        class_weight="balanced_subsample", n_jobs=-1, random_state=SEED,
    ).fit(x, y)


def fit_logistic(x, y, xv, yv):
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import FunctionTransformer, StandardScaler

    # Counts and rates span nine orders of magnitude; a linear model needs them logged.
    return make_pipeline(
        FunctionTransformer(np.log1p), StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=500),
    ).fit(np.clip(x, 0, None), y)


LEARNERS = {
    "LightGBM": fit_lightgbm,
    "XGBoost": fit_xgboost,
    "Random forest": fit_forest,
    "Logistic regression": fit_logistic,
}


def scores(model, x: np.ndarray) -> np.ndarray:
    if hasattr(model, "steps"):  # the logistic pipeline expects non-negative input
        x = np.clip(x, 0, None)
    return model.predict_proba(x)[:, 1]


def assess(model, split: dict, features: list[str]) -> tuple[dict, np.ndarray, float]:
    """Threshold on validation, measure on test. Returns metrics, test scores, threshold."""
    xv, yv = xy(split["val"], features)
    xt, yt = xy(split["test"], features)
    threshold = tier_a.choose_threshold(scores(model, xv), yv)
    started = time.perf_counter()
    probs = scores(model, xt)
    per_flow_us = (time.perf_counter() - started) / len(xt) * 1e6
    metrics = tier_a.evaluate(probs, yt, threshold)
    metrics["batch_us_per_flow"] = per_flow_us
    return metrics, probs, threshold


# --- the five questions -------------------------------------------------------

def compare_learners(split) -> tuple[dict, dict]:
    x, y = xy(split["train"], FEATURES)
    xv, yv = xy(split["val"], FEATURES)
    results, curves = {}, {}
    for name, fit in LEARNERS.items():
        started = time.perf_counter()
        model = fit(x, y, xv, yv)
        fit_s = time.perf_counter() - started
        metrics, probs, threshold = assess(model, split, FEATURES)
        metrics |= {"fit_seconds": fit_s, "threshold": threshold}
        results[name] = metrics
        curves[name] = probs
        print(f"  {name:<20} PR-AUC {metrics['pr_auc']:.4f}  recall {metrics['recall']:.4f}  "
              f"FPR {metrics['false_positive_rate']:.4f}  ({fit_s:.0f}s)")
        del model
    return results, curves


def ablate_ttl(split) -> dict:
    variants = {
        "Tier A features (served)": FEATURES,
        "Tier A + TTL": FEATURES + list(TTL),
        "TTL only": list(TTL),
    }
    out = {}
    for name, features in variants.items():
        x, y = xy(split["train"], features)
        xv, yv = xy(split["val"], features)
        model = fit_lightgbm(x, y, xv, yv)
        metrics, _, _ = assess(model, split, features)
        gain = model.booster_.feature_importance("gain")
        share = {f: float(g / gain.sum()) for f, g in zip(features, gain)}
        metrics |= {
            "trees": int(model.best_iteration_ or model.n_estimators),
            "ttl_gain_share": sum(share.get(f, 0.0) for f in TTL),
            "top_features": sorted(share, key=share.get, reverse=True)[:3],
        }
        out[name] = metrics
        print(f"  {name:<26} PR-AUC {metrics['pr_auc']:.4f}  trees {metrics['trees']}  "
              f"TTL share of gain {metrics['ttl_gain_share']:.2f}")
    return out


def per_family(split, probs: np.ndarray, threshold: float) -> dict[str, float]:
    families = split["test"].get_column(ATTACK).to_numpy()
    flagged = probs >= threshold
    return {
        family: float(flagged[families == family].mean())
        for family in sorted(set(families))
    }


def tier_d_families(split) -> tuple[dict, dict]:
    """The Tier D detector on benign traffic only: what unfamiliarity alone catches."""
    train = split["train"].filter(pl.col(LABEL) == 0).select(FEATURES).to_numpy().astype(np.float32)
    val = split["val"].filter(pl.col(LABEL) == 0).select(FEATURES).to_numpy().astype(np.float32)
    xt, yt = xy(split["test"], FEATURES)
    detector = tier_d.fit_detector(train)
    levels, quantiles = tier_d.fit_quantiles(detector.decision_function(tier_d.log_scale(val)))
    probs = tier_d.anomaly_probability(
        detector.decision_function(tier_d.log_scale(xt)), levels, quantiles
    )
    threshold = 1.0 - tier_d.TARGET_MAX_FPR
    metrics = tier_d.evaluate(probs, yt, threshold)
    return metrics, per_family(split, probs, threshold)


def tier_d_variants(split, benign_rows: int = 400_000, test_rows: int = 100_000) -> dict:
    """Why Tier D is the forest it is: the M2 default, the served one, and LOF.

    On samples, because LOF scores against every reference point and a full test split
    would take hours on this machine; the samples are the same for all three.
    """
    from sklearn.ensemble import IsolationForest
    from sklearn.neighbors import LocalOutlierFactor
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler

    benign = split["train"].filter(pl.col(LABEL) == 0)
    train = benign.sample(n=min(benign_rows, benign.height), seed=SEED)
    train = train.select(FEATURES).to_numpy().astype(np.float32)
    val = split["val"].filter(pl.col(LABEL) == 0).select(FEATURES).to_numpy().astype(np.float32)
    test = split["test"].sample(n=min(test_rows, split["test"].height), seed=SEED)
    xt, yt = xy(test, FEATURES)
    log = tier_d.log_scale
    raw_forest = dict(tier_d.FOREST_PARAMS) | {"max_samples": 256}

    variants = {
        "Isolation Forest, raw features, 256-row subsamples (M2 default)":
            (IsolationForest(**raw_forest).fit(train), lambda x: x),
        "Isolation Forest, log features, 4096-row subsamples (served)":
            (tier_d.fit_detector(train), log),
        "Local Outlier Factor, log features (not servable: see Tier D)":
            (make_pipeline(StandardScaler(), LocalOutlierFactor(n_neighbors=35, novelty=True,
                                                                 n_jobs=-1)).fit(log(train[:60_000])),
             log),
    }
    out = {}
    for name, (model, transform) in variants.items():
        levels, quantiles = tier_d.fit_quantiles(model.decision_function(transform(val)))
        probs = tier_d.anomaly_probability(model.decision_function(transform(xt)), levels, quantiles)
        out[name] = tier_d.evaluate(probs, yt, 1.0 - tier_d.TARGET_MAX_FPR)
        print(f"  {name[:40]:<40} PR-AUC {out[name]['pr_auc']:.4f} recall {out[name]['recall']:.4f}")
    return out


def family_classifier(split) -> dict:
    """Which family, not only whether: macro-F1 over the nine attack classes and benign."""
    import lightgbm as lgb
    from sklearn.metrics import classification_report, confusion_matrix, f1_score

    train = split["train"]
    # Benign dominates 50:1; a sample keeps the family boundaries from drowning in it.
    benign = train.filter(pl.col(ATTACK) == "Benign")
    benign = benign.sample(n=min(200_000, benign.height), seed=SEED)
    train = pl.concat([benign, train.filter(pl.col(ATTACK) != "Benign")])
    classes = sorted(set().union(*(f.get_column(ATTACK).unique().to_list() for f in split.values())))
    index = {c: i for i, c in enumerate(classes)}

    def encode(frame):
        return (frame.select(FEATURES).to_numpy().astype(np.float32),
                np.array([index[c] for c in frame.get_column(ATTACK).to_list()]))

    x, y = encode(train)
    xv, yv = encode(split["val"])
    xt, yt = encode(split["test"])
    model = lgb.LGBMClassifier(
        objective="multiclass", n_estimators=400, learning_rate=0.05, num_leaves=63,
        min_child_samples=30, class_weight="balanced", n_jobs=-1, verbose=-1,
    )
    model.fit(x, y, eval_set=[(xv, yv)],
              callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(0)])
    predicted = model.predict(xt)
    report = classification_report(yt, predicted, target_names=classes, output_dict=True,
                                   zero_division=0)
    return {
        "classes": classes,
        "macro_f1": float(f1_score(yt, predicted, average="macro")),
        "macro_f1_attacks_only": float(np.mean([report[c]["f1-score"] for c in classes
                                                if c != "Benign"])),
        "weighted_f1": float(f1_score(yt, predicted, average="weighted")),
        "per_class": {c: {k: float(report[c][k]) for k in ("precision", "recall", "f1-score",
                                                           "support")} for c in classes},
        "confusion": confusion_matrix(yt, predicted, labels=range(len(classes))).tolist(),
    }


def calibration(split) -> dict:
    from sklearn.calibration import calibration_curve
    from sklearn.metrics import brier_score_loss

    x, y = xy(split["train"], FEATURES)
    xv, yv = xy(split["val"], FEATURES)
    xt, yt = xy(split["test"], FEATURES)
    model = fit_lightgbm(x, y, xv, yv)
    a, b = tier_a.fit_platt(model.booster_.predict(xv, raw_score=True), yv)
    raw = model.predict_proba(xt)[:, 1]
    platt = tier_a.apply_platt(model.booster_.predict(xt, raw_score=True), a, b)
    curves = {}
    for name, probs in (("uncalibrated", raw), ("platt", platt)):
        observed, predicted = calibration_curve(yt, probs, n_bins=10, strategy="quantile")
        curves[name] = {"brier": float(brier_score_loss(yt, probs)),
                        "predicted": predicted.tolist(), "observed": observed.tolist()}
    return curves


def cross_dataset(split, paths: list[Path]) -> dict:
    """Train on UNSW, test elsewhere; and train on the target itself for reference."""
    x, y = xy(split["train"], FEATURES)
    xv, yv = xy(split["val"], FEATURES)
    source_model = fit_lightgbm(x, y, xv, yv)
    source_threshold = tier_a.choose_threshold(scores(source_model, xv), yv)

    out = {}
    for path in paths:
        name = path.stem
        frame = sample_nf(path)
        n = frame.height
        parts = {"train": frame[: int(n * 0.70)], "val": frame[int(n * 0.70): int(n * 0.85)],
                 "test": frame[int(n * 0.85):]}
        xt, yt = xy(parts["test"], FEATURES)
        if yt.min() == yt.max():
            print(f"  {name}: test slice holds one class only, skipped")
            continue
        transferred = tier_a.evaluate(scores(source_model, xt), yt, source_threshold)

        xtr, ytr = xy(parts["train"], FEATURES)
        xva, yva = xy(parts["val"], FEATURES)
        native = fit_lightgbm(xtr, ytr, xva, yva)
        in_domain, _, _ = assess(native, parts, FEATURES)

        out[name] = {
            "sampled_rows": n,
            "attack_share_test": float(yt.mean()),
            "families_test": sorted(parts["test"].get_column(ATTACK).unique().to_list()),
            "trained_on_unsw": transferred,
            "trained_in_domain": in_domain,
        }
        print(f"  {name:<22} UNSW model PR-AUC {transferred['pr_auc']:.4f} "
              f"recall {transferred['recall']:.4f} | in-domain PR-AUC {in_domain['pr_auc']:.4f}")
        del native
    return out


def onnx_latency(onnx_path: Path, split, calls: int = 2000) -> dict | None:
    """NFR-01: per-flow latency of the exported graph, one flow per call as the sensor runs it."""
    if not onnx_path.exists():
        return None
    import onnxruntime as ort

    session = ort.InferenceSession(str(onnx_path), providers=["CPUExecutionProvider"])
    name = session.get_inputs()[0].name
    width = session.get_inputs()[0].shape[1]
    xt, _ = xy(split["test"], FEATURES)
    if width != xt.shape[1]:
        return None
    timings = []
    for row in xt[:calls]:
        started = time.perf_counter()
        session.run(None, {name: row.reshape(1, -1)})
        timings.append((time.perf_counter() - started) * 1000)
    timings = np.array(timings)
    return {"p50_ms": float(np.percentile(timings, 50)), "p99_ms": float(np.percentile(timings, 99)),
            "calls": calls}


# --- figures and report ---------------------------------------------------------

def figures(out: Path, results: dict, curves: dict, y_test: np.ndarray) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from sklearn.metrics import precision_recall_curve

    out.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(6, 4.5))
    for name, probs in curves.items():
        precision, recall, _ = precision_recall_curve(y_test, probs)
        ax.plot(recall, precision, label=f"{name} (AP {results['learners'][name]['pr_auc']:.3f})")
    ax.set(xlabel="Recall", ylabel="Precision", title="Precision-recall, temporal test split",
           xlim=(0, 1.01), ylim=(0, 1.01))
    ax.legend(loc="lower left", fontsize=8)
    fig.tight_layout(); fig.savefig(out / "pr_curves.png", dpi=150); plt.close(fig)

    ablation = results["ttl_ablation"]
    fig, ax = plt.subplots(figsize=(6, 3))
    names = list(ablation)
    ax.barh(names, [ablation[n]["pr_auc"] for n in names], color=["#2b6cb0", "#a0aec0", "#c53030"])
    for i, n in enumerate(names):
        ax.text(ablation[n]["pr_auc"], i, f" {ablation[n]['pr_auc']:.4f} ({ablation[n]['trees']} trees)",
                va="center", fontsize=8)
    ax.set(xlim=(0.9, 1.06), xlabel="PR-AUC", title="TTL shortcut: two features, near-perfect score")
    fig.tight_layout(); fig.savefig(out / "ttl_ablation.png", dpi=150); plt.close(fig)

    fam = results["family_classifier"]
    matrix = np.array(fam["confusion"], dtype=float)
    matrix = matrix / matrix.sum(axis=1, keepdims=True)
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.imshow(matrix, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(fam["classes"])), fam["classes"], rotation=45, ha="right", fontsize=8)
    ax.set_yticks(range(len(fam["classes"])), fam["classes"], fontsize=8)
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            if matrix[i, j] >= 0.01:
                ax.text(j, i, f"{matrix[i, j]:.2f}", ha="center", va="center", fontsize=6,
                        color="white" if matrix[i, j] > 0.5 else "black")
    ax.set(xlabel="Predicted", ylabel="True",
           title=f"Attack family, row-normalised (macro-F1 {fam['macro_f1']:.3f})")
    fig.tight_layout(); fig.savefig(out / "family_confusion.png", dpi=150); plt.close(fig)

    cal = results["calibration"]
    fig, ax = plt.subplots(figsize=(5, 4.5))
    ax.plot([0, 1], [0, 1], "k:", label="perfect")
    for name, curve in cal.items():
        ax.plot(curve["predicted"], curve["observed"], "o-", label=f"{name} (Brier {curve['brier']:.4f})")
    ax.set(xlabel="Predicted probability", ylabel="Observed attack share", title="Reliability")
    ax.legend(fontsize=8)
    fig.tight_layout(); fig.savefig(out / "calibration.png", dpi=150); plt.close(fig)

    if results.get("cross_dataset"):
        cross = results["cross_dataset"]
        names = list(cross)
        fig, ax = plt.subplots(figsize=(6, 3.5))
        width = 0.38
        positions = np.arange(len(names))
        ax.bar(positions - width / 2, [cross[n]["trained_on_unsw"]["pr_auc"] for n in names],
               width, label="trained on UNSW-NB15", color="#c53030")
        ax.bar(positions + width / 2, [cross[n]["trained_in_domain"]["pr_auc"] for n in names],
               width, label="trained on the target", color="#2b6cb0")
        ax.set_xticks(positions, names, fontsize=8)
        ax.set(ylim=(0, 1.05), ylabel="PR-AUC", title="Does it transfer to another network?")
        ax.legend(fontsize=8)
        fig.tight_layout(); fig.savefig(out / "cross_dataset.png", dpi=150); plt.close(fig)


def pct(value: float) -> str:
    return f"{value * 100:.2f}%"


def report(results: dict) -> str:
    learners = results["learners"]
    lines = [
        "# Tier A evaluation — NF-UNSW-NB15-v3",
        "",
        "Generated by `python -m netsentinel_training.eval.benchmark`; every number below is "
        "in `results.json` beside this file. Temporal split on `FLOW_START_MILLISECONDS` "
        f"(train {results['rows']['train']:,} / val {results['rows']['val']:,} / "
        f"test {results['rows']['test']:,} flows; {pct(results['attack_share_test'])} attacks in test). "
        "Thresholds are chosen on validation for at most 1% false positives, then frozen.",
        "",
        "## 1. Learner comparison (13 Tier A features)",
        "",
        "| Model | PR-AUC | ROC-AUC | Precision | Recall | F1 | FPR | Fit (s) | µs/flow (batch) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in learners.items():
        lines.append(
            f"| {name} | {m['pr_auc']:.4f} | {m['roc_auc']:.4f} | {m['precision']:.4f} | "
            f"{m['recall']:.4f} | {m['f1']:.4f} | {m['false_positive_rate']:.4f} | "
            f"{m['fit_seconds']:.0f} | {m['batch_us_per_flow']:.2f} |")
    lines += ["", "![PR curves](pr_curves.png)", "",
              "## 2. Shortcut audit: TTL", "",
              "| Features | PR-AUC | Trees | TTL share of gain | Top features |",
              "|---|---|---|---|---|"]
    for name, m in results["ttl_ablation"].items():
        lines.append(f"| {name} | {m['pr_auc']:.4f} | {m['trees']} | {m['ttl_gain_share']:.2f} | "
                     f"{', '.join(m['top_features'])} |")
    lines += [
        "",
        "TTL alone separates the classes almost perfectly because it identifies which testbed "
        "machine sent the flow, not what the flow did. It is therefore excluded from Tier A "
        "(`contract.TIER_A_FEATURES`); the served model is the first row.",
        "", "![TTL ablation](ttl_ablation.png)", "",
        "## 3. Recall per attack family (at the 1%-FPR threshold)", "",
        "| Family | Tier A (LightGBM) | Tier D (LOF, benign-only) |",
        "|---|---|---|",
    ]
    for family, recall in results["family_recall"]["tier_a"].items():
        if family == "Benign":
            continue
        lines.append(f"| {family} | {pct(recall)} | {pct(results['family_recall']['tier_d'][family])} |")
    td = results["tier_d"]
    lines += ["", "### Tier D: which unsupervised detector", "",
              "Benign-only training, calibrated on validation benign flows, flagged at the "
              "1% budget; on a 100k-flow test sample shared by all three.", "",
              "| Detector | PR-AUC | Recall | FPR |", "|---|---|---|---|"]
    for name, m in results["tier_d_variants"].items():
        lines.append(f"| {name} | {m['pr_auc']:.4f} | {pct(m['recall'])} | "
                     f"{pct(m['false_positive_rate'])} |")
    lines += [
        "",
        "The log transform is what matters: counts span nine orders of magnitude and a forest "
        "splits uniformly between a feature's extremes. LOF ranks best but exported to ONNX it "
        "searches its reference set on every call (over 100 ms per flow against the 5 ms "
        "budget of NFR-01), so the forest is served.",
    ]
    lines += [
        "",
        f"Tier D never sees an attack in training; at a {pct(td['false_positive_rate'])} false-positive "
        f"rate it recalls {pct(td['recall'])} of attacks (PR-AUC {td.get('pr_auc', float('nan')):.4f}). "
        "It is the tier that objects to the unfamiliar, not the one that names it.",
        "",
    ]
    fam = results["family_classifier"]
    lines += [
        "### Attack family classifier", "",
        f"Multiclass LightGBM over the same 13 features: **macro-F1 {fam['macro_f1']:.4f}** "
        f"(attack classes only {fam['macro_f1_attacks_only']:.4f}; weighted {fam['weighted_f1']:.4f}).",
        "", "| Class | Precision | Recall | F1 | Support |", "|---|---|---|---|---|",
    ]
    for c, m in fam["per_class"].items():
        lines.append(f"| {c} | {m['precision']:.3f} | {m['recall']:.3f} | {m['f1-score']:.3f} | "
                     f"{int(m['support']):,} |")
    lines += ["", "![Family confusion matrix](family_confusion.png)", "",
              "## 4. Calibration", "",
              "| | Brier score |", "|---|---|"]
    for name, curve in results["calibration"].items():
        lines.append(f"| {name} | {curve['brier']:.5f} |")
    lines += ["", "![Reliability](calibration.png)", ""]
    if results.get("cross_dataset"):
        lines += ["## 5. Cross-dataset generalisation", "",
                  "| Target dataset | Attack share | UNSW-trained PR-AUC | recall | FPR | "
                  "In-domain PR-AUC | recall | FPR |", "|---|---|---|---|---|---|---|---|"]
        for name, c in results["cross_dataset"].items():
            u, d = c["trained_on_unsw"], c["trained_in_domain"]
            lines.append(f"| {name} | {pct(c['attack_share_test'])} | {u['pr_auc']:.4f} | "
                         f"{u['recall']:.4f} | {u['false_positive_rate']:.4f} | {d['pr_auc']:.4f} | "
                         f"{d['recall']:.4f} | {d['false_positive_rate']:.4f} |")
        lines += [
            "",
            "Two different failures. Trained on UNSW and moved elsewhere, the model ranks "
            "worse and its threshold is meaningless on the new traffic (the false-positive "
            "column). Trained on the target itself, it ranks well (PR-AUC) but a threshold set "
            "on the validation period misses most attacks in the test period, because the "
            "attack mix changes over time. Both are why every model is born in shadow mode and "
            "promoted only on measured, site-local evidence.",
            "", "![Cross-dataset](cross_dataset.png)", ""]
    if results.get("onnx_latency"):
        lat = results["onnx_latency"]
        lines += ["## 6. Serving latency (NFR-01: ≤ 5 ms per flow)", "",
                  f"Exported ONNX graph, one flow per call over {lat['calls']:,} test flows: "
                  f"p50 **{lat['p50_ms']:.3f} ms**, p99 **{lat['p99_ms']:.3f} ms** (Tier A)."]
        if results.get("onnx_latency_tier_d"):
            lat_d = results["onnx_latency_tier_d"]
            lines.append(f"Tier D, the same way: p50 **{lat_d['p50_ms']:.3f} ms**, "
                         f"p99 **{lat_d['p99_ms']:.3f} ms**.")
        lines.append("")
    return "\n".join(lines)


def run(data_dir: Path, out: Path, cross: list[Path], onnx_path: Path) -> dict:
    split = load(data_dir)
    _, y_test = xy(split["test"], FEATURES)
    results: dict = {
        "dataset": data_dir.name,
        "features": FEATURES,
        "rows": {k: v.height for k, v in split.items()},
        "attack_share_test": float(y_test.mean()),
    }
    print("1. learners"); results["learners"], curves = compare_learners(split)
    lgbm = results["learners"]["LightGBM"]
    results["family_recall"] = {"tier_a": per_family(split, curves["LightGBM"], lgbm["threshold"])}
    print("2. TTL ablation"); results["ttl_ablation"] = ablate_ttl(split)
    print("3. Tier D and families")
    results["tier_d"], results["family_recall"]["tier_d"] = tier_d_families(split)
    results["tier_d_variants"] = tier_d_variants(split)
    results["family_classifier"] = family_classifier(split)
    print(f"  macro-F1 {results['family_classifier']['macro_f1']:.4f}")
    print("4. calibration"); results["calibration"] = calibration(split)
    if cross:
        print("5. cross-dataset"); results["cross_dataset"] = cross_dataset(split, cross)
    results["onnx_latency"] = onnx_latency(onnx_path, split)
    results["onnx_latency_tier_d"] = onnx_latency(onnx_path.parent.parent / "tier_d" / "tier_d.onnx", split)

    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    figures(out, results, curves, y_test)
    (out / "REPORT.md").write_text(report(results), encoding="utf-8")
    print(f"report -> {out / 'REPORT.md'}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Tier A benchmark report")
    parser.add_argument("--data", required=True, help="dir with train/val/test Parquet from prep")
    parser.add_argument("--out", default="docs/evaluation")
    parser.add_argument("--cross", nargs="*", default=[], help="other NF-* files to test transfer on")
    parser.add_argument("--onnx", default="artefacts/tier_a/tier_a.onnx")
    args = parser.parse_args()
    run(Path(args.data), Path(args.out), [Path(p) for p in args.cross], Path(args.onnx))


if __name__ == "__main__":
    main()
