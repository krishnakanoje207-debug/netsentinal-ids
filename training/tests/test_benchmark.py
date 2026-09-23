"""The benchmark report, run end to end on a small synthetic dataset.

What matters here is not the numbers but that the report cannot mislead: the TTL
ablation must actually detect a TTL shortcut when one is planted, the families in
the recall table must be the ones in the data, and the markdown must be written
from the same results that go into results.json.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.eval import benchmark

FAMILIES = ("Exploits", "Fuzzers", "DoS")


def _split(rng, rows: int) -> pl.DataFrame:
    attack = rng.random(rows) < 0.2
    data = {name: rng.gamma(2.0, 50.0, rows) for name in TIER_A_FEATURES}
    # A weak behavioural signal, and a perfect TTL one: the shortcut the audit exists for.
    data["pkt_rate"] = np.where(attack, data["pkt_rate"] * 0.5, data["pkt_rate"])
    data["min_ttl"] = np.where(attack, 254.0, 31.0)
    data["max_ttl"] = data["min_ttl"]
    data["Label"] = attack.astype(np.int8)
    data["Attack"] = np.where(attack, rng.choice(FAMILIES, rows), "Benign")
    return pl.DataFrame(data)


@pytest.fixture(scope="module")
def results(tmp_path_factory):
    rng = np.random.default_rng(7)
    data = tmp_path_factory.mktemp("processed")
    for name, rows in (("train", 3000), ("val", 1000), ("test", 1000)):
        _split(rng, rows).write_parquet(data / f"{name}.parquet")
    out = tmp_path_factory.mktemp("report")
    return benchmark.run(data, out, cross=[], onnx_path=out / "absent.onnx"), out


def test_every_learner_is_measured(results):
    res, _ = results
    assert set(res["learners"]) == set(benchmark.LEARNERS)
    for metrics in res["learners"].values():
        assert 0.0 <= metrics["pr_auc"] <= 1.0


def test_a_planted_ttl_shortcut_is_exposed(results):
    ablation = results[0]["ttl_ablation"]
    assert ablation["TTL only"]["pr_auc"] > 0.99
    assert ablation["TTL only"]["ttl_gain_share"] == pytest.approx(1.0)
    # The served feature set must never include TTL.
    assert ablation["Tier A features (served)"]["ttl_gain_share"] == 0.0


def test_recall_is_reported_for_the_families_present(results):
    recall = results[0]["family_recall"]
    assert set(recall["tier_a"]) == set(FAMILIES) | {"Benign"}
    assert set(recall["tier_d"]) == set(recall["tier_a"])


def test_report_and_json_come_from_the_same_run(results):
    res, out = results
    saved = json.loads((out / "results.json").read_text(encoding="utf-8"))
    report = (out / "REPORT.md").read_text(encoding="utf-8")

    assert saved["learners"]["LightGBM"]["pr_auc"] == res["learners"]["LightGBM"]["pr_auc"]
    assert f"{res['learners']['LightGBM']['pr_auc']:.4f}" in report
    assert f"{res['family_classifier']['macro_f1']:.4f}" in report
    for figure in ("pr_curves.png", "ttl_ablation.png", "family_confusion.png", "calibration.png"):
        assert (out / figure).exists()


def test_no_latency_section_without_an_exported_model(results):
    res, out = results
    assert res["onnx_latency"] is None
    assert "Serving latency" not in (out / "REPORT.md").read_text(encoding="utf-8")
