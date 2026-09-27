"""Re-baselining Tier D on a deployment's own benign traffic.

The claims: a deployment whose normal traffic the benchmark never showed stops being
flagged wholesale, the artefact is untouched so the registry still accepts it, and the
card says what it was baselined on.
"""

from __future__ import annotations

import json

import numpy as np
import polars as pl
import pytest

from netsentinel_core.features.contract import TIER_A_FEATURES
from netsentinel_training.models.recalibrate import MIN_FLOWS, recalibrate
from netsentinel_training.models.tier_a import sha256
from netsentinel_training.models.tier_d import TARGET_MAX_FPR


def _benign(rows: int, rng: np.random.Generator, centre: float) -> pl.DataFrame:
    return pl.DataFrame(
        {name: rng.normal(centre, 1.0, rows) for name in TIER_A_FEATURES}
    ).with_columns(Label=pl.lit(0, dtype=pl.Int8))


@pytest.fixture(scope="module")
def source_dir(tmp_path_factory):
    """A forest trained on benchmark-like benign flows centred on 0."""
    from netsentinel_training.models import tier_d

    data = tmp_path_factory.mktemp("benchmark")
    rng = np.random.default_rng(3)
    for name, rows in (("train", 3000), ("val", 1500), ("test", 500)):
        _benign(rows, rng, 0.0).write_parquet(data / f"{name}.parquet")
    out = tmp_path_factory.mktemp("tier_d")
    with pytest.MonkeyPatch.context() as patch:
        patch.setitem(tier_d.FOREST_PARAMS, "n_estimators", 40)
        tier_d.train(data, out, version="1.0.0")
    return out


def _deployment(tmp_path, name: str, rows: int, seed: int):
    """This deployment's normal traffic sits elsewhere than the benchmark's."""
    path = tmp_path / name
    _benign(rows, np.random.default_rng(seed), 4.0).drop("Label").write_parquet(path)
    return path


def _flagged(card_path, flows_path) -> float:
    from netsentinel_scoring.registry import load_model

    model = load_model(card_path)
    x = pl.read_parquet(flows_path).select(TIER_A_FEATURES).to_numpy()
    return float((model.score(x) >= model.threshold).mean())


@pytest.fixture(scope="module")
def recalibrated(source_dir, tmp_path_factory):
    tmp = tmp_path_factory.mktemp("deployment")
    flows = _deployment(tmp, "baseline.parquet", 3000, seed=11)
    card = recalibrate(source_dir / "model_card.json", flows, tmp / "out", "1.1.0-lab",
                       note="test deployment")
    return card, tmp / "out", flows


def test_unfamiliar_benign_traffic_is_flagged_wholesale_before(recalibrated):
    card, _, _ = recalibrated
    assert card["recalibrated_from"]["flagged_share_of_these_flows"] > 0.9


def test_after_baselining_fresh_deployment_traffic_keeps_the_budget(
    source_dir, recalibrated, tmp_path
):
    """Measured on flows the baseline never saw, through the registry as the sensor runs it."""
    _, out, _ = recalibrated
    fresh = _deployment(tmp_path, "fresh.parquet", 3000, seed=12)
    assert _flagged(source_dir / "model_card.json", fresh) > 0.9
    assert _flagged(out / "model_card.json", fresh) <= TARGET_MAX_FPR * 3


def test_the_artefact_is_unchanged_so_the_registry_accepts_it(source_dir, recalibrated):
    card, out, _ = recalibrated
    assert (out / "tier_d.onnx").read_bytes() == (source_dir / "tier_d.onnx").read_bytes()
    assert card["onnx_sha256"] == sha256(out / "tier_d.onnx")


def test_it_is_a_new_version_born_in_shadow(recalibrated):
    card, out, _ = recalibrated
    written = json.loads((out / "model_card.json").read_text(encoding="utf-8"))
    assert written == card
    assert card["version"] == "1.1.0-lab" and card["mode"] == "shadow"
    assert card["name"] == "tier_d_isolation_forest"
    assert card["feature_order"] == list(TIER_A_FEATURES)


def test_the_card_records_what_it_was_baselined_on(recalibrated):
    card, _, flows = recalibrated
    assert card["calibrated_on"] == {
        "note": "test deployment", "flows": 3000, "flows_sha256": sha256(flows),
    }


def test_measurements_of_the_old_calibration_are_not_passed_off_as_new(recalibrated):
    card, _, _ = recalibrated
    assert card["pr_auc"] is None and "metrics_test" not in card
    assert card["recalibrated_from"]["version"] == "1.0.0"
    assert "metrics_test" in card["recalibrated_from"]


def test_too_few_flows_are_refused(source_dir, tmp_path):
    flows = _deployment(tmp_path, "small.parquet", MIN_FLOWS - 1, seed=1)
    with pytest.raises(ValueError, match="at least"):
        recalibrate(source_dir / "model_card.json", flows, tmp_path / "out", "2.0.0", "x")


def test_flows_missing_features_are_refused(source_dir, tmp_path):
    flows = tmp_path / "flows.csv"
    pl.DataFrame({"proto": [6.0] * MIN_FLOWS}).write_csv(flows)
    with pytest.raises(ValueError, match="missing features"):
        recalibrate(source_dir / "model_card.json", flows, tmp_path / "out", "2.0.0", "x")


def test_the_same_version_is_refused(source_dir, tmp_path):
    flows = _deployment(tmp_path, "flows.parquet", MIN_FLOWS, seed=1)
    with pytest.raises(ValueError, match="card.s own"):
        recalibrate(source_dir / "model_card.json", flows, tmp_path / "out", "1.0.0", "x")


def test_writing_over_the_source_card_is_refused(source_dir, tmp_path):
    flows = _deployment(tmp_path, "flows.parquet", MIN_FLOWS, seed=1)
    with pytest.raises(ValueError, match="overwrite"):
        recalibrate(source_dir / "model_card.json", flows, source_dir, "2.0.0", "x")


def test_an_artefact_that_does_not_match_its_card_is_refused(source_dir, tmp_path):
    copy = tmp_path / "tampered"
    copy.mkdir()
    (copy / "model_card.json").write_bytes((source_dir / "model_card.json").read_bytes())
    (copy / "tier_d.onnx").write_bytes((source_dir / "tier_d.onnx").read_bytes() + b"\0")
    flows = _deployment(tmp_path, "flows.parquet", MIN_FLOWS, seed=1)
    with pytest.raises(ValueError, match="does not match"):
        recalibrate(copy / "model_card.json", flows, tmp_path / "out", "2.0.0", "x")
