"""The feature contract is load-bearing, so it is pinned by tests.

A change here means every trained model must be retrained. If one of these tests
fails, that is the intended alarm - bump the model version, do not relax the
test.
"""

from __future__ import annotations

import pytest

from netsentinel.features.contract import (
    FEATURE_DIM,
    FEATURE_ORDER,
    SCALAR_FIELDS,
    SPLT_IAT_FIELDS,
    SPLT_LEN_FIELDS,
    SPLT_N,
    FlowFeatures,
    FlowKey,
)


def _valid_features() -> FlowFeatures:
    return FlowFeatures(
        key=FlowKey("10.0.0.1", "10.0.0.2", 1234, 80, 6),
        ts_start=0.0,
        ts_last=1.0,
        scalars={name: float(i) for i, name in enumerate(SCALAR_FIELDS)},
        splt_len=[1] * SPLT_N,
        splt_iat=[0.5] * SPLT_N,
    )


def test_dimension_is_pinned():
    # 33 flow aggregates + 20 SPLT lengths + 20 SPLT inter-arrival times.
    assert len(SCALAR_FIELDS) == 33
    assert SPLT_N == 20
    assert FEATURE_DIM == 73
    assert len(FEATURE_ORDER) == FEATURE_DIM


def test_no_duplicate_feature_names():
    assert len(set(FEATURE_ORDER)) == len(FEATURE_ORDER)


def test_order_is_scalars_then_len_then_iat():
    assert FEATURE_ORDER[: len(SCALAR_FIELDS)] == SCALAR_FIELDS
    assert FEATURE_ORDER[len(SCALAR_FIELDS) : len(SCALAR_FIELDS) + SPLT_N] == SPLT_LEN_FIELDS
    assert FEATURE_ORDER[len(SCALAR_FIELDS) + SPLT_N :] == SPLT_IAT_FIELDS


def test_to_vector_matches_feature_order():
    features = _valid_features()
    vector = features.to_vector()
    assert len(vector) == FEATURE_DIM
    # Scalars were seeded with their own index, so position must equal value.
    for i, name in enumerate(SCALAR_FIELDS):
        assert vector[i] == float(i), f"{name} landed at the wrong index"


def test_label_never_enters_the_vector():
    features = _valid_features()
    features.label = "Exploits"
    assert len(features.to_vector()) == FEATURE_DIM
    assert "label" not in FEATURE_ORDER


def test_short_splt_is_rejected():
    features = _valid_features()
    features.splt_len = [1] * (SPLT_N - 1)
    with pytest.raises(ValueError, match="SPLT width mismatch"):
        features.to_vector()


def test_missing_scalar_is_rejected():
    features = _valid_features()
    del features.scalars["proto"]
    with pytest.raises(ValueError, match="missing scalar features"):
        features.to_vector()


def test_as_row_covers_every_feature():
    row = _valid_features().as_row()
    for name in FEATURE_ORDER:
        assert name in row, f"{name} would be lost on the way to ClickHouse"
