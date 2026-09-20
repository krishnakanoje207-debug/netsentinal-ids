"""Registering a model card in ml_models.

Driven with a fake session, like bootstrap: the decisions are what matter, and the
riskiest one is what a second registration of the same version is allowed to change.
"""

from __future__ import annotations

import json

import pytest

from netsentinel_api.db.models import AuditLog, MLModel, ModelMode, ModelTier
from netsentinel_api.register import (
    RegistrationError,
    load_card,
    register,
)

CARD = {
    "name": "tier_a_lightgbm",
    "tier": "A",
    "version": "0.1.0",
    "onnx_sha256": "a" * 64,
    "threshold": 0.62,
    "mode": "shadow",
    "pr_auc": 0.93,
}


class RecordingSession:
    """Answers the one lookup register performs: MLModel by name and version."""

    def __init__(self, existing: list[object] | None = None) -> None:
        self.added: list[object] = []
        self.existing: list[object] = list(existing or [])

    def add(self, instance: object, /) -> None:
        self.added.append(instance)

    def scalar(self, statement):
        name, version = (clause.right.value for clause in statement.whereclause.clauses)
        for row in self.existing + self.added:
            if isinstance(row, MLModel) and row.name == name and row.version == version:
                return row
        return None


@pytest.fixture
def session() -> RecordingSession:
    return RecordingSession()


def _card(**overrides) -> dict:
    return {**CARD, **overrides}


def _written(path, card) -> str:
    path.write_text(json.dumps(card), encoding="utf-8")
    return str(path)


# --- reading the card ------------------------------------------------------

def test_a_complete_card_loads(tmp_path):
    assert load_card(_written(tmp_path / "card.json", CARD))["name"] == CARD["name"]


def test_a_missing_file_is_refused(tmp_path):
    with pytest.raises(RegistrationError, match="cannot read"):
        load_card(tmp_path / "absent.json")


def test_a_card_missing_an_ml_models_column_is_refused(tmp_path):
    card = _card()
    del card["threshold"]
    with pytest.raises(RegistrationError, match="threshold"):
        load_card(_written(tmp_path / "card.json", card))


def test_an_unknown_tier_is_refused(tmp_path):
    with pytest.raises(RegistrationError, match="unknown tier"):
        load_card(_written(tmp_path / "card.json", _card(tier="Z")))


def test_a_truncated_hash_is_refused(tmp_path):
    """ck_onnx_sha256_length would reject it anyway; this says why, first."""
    with pytest.raises(RegistrationError, match="not a SHA-256"):
        load_card(_written(tmp_path / "card.json", _card(onnx_sha256="a" * 40)))


# --- registering -----------------------------------------------------------

def test_a_new_card_becomes_a_row(session):
    model = register(session, CARD)
    assert model.name == "tier_a_lightgbm"
    assert model.tier is ModelTier.A
    assert model.threshold == pytest.approx(0.62)
    assert model.pr_auc == pytest.approx(0.93)
    assert model in session.added


def test_registration_defaults_to_shadow(session):
    """Even though promotion is one flag away, it has to be typed."""
    model = register(session, CARD)
    assert model.mode is ModelMode.shadow
    assert model.deployed_at is None


def test_activating_stamps_the_deployment_time(session):
    model = register(session, CARD, ModelMode.active)
    assert model.mode is ModelMode.active
    assert model.deployed_at is not None


def test_registration_is_audited(session):
    register(session, CARD)
    entries = [row for row in session.added if isinstance(row, AuditLog)]
    assert [row.action for row in entries] == ["model.registered"]
    assert entries[0].entity == "tier_a_lightgbm:0.1.0"


def test_re_registering_reuses_the_row(session):
    """A new row would orphan every detections.model_id pointing at the old one."""
    first = register(session, CARD)
    first.model_id = 4
    again = register(session, _card(threshold=0.71))

    assert again is first
    assert first.model_id == 4
    assert first.threshold == pytest.approx(0.71)


def test_a_different_artefact_under_the_same_version_is_refused(session):
    """Detections stored against this row came from the old file, not the new one."""
    register(session, CARD)
    with pytest.raises(RegistrationError, match="Bump the version"):
        register(session, _card(onnx_sha256="b" * 64))


def test_promotion_is_audited_but_an_unchanged_mode_is_not(session):
    register(session, CARD)
    register(session, CARD)
    assert [row.action for row in session.added if isinstance(row, AuditLog)] == [
        "model.registered"
    ]

    register(session, CARD, ModelMode.active)
    changes = [
        row
        for row in session.added
        if isinstance(row, AuditLog) and row.action == "model.mode_changed"
    ]
    assert len(changes) == 1
    assert changes[0].details == {"from": "shadow", "to": "active"}


def test_the_card_cannot_promote_itself(session):
    """mode in the card is ignored; a promotion is an operator decision."""
    model = register(session, _card(mode="active"))
    assert model.mode is ModelMode.shadow
