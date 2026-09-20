"""Registering a trained model with the database.

    python -m netsentinel_api.register artefacts/tier_a/model_card.json

``ml_models`` is the join between a file on disk and a row a detection can point at.
Training writes the card, this puts it in PostgreSQL, and only then can the writer
attribute a detection to a model.

Two rules, both about not rewriting history:

* A model is identified by ``(name, version)``, and re-registering the same pair
  updates the mutable columns only. A detection already references that row.
* ``onnx_sha256`` is immutable. A card presenting a different hash under a version
  that already exists is refused rather than applied, because the detections stored
  against that row were produced by the old artefact and would silently start
  claiming to come from the new one. Bump the version instead.

Mode is deliberately not taken from the card. Promotion is an operator decision
recorded in the audit log, not a property of a file, and a card is born ``shadow``
anyway - so ``--mode active`` has to be typed by a person.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from netsentinel_api.db.models import AuditLog, MLModel, ModelMode, ModelTier
from netsentinel_api.db.session import get_sessionmaker

#: Everything ml_models needs that a card is expected to supply.
REQUIRED_CARD_FIELDS = ("name", "tier", "version", "onnx_sha256", "threshold")


class RegistrationError(RuntimeError):
    """The card could not be registered. The message says which rule it broke."""


def load_card(path: str | Path) -> dict:
    path = Path(path)
    try:
        card = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistrationError(f"cannot read model card {path}: {exc}") from exc

    missing = [field for field in REQUIRED_CARD_FIELDS if field not in card]
    if missing:
        raise RegistrationError(f"model card {path} is missing fields {missing}")

    tier = str(card["tier"])
    if tier not in {member.value for member in ModelTier}:
        raise RegistrationError(f"unknown tier {tier!r} in {path}")

    digest = str(card["onnx_sha256"])
    if len(digest) != 64:
        raise RegistrationError(
            f"onnx_sha256 in {path} is {len(digest)} characters, not a SHA-256"
        )
    return card


def register(session: Session, card: dict, mode: ModelMode = ModelMode.shadow) -> MLModel:
    """Insert or update the row for this card. Returns it, unflushed."""
    name, version = str(card["name"]), str(card["version"])
    existing = session.scalar(
        select(MLModel).where(MLModel.name == name, MLModel.version == version)
    )

    if existing is not None:
        if existing.onnx_sha256 != str(card["onnx_sha256"]):
            raise RegistrationError(
                f"{name}:{version} is already registered against artefact "
                f"{existing.onnx_sha256[:12]}..., and this card declares "
                f"{str(card['onnx_sha256'])[:12]}.... Detections already point at the "
                "old one. Bump the version rather than re-pointing this row."
            )
        existing.threshold = float(card["threshold"])
        existing.pr_auc = _optional_float(card.get("pr_auc"))
        _set_mode(session, existing, mode)
        return existing

    model = MLModel(
        name=name,
        tier=ModelTier(str(card["tier"])),
        version=version,
        onnx_sha256=str(card["onnx_sha256"]),
        threshold=float(card["threshold"]),
        mode=mode,
        pr_auc=_optional_float(card.get("pr_auc")),
        deployed_at=datetime.now(timezone.utc) if mode is ModelMode.active else None,
    )
    session.add(model)
    session.add(
        AuditLog(
            user_id=None,  # a deployment action; nobody is logged in
            action="model.registered",
            entity=f"{name}:{version}",
            details={"tier": str(card["tier"]), "mode": mode.value},
        )
    )
    return model


def _set_mode(session: Session, model: MLModel, mode: ModelMode) -> None:
    """Change mode only when it actually changes, and say so in the audit log."""
    if model.mode is mode:
        return
    was = model.mode
    model.mode = mode
    if mode is ModelMode.active and model.deployed_at is None:
        model.deployed_at = datetime.now(timezone.utc)
    session.add(
        AuditLog(
            user_id=None,
            action="model.mode_changed",
            entity=f"{model.name}:{model.version}",
            details={"from": was.value, "to": mode.value},
        )
    )


def _optional_float(value) -> float | None:
    return None if value is None else float(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Register a model card in ml_models")
    parser.add_argument("card", help="path to a model_card.json")
    parser.add_argument(
        "--mode",
        choices=[member.value for member in ModelMode],
        default=ModelMode.shadow.value,
        help="shadow observes without influencing a score; active is a promotion",
    )
    args = parser.parse_args(argv)

    try:
        card = load_card(args.card)
    except RegistrationError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2

    with get_sessionmaker()() as session:
        try:
            model = register(session, card, ModelMode(args.mode))
        except RegistrationError as exc:
            print(f"refused: {exc}", file=sys.stderr)
            return 2
        session.commit()
        print(
            f"tier {model.tier.value} {model.name}:{model.version} registered "
            f"as model_id {model.model_id} in {model.mode.value} mode"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
