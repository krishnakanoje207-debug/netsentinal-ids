"""widen the action_status domain with rollback_requested

A rollback is now two facts rather than one: a human asks for an executed action to
be lifted, and the responder later lifts it. The state between the two needs a name,
because in it the ban is still in force - calling it ``rolled_back`` early would tell
the dashboard traffic is flowing while it is not.

The status column is VARCHAR plus a CHECK rather than a native PostgreSQL enum (see
``models._enum``), so widening it is this: drop the constraint, widen the column to
fit the longer value, recreate the constraint with the new list. No ALTER TYPE, and
nothing that has to run outside a transaction.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

#: The name SQLAlchemy gives the CHECK is the ``name`` passed to Enum(), not a
#: ck_-prefixed one. Confirmed by rendering 0001 offline rather than assumed.
CONSTRAINT = "action_status"

OLD_VALUES = ("pending_approval", "approved", "rejected", "executed",
              "rolled_back", "failed")
NEW_VALUES = ("pending_approval", "approved", "rejected", "executed",
              "rollback_requested", "rolled_back", "failed")


def _domain(values: tuple[str, ...]) -> str:
    return "status IN ({})".format(", ".join(f"'{value}'" for value in values))


def upgrade() -> None:
    op.drop_constraint(CONSTRAINT, "response_actions", type_="check")
    # 'rollback_requested' is eighteen characters and the column was sized for the
    # longest of the old values. Widening the CHECK alone would trade a constraint
    # violation for a string truncation.
    op.alter_column(
        "response_actions",
        "status",
        type_=sa.String(length=len(max(NEW_VALUES, key=len))),
        existing_type=sa.String(length=len(max(OLD_VALUES, key=len))),
        existing_nullable=False,
    )
    op.create_check_constraint(CONSTRAINT, "response_actions", _domain(NEW_VALUES))


def downgrade() -> None:
    # Deliberately not data-preserving. A row sitting in 'rollback_requested' has a
    # ban in force and a human waiting for it to be lifted; rewriting it to
    # 'executed' or to 'rolled_back' would make the database state something about
    # the network that is not true, and nobody would know it had happened. So the
    # constraint is recreated exactly as it was: PostgreSQL validates it against the
    # existing rows and this downgrade fails loudly if any are in the new state. The
    # operator then resolves them on purpose - let the responder finish the undo, or
    # decide by hand what actually happened at the enforcement point.
    op.drop_constraint(CONSTRAINT, "response_actions", type_="check")
    op.alter_column(
        "response_actions",
        "status",
        type_=sa.String(length=len(max(OLD_VALUES, key=len))),
        existing_type=sa.String(length=len(max(NEW_VALUES, key=len))),
        existing_nullable=False,
    )
    op.create_check_constraint(CONSTRAINT, "response_actions", _domain(OLD_VALUES))
