"""record who proposed each response action

Two-person approval was enforced only by role permissions: no shipped role holds
both ``response:propose`` and ``approvals:decide``. A role is a row, though, and an
account edited to hold both could approve its own block. Recording the proposer lets
the gate refuse that by person rather than by role.

Nullable because actions proposed before this revision have no recorded proposer,
and inventing one would put a name on a decision nobody can vouch for. The rule
applies to every action proposed from here on.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

FOREIGN_KEY = "fk_response_actions_proposed_by_users"


def upgrade() -> None:
    op.add_column("response_actions", sa.Column("proposed_by", sa.Integer(), nullable=True))
    op.create_foreign_key(
        FOREIGN_KEY, "response_actions", "users", ["proposed_by"], ["user_id"]
    )


def downgrade() -> None:
    op.drop_constraint(FOREIGN_KEY, "response_actions", type_="foreignkey")
    op.drop_column("response_actions", "proposed_by")
