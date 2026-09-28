"""let an administrator revoke a sensor

A flag rather than a new ``status`` value: status says whether the sensor is up, and
this says whether it is trusted. A revoked sensor that is still running is exactly
the case an administrator needs to see both of.

NOT NULL with a server default of false, so every existing sensor stays trusted.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sensors",
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("sensors", "revoked")
