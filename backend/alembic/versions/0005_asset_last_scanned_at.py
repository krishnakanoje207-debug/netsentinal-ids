"""record when each host was last covered by a vulnerability scan

Without it, a host with no rows in ``vulnerabilities`` is either clean or was never
scanned, and nothing in the database says which. The Greenbone report lists every
host it scanned, including the ones it found nothing on, so the import can stamp
each of them.

Nullable, with no default: a host that has not been scanned has no scan time, and
backfilling one would make every existing host look covered.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("last_scanned_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("assets", "last_scanned_at")
