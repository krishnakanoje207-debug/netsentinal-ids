"""link an ML alert to the signature alert that corroborated it

FR-10 asks for the models, the signatures and the intelligence to be fused into one
verdict. Intelligence already raises an alert's severity; a signature firing between
the same two addresses at the same time now does too, and this column says which
signature alert did it. It is also what makes the raise happen once: an alert that
has a corroborating signature is not raised again by the next one.

Nullable, with no back-fill: an alert stored before this has not been compared, and
``SET NULL`` on delete because losing the signature row must not delete the alert.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column(
            "corroborated_by_alert_id",
            sa.Integer(),
            sa.ForeignKey("alerts.alert_id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("alerts", "corroborated_by_alert_id")
