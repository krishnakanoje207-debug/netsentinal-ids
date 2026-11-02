"""Keep imported event identity and bounded source evidence.

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("alerts", sa.Column("source_event_id", sa.String(255), nullable=True))
    op.add_column("alerts", sa.Column("source_details", postgresql.JSONB(), nullable=True))
    op.create_unique_constraint("uq_alert_source_event", "alerts", ["source", "source_event_id"])


def downgrade() -> None:
    op.drop_constraint("uq_alert_source_event", "alerts", type_="unique")
    op.drop_column("alerts", "source_details")
    op.drop_column("alerts", "source_event_id")
