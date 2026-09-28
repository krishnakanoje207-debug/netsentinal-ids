"""store the input feature values with each detection

A verdict was traceable to its model and its SHAP values but not to the inputs: the
row carried only ``flow_id``, and the values lived in ClickHouse ``network_flows``,
a different store with its own retention. Now the writer copies the contract feature
values it scored into the detection itself.

Nullable, because existing rows cannot be back-filled honestly. Joining them to
ClickHouse by ``flow_id`` would guess: a flow id is a 5-tuple, not unique over time,
and the flow may have aged out. A legacy row says "not recorded" rather than show
values that may not be the ones the model saw.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("detections", sa.Column("features", JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("detections", "features")
