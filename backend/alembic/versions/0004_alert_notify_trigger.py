"""announce each new alert with a NOTIFY

Alerts are written by other processes - the detection writer, the Suricata importer -
so the API never sees one arrive and its live feed had nothing to push. A trigger
covers every writer, present and future, without each one having to remember to
announce what it stored.

NOTIFY is transactional: the announcement goes out when the inserting transaction
commits, and not at all if it rolls back, so a dashboard never hears of an alert it
cannot then load. The payload is the id alone; the dashboard refetches the feed.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

#: Also read by netsentinel_api.notify, which LISTENs on it.
CHANNEL = "netsentinel_alerts"


def upgrade() -> None:
    op.execute(
        f"""
        CREATE FUNCTION notify_alert_created() RETURNS trigger AS $$
        BEGIN
            PERFORM pg_notify('{CHANNEL}', NEW.alert_id::text);
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        "CREATE TRIGGER alerts_notify_created AFTER INSERT ON alerts "
        "FOR EACH ROW EXECUTE FUNCTION notify_alert_created()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS alerts_notify_created ON alerts")
    op.execute("DROP FUNCTION IF EXISTS notify_alert_created()")
