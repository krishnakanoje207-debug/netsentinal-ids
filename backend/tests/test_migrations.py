"""The migration must build exactly what the models declare.

Alembic's offline mode renders a migration to SQL without connecting, so this runs
on a machine with no PostgreSQL. That makes the check cheap enough to keep, and it
catches the failure that would otherwise surface only on the VM: a model changed,
the migration was not regenerated, and the deployed schema is missing a column.
"""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config

from netsentinel_api.db.models import Base

BACKEND = Path(__file__).resolve().parents[1]


def _render(direction: str) -> str:
    """Render the migration as SQL, offline."""
    buffer = io.StringIO()
    # output_buffer, not stdout: offline SQL goes to the former, and a Config with
    # only stdout redirected yields an empty string.
    config = Config(str(BACKEND / "alembic.ini"), output_buffer=buffer)
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    if direction == "up":
        command.upgrade(config, "head", sql=True)
    else:
        command.downgrade(config, "0001:base", sql=True)
    return buffer.getvalue()


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _render("up")


@pytest.fixture(scope="module")
def downgrade_sql() -> str:
    return _render("down")


def test_upgrade_creates_every_model_table(upgrade_sql):
    for table in Base.metadata.tables:
        assert f"CREATE TABLE {table} " in upgrade_sql, f"{table} is not in the migration"


def test_upgrade_creates_every_model_column(upgrade_sql):
    """The drift this whole test module exists to catch."""
    for name, table in Base.metadata.tables.items():
        # Isolate one CREATE TABLE so a column name cannot be matched elsewhere.
        start = upgrade_sql.index(f"CREATE TABLE {name} ")
        body = upgrade_sql[start : upgrade_sql.index(");", start)]
        for column in table.c.keys():
            # A later revision adds a column to an existing table rather than
            # recreating it, so either form counts.
            added = f"ALTER TABLE {name} ADD COLUMN {column} " in upgrade_sql
            assert column in body or added, f"{name}.{column} is missing from the migration"


def test_upgrade_creates_every_index(upgrade_sql):
    for table in Base.metadata.tables.values():
        for index in table.indexes:
            assert index.name in upgrade_sql, f"index {index.name} is not in the migration"


def test_enum_check_constraints_survive_the_migration(upgrade_sql):
    # These come from Enum(create_constraint=True); a renderer that dropped them
    # would leave the value domains unenforced in the deployed database.
    assert "CHECK (status IN ('pending_approval'" in upgrade_sql
    assert "CHECK (severity IN ('info'" in upgrade_sql


def test_the_status_domain_ends_up_wide_enough_for_a_requested_rollback(upgrade_sql):
    """0001 creates the narrow domain; 0002 widens it. Head is what deploys."""
    assert (
        "CHECK (status IN ('pending_approval', 'approved', 'rejected', 'executed', "
        "'rollback_requested', 'rolled_back', 'failed'))"
    ) in upgrade_sql
    # The new value is longer than every old one, so the column has to grow with it.
    assert "ALTER COLUMN status TYPE VARCHAR(18)" in upgrade_sql


def test_actions_record_who_proposed_them(upgrade_sql):
    """0003: the gate refuses self-approval by person, so the person is stored."""
    assert "ALTER TABLE response_actions ADD COLUMN proposed_by INTEGER" in upgrade_sql
    assert "REFERENCES users (user_id)" in upgrade_sql.split("proposed_by INTEGER", 1)[1]

    buffer = io.StringIO()
    config = Config(str(BACKEND / "alembic.ini"), output_buffer=buffer)
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    command.downgrade(config, "0003:0002", sql=True)
    assert "ALTER TABLE response_actions DROP COLUMN proposed_by" in buffer.getvalue()


def test_new_alerts_are_announced_on_the_channel_the_api_listens_on(upgrade_sql):
    """0004: without the trigger the live feed connects and never pushes anything."""
    from netsentinel_api.notify import CHANNEL

    assert f"pg_notify('{CHANNEL}', NEW.alert_id::text)" in upgrade_sql
    assert "AFTER INSERT ON alerts FOR EACH ROW" in upgrade_sql

    buffer = io.StringIO()
    config = Config(str(BACKEND / "alembic.ini"), output_buffer=buffer)
    config.set_main_option("script_location", str(BACKEND / "alembic"))
    command.downgrade(config, "0004:0003", sql=True)
    assert "DROP TRIGGER IF EXISTS alerts_notify_created ON alerts" in buffer.getvalue()


def test_named_check_constraints_survive_the_migration(upgrade_sql):
    for name in (
        "ck_risk_score_range",
        "ck_onnx_sha256_length",
        "ck_executed_has_timestamp",
        "ck_cvss_range",
    ):
        assert name in upgrade_sql, f"{name} is not in the migration"


def test_postgres_types_survive_the_migration(upgrade_sql):
    assert "JSONB" in upgrade_sql
    assert "INET" in upgrade_sql


def test_downgrade_drops_every_table(downgrade_sql):
    for table in Base.metadata.tables:
        assert f"DROP TABLE {table}" in downgrade_sql, f"{table} would be left behind"


def test_tables_are_created_after_what_they_reference(upgrade_sql):
    """Foreign keys need their target to exist already."""
    order = {}
    for name in Base.metadata.tables:
        order[name] = upgrade_sql.index(f"CREATE TABLE {name} ")

    for name, table in Base.metadata.tables.items():
        for fk in table.foreign_keys:
            target = fk.column.table.name
            if target == name:
                continue  # self reference
            assert order[target] < order[name], (
                f"{name} references {target} but is created before it"
            )
