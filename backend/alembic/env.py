"""Alembic environment.

Offline mode matters here beyond the usual reasons: it renders the migration as
SQL without touching a database, which is how the test suite verifies the schema
on a machine with no PostgreSQL running.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import engine_from_config, pool

from netsentinel_api.config import database_url
from netsentinel_api.db.models import Base

config = context.config
config.set_main_option("sqlalchemy.url", database_url())

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
