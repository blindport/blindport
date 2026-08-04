"""Alembic migration helpers for Blindport databases."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from importlib.resources import files

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection, Engine


class DatabaseRevisionError(RuntimeError):
    """The database is not at the migration revision required by this build."""


def _config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("blindport.migrations")))
    config.attributes["connection"] = connection
    return config


@contextmanager
def _migration_connection(engine: Engine) -> Iterator[Connection]:
    if engine.dialect.name != "sqlite":
        with engine.begin() as connection:
            yield connection
        return

    # sqlite3 does not start a transaction for DDL, so issue BEGIN ourselves
    # before Alembic can create or drop anything.
    with engine.connect() as connection:
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.rollback()
            raise
        else:
            connection.commit()


def upgrade_database(engine: Engine, revision: str = "head") -> None:
    """Upgrade a database to an Alembic revision."""
    with _migration_connection(engine) as connection:
        command.upgrade(_config(connection), revision)


def downgrade_database(engine: Engine, revision: str) -> None:
    """Downgrade a database to an Alembic revision."""
    with _migration_connection(engine) as connection:
        command.downgrade(_config(connection), revision)


def database_revisions(engine: Engine) -> tuple[str | None, str]:
    """Return the database's current revision and the package migration head."""
    with engine.connect() as connection:
        config = _config(connection)
        current = MigrationContext.configure(connection).get_current_revision()
        head = ScriptDirectory.from_config(config).get_current_head()
    if head is None:  # pragma: no cover - a packaged build always has a revision
        raise DatabaseRevisionError("the package contains no migration head")
    return current, head


def verify_database_current(engine: Engine) -> None:
    """Raise when the database has not been migrated to this package's head."""
    current, head = database_revisions(engine)
    if current != head:
        raise DatabaseRevisionError(
            f"database revision is {current or 'unversioned'}, expected migration head {head}"
        )
