"""Alembic environment backed by the connection supplied by Blindport."""

from __future__ import annotations

from alembic import context
from sqlmodel import SQLModel

from blindport.core import models  # noqa: F401

target_metadata = SQLModel.metadata


def run_migrations() -> None:
    connection = context.config.attributes.get("connection")
    if connection is None:
        raise RuntimeError("Blindport migrations require a configured database connection")

    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        render_as_batch=connection.dialect.name == "sqlite",
    )
    with context.begin_transaction():
        context.run_migrations()


run_migrations()
