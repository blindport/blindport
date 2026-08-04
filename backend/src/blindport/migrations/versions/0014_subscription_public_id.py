"""Add immutable random public subscription identifiers.

Revision ID: 0014
Revises: 0013
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "0014"
down_revision: str | None = "0013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TRIGGER = "trg_subscription_public_id_immutable"
_IMMUTABLE_FUNCTION = "blindport_subscription_public_id_immutable"


def _server_default(dialect_name: str) -> sa.TextClause:
    if dialect_name == "postgresql":
        return sa.text("gen_random_uuid()")
    if dialect_name == "sqlite":
        return sa.text(
            "(lower(hex(randomblob(6))) || '4' || "
            "substr(lower(hex(randomblob(2))), 2) || "
            "substr('89ab', (random() & 3) + 1, 1) || "
            "substr(lower(hex(randomblob(2))), 2) || lower(hex(randomblob(6))))"
        )
    raise RuntimeError(f"subscription public IDs do not support {dialect_name!r}")


def _create_immutability_guard(dialect_name: str) -> None:
    if dialect_name == "sqlite":
        op.execute(f"DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER}")
        op.execute(
            f"""CREATE TRIGGER {_IMMUTABLE_TRIGGER}
            BEFORE UPDATE OF public_id ON subscription
            FOR EACH ROW
            WHEN NEW.public_id IS NOT OLD.public_id
            BEGIN
                SELECT RAISE(ABORT, 'subscription public_id is immutable');
            END"""
        )
        return
    if dialect_name == "postgresql":
        op.execute(f"DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER} ON subscription")
        op.execute(f"DROP FUNCTION IF EXISTS {_IMMUTABLE_FUNCTION}()")
        op.execute(
            f"""CREATE FUNCTION {_IMMUTABLE_FUNCTION}() RETURNS trigger AS $$
            BEGIN
                IF NEW.public_id IS DISTINCT FROM OLD.public_id THEN
                    RAISE EXCEPTION 'subscription public_id is immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql"""
        )
        op.execute(
            f"""CREATE TRIGGER {_IMMUTABLE_TRIGGER}
            BEFORE UPDATE OF public_id ON subscription
            FOR EACH ROW EXECUTE FUNCTION {_IMMUTABLE_FUNCTION}()"""
        )
        return
    raise RuntimeError(f"subscription public IDs do not support {dialect_name!r}")


def _drop_immutability_guard(dialect_name: str) -> None:
    op.execute(
        f"DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER} ON subscription"
        if dialect_name == "postgresql"
        else f"DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER}"
    )
    if dialect_name == "postgresql":
        op.execute(f"DROP FUNCTION IF EXISTS {_IMMUTABLE_FUNCTION}()")


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    inspector = sa.inspect(bind)
    columns = {column["name"] for column in inspector.get_columns("subscription")}
    index_names = {index["name"] for index in inspector.get_indexes("subscription")}

    column_added = "public_id" not in columns
    if column_added:
        # SQLite cannot add a column with a non-constant expression default.
        # Its migration transaction holds an immediate write lock until the
        # batch rebuild installs the default. On PostgreSQL, setting the
        # volatile default after ADD COLUMN avoids rewriting existing rows.
        op.add_column(
            "subscription",
            sa.Column(
                "public_id",
                sa.Uuid(),
                nullable=True,
            ),
        )
        if dialect_name == "postgresql":
            op.alter_column(
                "subscription",
                "public_id",
                existing_type=sa.Uuid(),
                nullable=True,
                server_default=_server_default(dialect_name),
            )

    subscription = sa.table(
        "subscription",
        sa.column("id", sa.Integer()),
        sa.column("public_id", sa.Uuid()),
    )
    missing_ids = (
        bind.execute(sa.select(subscription.c.id).where(subscription.c.public_id.is_(None)))
        .scalars()
        .all()
    )
    generated_ids = [uuid4() for _ in missing_ids]
    if len(set(generated_ids)) != len(generated_ids):  # pragma: no cover
        raise RuntimeError("generated duplicate public subscription IDs")
    for subscription_pk, public_id in zip(missing_ids, generated_ids, strict=True):
        bind.execute(
            subscription.update()
            .where(subscription.c.id == subscription_pk)
            .values(public_id=public_id)
        )

    if column_added:
        with op.batch_alter_table("subscription") as batch_op:
            batch_op.alter_column(
                "public_id",
                existing_type=sa.Uuid(),
                nullable=False,
                server_default=_server_default(dialect_name),
            )
    if "ix_subscription_public_id" not in index_names:
        op.create_index(
            "ix_subscription_public_id",
            "subscription",
            ["public_id"],
            unique=True,
        )
    _create_immutability_guard(dialect_name)


def downgrade() -> None:
    # Keep the additive identity column and index. Rewritten revision 0001 owns
    # them on clean installs, and dropping published identities is never safe.
    _drop_immutability_guard(op.get_bind().dialect.name)
