"""Add immutable random public account identifiers.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TRIGGER = "trg_user_public_id_immutable"
_IMMUTABLE_FUNCTION = "blindport_user_public_id_immutable"


def _public_id_server_default(dialect_name: str) -> sa.TextClause:
    if dialect_name == "postgresql":
        return sa.text("gen_random_uuid()")
    if dialect_name == "sqlite":
        # SQLAlchemy's SQLite UUID storage is 32 lowercase hexadecimal characters.
        # Fix the version and variant nibbles while retaining 122 random bits.
        return sa.text(
            "(lower(hex(randomblob(6))) || '4' || "
            "substr(lower(hex(randomblob(2))), 2) || "
            "substr('89ab', abs(random()) % 4 + 1, 1) || "
            "substr(lower(hex(randomblob(2))), 2) || lower(hex(randomblob(6))))"
        )
    raise RuntimeError(f"public account IDs do not support database dialect {dialect_name!r}")


def _create_immutability_guard() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            f"""CREATE TRIGGER {_IMMUTABLE_TRIGGER}
            BEFORE UPDATE OF public_id ON "user"
            FOR EACH ROW
            WHEN NEW.public_id IS NOT OLD.public_id
            BEGIN
                SELECT RAISE(ABORT, 'user public_id is immutable');
            END"""
        )
    elif bind.dialect.name == "postgresql":
        op.execute(
            f"""CREATE FUNCTION {_IMMUTABLE_FUNCTION}() RETURNS trigger AS $$
            BEGIN
                IF NEW.public_id IS DISTINCT FROM OLD.public_id THEN
                    RAISE EXCEPTION 'user public_id is immutable';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql"""
        )
        op.execute(
            f"""CREATE TRIGGER {_IMMUTABLE_TRIGGER}
            BEFORE UPDATE OF public_id ON "user"
            FOR EACH ROW EXECUTE FUNCTION {_IMMUTABLE_FUNCTION}()"""
        )
    else:  # pragma: no cover - application startup rejects unsupported databases
        raise RuntimeError(
            f"public account IDs do not support database dialect {bind.dialect.name!r}"
        )


def _drop_immutability_guard() -> None:
    bind = op.get_bind()
    op.execute(
        f'DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER} ON "user"'
        if bind.dialect.name == "postgresql"
        else f"DROP TRIGGER IF EXISTS {_IMMUTABLE_TRIGGER}"
    )
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP FUNCTION IF EXISTS {_IMMUTABLE_FUNCTION}()")


def upgrade() -> None:
    op.add_column("user", sa.Column("public_id", sa.Uuid(), nullable=True))
    user = sa.table(
        "user",
        sa.column("id", sa.Integer()),
        sa.column("public_id", sa.Uuid()),
    )
    bind = op.get_bind()
    user_ids = bind.execute(sa.select(user.c.id)).scalars().all()
    public_ids = [uuid4() for _ in user_ids]
    if len(set(public_ids)) != len(public_ids):  # pragma: no cover - UUID collision is theoretical
        raise RuntimeError("generated duplicate public account IDs")
    for user_id, public_id in zip(user_ids, public_ids, strict=True):
        bind.execute(user.update().where(user.c.id == user_id).values(public_id=public_id))

    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column(
            "public_id",
            existing_type=sa.Uuid(),
            nullable=False,
            server_default=_public_id_server_default(bind.dialect.name),
        )
    op.create_index("ix_user_public_id", "user", ["public_id"], unique=True)
    _create_immutability_guard()


def downgrade() -> None:
    _drop_immutability_guard()
    op.drop_index("ix_user_public_id", table_name="user")
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("public_id")
