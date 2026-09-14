"""Add encrypted NWC credentials and durable payment attempts.

Revision ID: 0010
Revises: 0009
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TRIGGER = "trg_user_legacy_nwc_uri_revoked"
_FUNCTION = "blindport_legacy_nwc_uri_revoked"


def _create_legacy_revocation_guard() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            f"""CREATE TRIGGER {_TRIGGER}
            AFTER INSERT ON "user" FOR EACH ROW WHEN NEW.nwc_uri IS NOT NULL
            BEGIN UPDATE "user" SET nwc_uri = NULL WHERE id = NEW.id; END"""
        )
        op.execute(
            f"""CREATE TRIGGER {_TRIGGER}_update
            AFTER UPDATE OF nwc_uri ON "user" FOR EACH ROW WHEN NEW.nwc_uri IS NOT NULL
            BEGIN UPDATE "user" SET nwc_uri = NULL WHERE id = NEW.id; END"""
        )
    elif bind.dialect.name == "postgresql":
        op.execute(
            f"""CREATE FUNCTION {_FUNCTION}() RETURNS trigger AS $$
            BEGIN NEW.nwc_uri := NULL; RETURN NEW; END;
            $$ LANGUAGE plpgsql"""
        )
        op.execute(
            f"""CREATE TRIGGER {_TRIGGER} BEFORE INSERT OR UPDATE OF nwc_uri ON "user"
            FOR EACH ROW EXECUTE FUNCTION {_FUNCTION}()"""
        )


def _drop_legacy_revocation_guard() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'DROP TRIGGER IF EXISTS {_TRIGGER} ON "user"')
        op.execute(f"DROP FUNCTION IF EXISTS {_FUNCTION}()")
    else:
        op.execute(f"DROP TRIGGER IF EXISTS {_TRIGGER}")
        op.execute(f"DROP TRIGGER IF EXISTS {_TRIGGER}_update")


def upgrade() -> None:
    op.execute('UPDATE "user" SET nwc_uri = NULL')
    op.add_column(
        "user", sa.Column("has_nwc", sa.Boolean(), nullable=False, server_default=sa.false())
    )
    op.add_column("user", sa.Column("nwc_ciphertext", sa.Text(), nullable=True))
    op.add_column("user", sa.Column("nwc_key_version", sa.String(length=32), nullable=True))
    op.add_column(
        "user", sa.Column("nwc_generation", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("user", sa.Column("nwc_capabilities", sa.String(), nullable=True))
    op.add_column(
        "user", sa.Column("nwc_last_validated_at", sa.DateTime(timezone=True), nullable=True)
    )
    _create_legacy_revocation_guard()

    columns = (
        sa.Column("nwc_state", sa.String(length=32), nullable=True),
        sa.Column("nwc_attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nwc_first_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_last_lookup_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_lease_token", sa.String(length=32), nullable=True),
        sa.Column("nwc_error_code", sa.String(length=64), nullable=True),
        sa.Column("nwc_preimage_hash", sa.String(length=64), nullable=True),
        sa.Column("nwc_fees_paid_msats", sa.Integer(), nullable=True),
        sa.Column("nwc_credential_generation", sa.Integer(), nullable=True),
    )
    for column in columns:
        op.add_column("payment", column)


def downgrade() -> None:
    for column in (
        "nwc_credential_generation",
        "nwc_fees_paid_msats",
        "nwc_preimage_hash",
        "nwc_error_code",
        "nwc_lease_token",
        "nwc_lease_until",
        "nwc_last_lookup_at",
        "nwc_next_attempt_at",
        "nwc_last_attempt_at",
        "nwc_first_attempt_at",
        "nwc_attempt_count",
        "nwc_state",
    ):
        op.drop_column("payment", column)
    _drop_legacy_revocation_guard()
    for column in (
        "nwc_last_validated_at",
        "nwc_capabilities",
        "nwc_generation",
        "nwc_key_version",
        "nwc_ciphertext",
        "has_nwc",
    ):
        op.drop_column("user", column)
