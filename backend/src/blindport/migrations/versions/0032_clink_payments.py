"""Add CLINK account credentials and payment attribution.

Revision ID: 0032
Revises: 0031
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0032"
down_revision: str | None = "0031"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_METHODS = ("LIGHTNING", "CASHU", "NWC", "STABLECOIN_SWAP")
_NEW_METHODS = (*_OLD_METHODS, "CLINK")


def _payment_method_enum(methods: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*methods, name="paymentmethod")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE paymentmethod ADD VALUE IF NOT EXISTS 'CLINK'")
    else:
        with op.batch_alter_table("payment") as batch_op:
            batch_op.alter_column(
                "method",
                existing_type=_payment_method_enum(_OLD_METHODS),
                type_=_payment_method_enum(_NEW_METHODS),
                existing_nullable=False,
            )

    op.add_column(
        "user",
        sa.Column("has_clink", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("user", sa.Column("clink_ciphertext", sa.Text()))
    op.add_column("user", sa.Column("clink_key_version", sa.String(length=32)))
    op.add_column(
        "user",
        sa.Column("clink_generation", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("user", sa.Column("clink_last_validated_at", sa.DateTime(timezone=True)))

    op.add_column("payment", sa.Column("clink_state", sa.String(length=32)))
    op.add_column(
        "payment",
        sa.Column("clink_attempt_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )
    op.add_column("payment", sa.Column("clink_attempted_at", sa.DateTime(timezone=True)))
    op.add_column("payment", sa.Column("clink_lease_until", sa.DateTime(timezone=True)))
    op.add_column("payment", sa.Column("clink_lease_token", sa.String(length=32)))
    op.add_column("payment", sa.Column("clink_error_code", sa.String(length=64)))
    op.add_column("payment", sa.Column("clink_preimage_hash", sa.String(length=64)))
    op.add_column("payment", sa.Column("clink_credential_generation", sa.Integer()))
    op.add_column(
        "payment",
        sa.Column("clink_nwc_fallback", sa.Boolean(), server_default=sa.false(), nullable=False),
    )


def downgrade() -> None:
    bind = op.get_bind()
    clink_credentials = bind.execute(
        sa.text(
            'SELECT COUNT(*) FROM "user" '
            "WHERE has_clink = :connected OR clink_ciphertext IS NOT NULL "
            "OR clink_key_version IS NOT NULL"
        ),
        {"connected": True},
    ).scalar_one()
    if clink_credentials:
        raise RuntimeError("cannot downgrade while CLINK credentials exist")
    clink_rows = bind.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE method = :method"),
        {"method": "CLINK"},
    ).scalar_one()
    if clink_rows:
        raise RuntimeError("cannot downgrade while CLINK payments exist")

    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("clink_nwc_fallback")
        batch_op.drop_column("clink_credential_generation")
        batch_op.drop_column("clink_preimage_hash")
        batch_op.drop_column("clink_error_code")
        batch_op.drop_column("clink_lease_token")
        batch_op.drop_column("clink_lease_until")
        batch_op.drop_column("clink_attempted_at")
        batch_op.drop_column("clink_attempt_count")
        batch_op.drop_column("clink_state")
        if bind.dialect.name != "postgresql":
            batch_op.alter_column(
                "method",
                existing_type=_payment_method_enum(_NEW_METHODS),
                type_=_payment_method_enum(_OLD_METHODS),
                existing_nullable=False,
            )
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("clink_last_validated_at")
        batch_op.drop_column("clink_generation")
        batch_op.drop_column("clink_key_version")
        batch_op.drop_column("clink_ciphertext")
        batch_op.drop_column("has_clink")

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE payment ALTER COLUMN method TYPE VARCHAR(32) USING method::text")
        postgresql.ENUM(name="paymentmethod").drop(bind, checkfirst=False)
        postgresql.ENUM(*_OLD_METHODS, name="paymentmethod").create(bind, checkfirst=False)
        op.execute(
            "ALTER TABLE payment ALTER COLUMN method TYPE paymentmethod USING method::paymentmethod"
        )
