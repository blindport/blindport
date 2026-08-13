"""Add LND-backed stablecoin swap payments.

Revision ID: 0016
Revises: 0015
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0016"
down_revision: str | None = "0015"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_METHODS = ("LIGHTNING", "CASHU", "NWC")
_NEW_METHODS = (*_OLD_METHODS, "STABLECOIN_SWAP")


def _payment_method_enum(methods: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*methods, name="paymentmethod")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE paymentmethod ADD VALUE IF NOT EXISTS 'STABLECOIN_SWAP'")
    else:
        with op.batch_alter_table("payment") as batch_op:
            batch_op.alter_column(
                "method",
                existing_type=_payment_method_enum(_OLD_METHODS),
                type_=_payment_method_enum(_NEW_METHODS),
                existing_nullable=False,
            )
    op.add_column(
        "payment",
        sa.Column("markup_sats", sa.Integer(), server_default=sa.text("0"), nullable=False),
    )


def downgrade() -> None:
    bind = op.get_bind()
    stablecoin_rows = bind.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE method = :method"),
        {"method": "STABLECOIN_SWAP"},
    ).scalar_one()
    if stablecoin_rows:
        raise RuntimeError("cannot downgrade while stablecoin swap payments exist")

    op.drop_column("payment", "markup_sats")
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TABLE payment ALTER COLUMN method TYPE VARCHAR(32) USING method::text")
        postgresql.ENUM(name="paymentmethod").drop(bind, checkfirst=False)
        postgresql.ENUM(*_OLD_METHODS, name="paymentmethod").create(bind, checkfirst=False)
        op.execute(
            "ALTER TABLE payment ALTER COLUMN method TYPE paymentmethod USING method::paymentmethod"
        )
    else:
        with op.batch_alter_table("payment") as batch_op:
            batch_op.alter_column(
                "method",
                existing_type=_payment_method_enum(_NEW_METHODS),
                type_=_payment_method_enum(_OLD_METHODS),
                existing_nullable=False,
            )
