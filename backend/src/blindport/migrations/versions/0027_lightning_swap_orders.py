"""Persist encrypted Lightning Swap order access.

Revision ID: 0027
Revises: 0026
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0027"
down_revision: str | None = "0026"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "payment",
        sa.Column(
            "stablecoin_api_order_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column("payment", sa.Column("stablecoin_order_id", sa.String(length=32)))
    op.add_column("payment", sa.Column("stablecoin_order_token_ciphertext", sa.String(length=8192)))
    op.add_column("payment", sa.Column("stablecoin_order_token_key_version", sa.String(length=32)))
    op.add_column("payment", sa.Column("stablecoin_order_status", sa.String(length=32)))
    op.add_column("payment", sa.Column("stablecoin_order_expires_at", sa.DateTime(timezone=True)))


def downgrade() -> None:
    connection = op.get_bind()
    api_payment_count = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM payment "
            "WHERE stablecoin_api_order_enabled OR stablecoin_order_id IS NOT NULL"
        )
    ).scalar_one()
    if api_payment_count:
        raise RuntimeError("cannot downgrade while Lightning Swap API payments exist")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("stablecoin_order_expires_at")
        batch_op.drop_column("stablecoin_order_status")
        batch_op.drop_column("stablecoin_order_token_key_version")
        batch_op.drop_column("stablecoin_order_token_ciphertext")
        batch_op.drop_column("stablecoin_order_id")
        batch_op.drop_column("stablecoin_api_order_enabled")
