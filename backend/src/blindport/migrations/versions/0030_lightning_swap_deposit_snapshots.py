"""Persist prepared Lightning Swap deposit instructions.

Revision ID: 0030
Revises: 0029
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0030"
down_revision: str | None = "0029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("payment", sa.Column("stablecoin_deposit_amount", sa.String(length=128)))
    op.add_column("payment", sa.Column("stablecoin_deposit_address", sa.String(length=512)))
    op.add_column("payment", sa.Column("stablecoin_deposit_network", sa.String(length=32)))
    op.add_column("payment", sa.Column("stablecoin_deposit_tag", sa.String(length=512)))
    op.add_column("payment", sa.Column("stablecoin_required_confirmations", sa.Integer()))


def downgrade() -> None:
    connection = op.get_bind()
    prepared_order_count = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM payment WHERE stablecoin_api_order_enabled "
            "OR stablecoin_order_id IS NOT NULL "
            "OR stablecoin_deposit_amount IS NOT NULL "
            "OR stablecoin_deposit_address IS NOT NULL "
            "OR stablecoin_deposit_network IS NOT NULL "
            "OR stablecoin_deposit_tag IS NOT NULL "
            "OR stablecoin_required_confirmations IS NOT NULL"
        )
    ).scalar_one()
    if prepared_order_count:
        raise RuntimeError("cannot downgrade while Lightning Swap API payments exist")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("stablecoin_required_confirmations")
        batch_op.drop_column("stablecoin_deposit_tag")
        batch_op.drop_column("stablecoin_deposit_network")
        batch_op.drop_column("stablecoin_deposit_address")
        batch_op.drop_column("stablecoin_deposit_amount")
