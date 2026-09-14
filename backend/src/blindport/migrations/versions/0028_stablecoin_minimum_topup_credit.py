"""Snapshot the configured stablecoin surcharge separately from floor top-ups.

Revision ID: 0028
Revises: 0027
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: str | None = "0027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "payment",
        sa.Column(
            "stablecoin_surcharge_sats",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )


def downgrade() -> None:
    connection = op.get_bind()
    bonus_count = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM payment "
            "WHERE UPPER(CAST(method AS VARCHAR)) = 'STABLECOIN_SWAP' AND "
            "((LOWER(CAST(billing_term AS VARCHAR)) = 'monthly' AND period_days <> 30) OR "
            "(LOWER(CAST(billing_term AS VARCHAR)) = 'yearly' AND period_days <> 365))"
        )
    ).scalar_one()
    if bonus_count:
        raise RuntimeError("cannot downgrade while stablecoin bonus-day payments exist")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("stablecoin_surcharge_sats")
