"""Snapshot stablecoin checkout provider details on payments.

Revision ID: 0026
Revises: 0025
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0026"
down_revision: str | None = "0025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("payment", sa.Column("stablecoin_provider", sa.String(length=32), nullable=True))
    op.add_column(
        "payment", sa.Column("stablecoin_checkout_origin", sa.String(length=2048), nullable=True)
    )
    op.add_column("payment", sa.Column("stablecoin_asset", sa.String(length=64), nullable=True))
    op.execute(
        sa.text(
            "UPDATE payment SET stablecoin_provider = :provider "
            "WHERE CAST(method AS VARCHAR) = :method"
        ).bindparams(
            provider="boltz",
            method="STABLECOIN_SWAP",
        )
    )


def downgrade() -> None:
    connection = op.get_bind()
    stablecoin_payment_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE CAST(method AS VARCHAR) = :method").bindparams(
            method="STABLECOIN_SWAP"
        )
    ).scalar_one()
    if stablecoin_payment_count:
        raise RuntimeError("cannot downgrade while stablecoin swap payments exist")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("stablecoin_asset")
        batch_op.drop_column("stablecoin_checkout_origin")
        batch_op.drop_column("stablecoin_provider")
