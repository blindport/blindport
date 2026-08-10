"""Add latest per-edge subscription connection observations.

Revision ID: 0025
Revises: 0024
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025"
down_revision: str | None = "0024"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "relaysubscriptionconnection",
        sa.Column("edge_id", sa.String(length=63), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_connected_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("edge_id", "subscription_id"),
    )
    op.create_index(
        "ix_relaysubscriptionconnection_subscription_id",
        "relaysubscriptionconnection",
        ["subscription_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_relaysubscriptionconnection_subscription_id", table_name="relaysubscriptionconnection"
    )
    op.drop_table("relaysubscriptionconnection")
