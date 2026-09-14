"""Add privacy-preserving daily subscription bandwidth aggregates.

Revision ID: 0021
Revises: 0020
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0021"
down_revision: str | None = "0020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "subscriptiondailybandwidth",
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("ingress_bytes", sa.BigInteger(), nullable=False),
        sa.Column("egress_bytes", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "ingress_bytes >= 0 AND egress_bytes >= 0",
            name="ck_subscriptiondailybandwidth_bytes_nonnegative",
        ),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("subscription_id", "day"),
    )
    op.create_table(
        "relaybandwidthcursor",
        sa.Column("edge_id", sa.String(length=63), nullable=False),
        sa.Column("boot_id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("sequence", sa.BigInteger(), nullable=False),
        sa.Column("ingress_bytes", sa.BigInteger(), nullable=False),
        sa.Column("egress_bytes", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("sequence >= 0", name="ck_relaybandwidthcursor_sequence_nonnegative"),
        sa.CheckConstraint(
            "ingress_bytes >= 0 AND egress_bytes >= 0",
            name="ck_relaybandwidthcursor_bytes_nonnegative",
        ),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("edge_id", "boot_id", "subscription_id", "day"),
    )


def downgrade() -> None:
    op.drop_table("relaybandwidthcursor")
    op.drop_table("subscriptiondailybandwidth")
