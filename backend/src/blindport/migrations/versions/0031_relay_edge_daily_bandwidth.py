"""Add privacy-minimized daily relay edge bandwidth aggregates.

Revision ID: 0031
Revises: 0030
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0031"
down_revision: str | None = "0030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "relayedgedailybandwidth",
        sa.Column("edge_id", sa.String(length=63), nullable=False),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("ingress_bytes", sa.BigInteger(), nullable=False),
        sa.Column("egress_bytes", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "ingress_bytes >= 0 AND egress_bytes >= 0",
            name="ck_relayedgedailybandwidth_bytes_nonnegative",
        ),
        sa.PrimaryKeyConstraint("edge_id", "day"),
    )
    # Cursors are retained only for the recent deduplication window, so they
    # are the only privacy-preserving source for upgrade-time edge totals.
    op.get_bind().execute(
        sa.text(
            "INSERT INTO relayedgedailybandwidth "
            "(edge_id, day, ingress_bytes, egress_bytes) "
            "SELECT edge_id, day, SUM(ingress_bytes), SUM(egress_bytes) "
            "FROM relaybandwidthcursor GROUP BY edge_id, day"
        )
    )


def downgrade() -> None:
    op.drop_table("relayedgedailybandwidth")
