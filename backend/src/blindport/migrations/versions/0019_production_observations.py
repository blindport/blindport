"""Add latest relay heartbeat and DNS supervision observations.

Revision ID: 0019
Revises: 0018
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019"
down_revision: str | None = "0018"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "relayheartbeat",
        sa.Column("edge_id", sa.String(length=63), nullable=False),
        sa.Column("ready", sa.Boolean(), nullable=False),
        sa.Column("authorization", sa.String(length=16), nullable=False),
        sa.Column("certificate", sa.String(length=16), nullable=False),
        sa.Column("lifecycle", sa.String(length=16), nullable=False),
        sa.Column("listeners", sa.String(length=16), nullable=False),
        sa.Column("wireguard", sa.String(length=16), nullable=False),
        sa.Column("active_tunnels", sa.BigInteger(), nullable=False),
        sa.Column("active_streams", sa.BigInteger(), nullable=False),
        sa.Column("accepted_connections_total", sa.BigInteger(), nullable=False),
        sa.Column("forwarded_bytes_total", sa.BigInteger(), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "active_tunnels >= 0 AND active_streams >= 0 AND "
            "accepted_connections_total >= 0 AND forwarded_bytes_total >= 0",
            name="ck_relayheartbeat_counters_nonnegative",
        ),
        sa.PrimaryKeyConstraint("edge_id"),
    )
    op.create_index("ix_relayheartbeat_received_at", "relayheartbeat", ["received_at"])
    op.create_table(
        "dnsobservation",
        sa.Column("hostname", sa.String(length=253), nullable=False),
        sa.Column("expected_ips", sa.Text(), nullable=False),
        sa.Column("observed_ips", sa.Text(), nullable=False),
        sa.Column("healthy", sa.Boolean(), nullable=False),
        sa.Column("resolver_count", sa.Integer(), nullable=False),
        sa.Column("successful_resolvers", sa.Integer(), nullable=False),
        sa.Column("error_code", sa.String(length=32), nullable=True),
        sa.Column("checked_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "resolver_count >= 0 AND successful_resolvers >= 0 AND "
            "successful_resolvers <= resolver_count",
            name="ck_dnsobservation_resolver_counts_nonnegative",
        ),
        sa.PrimaryKeyConstraint("hostname"),
    )
    op.create_index("ix_dnsobservation_checked_at", "dnsobservation", ["checked_at"])


def downgrade() -> None:
    op.drop_index("ix_dnsobservation_checked_at", table_name="dnsobservation")
    op.drop_table("dnsobservation")
    op.drop_index("ix_relayheartbeat_received_at", table_name="relayheartbeat")
    op.drop_table("relayheartbeat")
