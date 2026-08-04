"""Add UDP Blindport Port transport and transport-aware socket leases.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE transport ADD VALUE IF NOT EXISTS 'UDP'")

    with op.batch_alter_table("subscription") as batch_op:
        batch_op.drop_constraint("uq_subscription_port_tuple", type_="unique")
        batch_op.create_unique_constraint(
            "uq_subscription_port_tuple",
            ["assigned_ip", "assigned_port", "transport"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    udp_rows = bind.execute(
        sa.text("SELECT COUNT(*) FROM subscription WHERE transport = 'UDP'")
    ).scalar_one()
    if udp_rows:
        raise RuntimeError("cannot downgrade while UDP subscriptions exist")

    with op.batch_alter_table("subscription") as batch_op:
        batch_op.drop_constraint("uq_subscription_port_tuple", type_="unique")
        batch_op.create_unique_constraint(
            "uq_subscription_port_tuple",
            ["assigned_ip", "assigned_port"],
        )

    if bind.dialect.name == "postgresql":
        op.execute("ALTER TYPE transport RENAME TO transport_with_udp")
        op.execute("CREATE TYPE transport AS ENUM ('TCP')")
        op.execute(
            "ALTER TABLE subscription ALTER COLUMN transport TYPE transport "
            "USING transport::text::transport"
        )
        op.execute("DROP TYPE transport_with_udp")
