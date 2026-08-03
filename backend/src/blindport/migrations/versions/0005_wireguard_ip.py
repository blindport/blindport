"""Add routed Blindport IP delivery over WireGuard and peer enrollment.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    delivery = sa.Enum("FRAMED", "WIREGUARD", name="deliverymode")
    delivery.create(op.get_bind(), checkfirst=True)
    with op.batch_alter_table("subscription") as batch_op:
        batch_op.add_column(
            sa.Column("delivery", delivery, nullable=False, server_default="FRAMED")
        )
    with op.batch_alter_table("subscription") as batch_op:
        batch_op.alter_column("delivery", server_default=None)

    op.create_table(
        "wireguardpeer",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("instance_id", sa.String(length=36), nullable=False),
        sa.Column("public_key", sa.String(length=44), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("public_key"),
    )


def downgrade() -> None:
    bind = op.get_bind()
    routed_rows = bind.execute(
        sa.text("SELECT COUNT(*) FROM subscription WHERE delivery = 'WIREGUARD'")
    ).scalar_one()
    if routed_rows:
        raise RuntimeError("cannot downgrade while WireGuard subscriptions exist")

    op.drop_table("wireguardpeer")
    with op.batch_alter_table("subscription") as batch_op:
        batch_op.drop_column("delivery")
    if bind.dialect.name == "postgresql":
        sa.Enum(name="deliverymode").drop(bind, checkfirst=True)
