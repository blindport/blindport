"""Add idempotent label-driven agent orders.

Revision ID: 0012
Revises: 0011
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0012"
down_revision: str | None = "0011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _enum(name: str, *values: str) -> sa.Enum:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.ENUM(*values, name=name, create_type=False)
    return sa.Enum(*values, name=name)


def upgrade() -> None:
    op.create_table(
        "agentorder",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("order_key", sa.String(length=63), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("product", _enum("producttype", "ip", "port", "relay"), nullable=False),
        sa.Column("billing_term", _enum("billingterm", "monthly", "yearly"), nullable=False),
        sa.Column("delivery", _enum("deliverymode", "FRAMED", "WIREGUARD"), nullable=False),
        sa.Column("transport", _enum("transport", "TCP", "UDP"), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("subscription_id"),
        sa.UniqueConstraint("user_id", "order_key", name="uq_agentorder_user_order_key"),
    )
    op.create_index("ix_agentorder_user_id", "agentorder", ["user_id"], unique=False)
    with op.batch_alter_table("payment") as batch_op:
        batch_op.add_column(sa.Column("agent_order_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_payment_agent_order_id_agentorder",
            "agentorder",
            ["agent_order_id"],
            ["id"],
        )
    op.create_index(
        "uq_payment_agent_order_id",
        "payment",
        ["agent_order_id"],
        unique=True,
        sqlite_where=sa.text("agent_order_id IS NOT NULL"),
        postgresql_where=sa.text("agent_order_id IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_payment_agent_order_id", table_name="payment")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_constraint(
            "fk_payment_agent_order_id_agentorder",
            type_="foreignkey",
        )
        batch_op.drop_column("agent_order_id")
    op.drop_index("ix_agentorder_user_id", table_name="agentorder")
    op.drop_table("agentorder")
