"""Create the initial Blindport schema.

Revision ID: 0001
Revises: None
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("display_token", sa.String(), nullable=True),
        sa.Column("hashed_token", sa.String(), nullable=False),
        sa.Column("is_admin", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("nwc_uri", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_hashed_token", "user", ["hashed_token"], unique=True)

    op.create_table(
        "subscription",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column(
            "product",
            sa.Enum("ip", "port", "relay", name="producttype"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("PENDING", "ACTIVE", "EXPIRED", "CANCELLED", name="subscriptionstatus"),
            nullable=False,
        ),
        sa.Column("assigned_ip", sa.String(), nullable=True),
        sa.Column("assigned_port", sa.Integer(), nullable=True),
        sa.Column("transport", sa.Enum("TCP", name="transport"), nullable=False),
        sa.Column("domain", sa.String(), nullable=True),
        sa.Column("relay_pool_domain", sa.String(), nullable=True),
        sa.Column("domain_is_managed", sa.Boolean(), nullable=False),
        sa.Column("domain_verification_token", sa.String(), nullable=True),
        sa.Column("domain_verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_claim_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("domain_renewal_grace_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reservation_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reservation_payment_id", sa.Integer(), nullable=True),
        sa.Column("resource_quarantined_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("monthly_price_sats", sa.Integer(), nullable=False),
        sa.Column("current_period_start", sa.DateTime(timezone=True), nullable=True),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("auto_renew", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("assigned_ip", "assigned_port", name="uq_subscription_port_tuple"),
        sa.UniqueConstraint("domain"),
    )
    op.create_index(
        "uq_subscription_dedicated_ip",
        "subscription",
        ["assigned_ip"],
        unique=True,
        sqlite_where=sa.text("product = 'ip'"),
        postgresql_where=sa.text("product = 'ip'"),
    )
    op.create_index(
        "ix_subscription_reservation_payment_id",
        "subscription",
        ["reservation_payment_id"],
    )
    op.create_index("ix_subscription_user_id", "subscription", ["user_id"])

    op.create_table(
        "payment",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column(
            "method",
            sa.Enum("LIGHTNING", "CASHU", "NWC", name="paymentmethod"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.Enum("PENDING", "PROCESSING", "PAID", "EXPIRED", "FAILED", name="paymentstatus"),
            nullable=False,
        ),
        sa.Column("amount_sats", sa.Integer(), nullable=False),
        sa.Column("invoice", sa.String(), nullable=True),
        sa.Column("payment_hash", sa.String(), nullable=True),
        sa.Column("cashu_token", sa.String(), nullable=True),
        sa.Column("nwc_request_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_payment_payment_hash", "payment", ["payment_hash"])
    op.create_index("ix_payment_subscription_id", "payment", ["subscription_id"])
    op.create_index(
        "uq_payment_open_subscription",
        "payment",
        ["subscription_id"],
        unique=True,
        sqlite_where=sa.text("status IN ('PENDING', 'PROCESSING')"),
        postgresql_where=sa.text("status IN ('PENDING', 'PROCESSING')"),
    )


def downgrade() -> None:
    op.drop_table("payment")
    op.drop_table("subscription")
    op.drop_table("user")

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for name in (
            "paymentstatus",
            "paymentmethod",
            "transport",
            "subscriptionstatus",
            "producttype",
        ):
            postgresql.ENUM(name=name).drop(bind, checkfirst=True)
