"""Add the privacy-preserving unified notification delivery outbox.

Revision ID: 0022
Revises: 0021
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022"
down_revision: str | None = "0021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "announcement",
        sa.Column("recipient_cursor", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column("announcement", sa.Column("recipient_max_user_id", sa.Integer(), nullable=True))
    op.add_column(
        "announcement",
        sa.Column("expansion_complete", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    # Campaigns created by the legacy implementation already own their recipient
    # rows. Only campaigns queued by the new implementation are expanded here.
    op.execute("UPDATE announcement SET expansion_complete = true")
    op.create_table(
        "announcementrecipientsnapshot",
        sa.Column("announcement_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("recipient_generation", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["announcement_id"], ["announcement.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("announcement_id", "user_id"),
    )
    category = sa.Enum("account", "service", name="notificationcategory")
    kind = sa.Enum(
        "expiration_7_day",
        "expiration_1_day",
        "subscription_activated",
        "subscription_renewed",
        "subscription_expired",
        "service_announcement",
        name="notificationkind",
    )
    state = sa.Enum(
        "queued",
        "sending",
        "sent",
        "delivery_ambiguous",
        "cancelled",
        "failed",
        "expired",
        name="notificationdeliverystate",
    )
    op.create_table(
        "notificationdelivery",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=True),
        sa.Column("payment_id", sa.Integer(), nullable=True),
        sa.Column("announcement_id", sa.Integer(), nullable=True),
        sa.Column("category", category, nullable=False),
        sa.Column("kind", kind, nullable=False),
        sa.Column("idempotency_key", sa.String(length=255), nullable=False),
        sa.Column("recipient_generation", sa.Integer(), nullable=False),
        sa.Column("event_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", state, server_default="queued", nullable=False),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("terminal_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("lease_token", sa.String(length=32), nullable=True),
        sa.Column("lease_until", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 20",
            name="ck_notificationdelivery_attempt_count",
        ),
        sa.ForeignKeyConstraint(["announcement_id"], ["announcement.id"]),
        sa.ForeignKeyConstraint(["payment_id"], ["payment.id"]),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    op.create_index("ix_notificationdelivery_user_id", "notificationdelivery", ["user_id"])
    op.create_index(
        "ix_notificationdelivery_subscription_id", "notificationdelivery", ["subscription_id"]
    )
    op.create_index("ix_notificationdelivery_payment_id", "notificationdelivery", ["payment_id"])
    op.create_index(
        "ix_notificationdelivery_announcement_id", "notificationdelivery", ["announcement_id"]
    )
    op.create_index(
        "ix_notificationdelivery_due", "notificationdelivery", ["state", "next_attempt_at", "id"]
    )
    op.create_index(
        "ix_notificationdelivery_announcement_state",
        "notificationdelivery",
        ["announcement_id", "state"],
    )


def downgrade() -> None:
    op.drop_index("ix_notificationdelivery_announcement_state", table_name="notificationdelivery")
    op.drop_index("ix_notificationdelivery_due", table_name="notificationdelivery")
    op.drop_index("ix_notificationdelivery_announcement_id", table_name="notificationdelivery")
    op.drop_index("ix_notificationdelivery_payment_id", table_name="notificationdelivery")
    op.drop_index("ix_notificationdelivery_subscription_id", table_name="notificationdelivery")
    op.drop_index("ix_notificationdelivery_user_id", table_name="notificationdelivery")
    op.drop_table("notificationdelivery")
    op.drop_table("announcementrecipientsnapshot")
    op.drop_column("announcement", "expansion_complete")
    op.drop_column("announcement", "recipient_max_user_id")
    op.drop_column("announcement", "recipient_cursor")
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP TYPE IF EXISTS notificationdeliverystate")
        op.execute("DROP TYPE IF EXISTS notificationkind")
        op.execute("DROP TYPE IF EXISTS notificationcategory")
