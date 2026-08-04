"""Add encrypted reminder preferences and a generic delivery outbox.

Revision ID: 0011
Revises: 0010
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: str | None = "0010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("has_reminder_email", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("user", sa.Column("reminder_email_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "user", sa.Column("reminder_email_key_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "user",
        sa.Column("reminder_email_generation", sa.Integer(), nullable=False, server_default="0"),
    )
    _create_delivery_table("reminderdelivery")
    _create_delivery_indexes("reminderdelivery")


def _create_delivery_table(name: str) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recipient_generation", sa.Integer(), nullable=False),
        sa.Column("kind", sa.Enum("7_day", "1_day", name="reminderkind"), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "queued",
                "sending",
                "sent",
                "delivery_ambiguous",
                "cancelled",
                "failed",
                "expired",
                name="reminderdeliverystate",
            ),
            nullable=False,
            server_default=sa.text("'queued'"),
        ),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
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
            name="ck_reminderdelivery_attempt_count",
        ),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "subscription_id",
            "current_period_end",
            "kind",
            name="uq_reminderdelivery_subscription_period_kind",
        ),
    )


def _create_delivery_indexes(name: str) -> None:
    op.create_index("ix_reminderdelivery_subscription_id", name, ["subscription_id"], unique=False)
    op.create_index(
        "ix_reminderdelivery_due", name, ["state", "next_attempt_at", "id"], unique=False
    )


def downgrade() -> None:
    op.drop_index("ix_reminderdelivery_due", table_name="reminderdelivery")
    op.drop_index("ix_reminderdelivery_subscription_id", table_name="reminderdelivery")
    op.drop_table("reminderdelivery")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        sa.Enum(name="reminderdeliverystate").drop(bind, checkfirst=True)
        sa.Enum(name="reminderkind").drop(bind, checkfirst=True)
    op.drop_column("user", "reminder_email_generation")
    op.drop_column("user", "reminder_email_key_version")
    op.drop_column("user", "reminder_email_ciphertext")
    op.drop_column("user", "has_reminder_email")
