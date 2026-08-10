"""Add one consented recipient for all notification categories.

Revision ID: 0024
Revises: 0023
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0024"
down_revision: str | None = "0023"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column(
            "has_notification_email", sa.Boolean(), server_default=sa.false(), nullable=False
        ),
    )
    op.add_column("user", sa.Column("notification_email_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "user", sa.Column("notification_email_key_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "user",
        sa.Column(
            "notification_email_generation", sa.Integer(), server_default="0", nullable=False
        ),
    )
    now = sa.text("CURRENT_TIMESTAMP")
    for table_name in ("notificationdelivery", "reminderdelivery", "announcementdelivery"):
        delivery = sa.table(
            table_name,
            sa.column("state"),
            sa.column("error_code"),
            sa.column("updated_at"),
            sa.column("terminal_at"),
            sa.column("next_attempt_at"),
            sa.column("lease_token"),
            sa.column("lease_until"),
        )
        op.execute(
            sa.update(delivery)
            .where(delivery.c.state == sa.literal_column("'queued'"))
            .values(
                state=sa.literal_column("'cancelled'"),
                error_code="notification_preference_cutover",
                updated_at=now,
                terminal_at=now,
                next_attempt_at=None,
                lease_token=None,
                lease_until=None,
            )
        )
    op.drop_column("user", "service_email_generation")
    op.drop_column("user", "service_email_key_version")
    op.drop_column("user", "service_email_ciphertext")
    op.drop_column("user", "has_service_email")
    op.drop_column("user", "reminder_email_generation")
    op.drop_column("user", "reminder_email_key_version")
    op.drop_column("user", "reminder_email_ciphertext")
    op.drop_column("user", "has_reminder_email")


def downgrade() -> None:
    op.add_column(
        "user",
        sa.Column("has_reminder_email", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("user", sa.Column("reminder_email_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "user", sa.Column("reminder_email_key_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "user",
        sa.Column("reminder_email_generation", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "user",
        sa.Column("has_service_email", sa.Boolean(), server_default=sa.false(), nullable=False),
    )
    op.add_column("user", sa.Column("service_email_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "user", sa.Column("service_email_key_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "user",
        sa.Column("service_email_generation", sa.Integer(), server_default="0", nullable=False),
    )
    op.drop_column("user", "notification_email_generation")
    op.drop_column("user", "notification_email_key_version")
    op.drop_column("user", "notification_email_ciphertext")
    op.drop_column("user", "has_notification_email")
