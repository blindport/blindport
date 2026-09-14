"""Add encrypted service announcement preferences and SMTP outbox.

Revision ID: 0018
Revises: 0017
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0018"
down_revision: str | None = "0017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "user",
        sa.Column("has_service_email", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("user", sa.Column("service_email_ciphertext", sa.Text(), nullable=True))
    op.add_column(
        "user", sa.Column("service_email_key_version", sa.String(length=32), nullable=True)
    )
    op.add_column(
        "user",
        sa.Column(
            "service_email_generation",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.create_table(
        "announcement",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum("draft", "queued", "completed", "cancelled", name="announcementstate"),
            nullable=False,
            server_default=sa.text("'draft'"),
        ),
        sa.Column("subject", sa.String(length=160), nullable=False),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column("author_marker", sa.String(length=100), nullable=False),
        sa.Column("recipient_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("recipient_count >= 0", name="ck_announcement_recipient_count"),
        sa.CheckConstraint("length(body) <= 10000", name="ck_announcement_body_length"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "announcementdelivery",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("announcement_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("recipient_generation", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum(
                "queued",
                "sending",
                "sent",
                "delivery_ambiguous",
                "cancelled",
                "failed",
                name="announcementdeliverystate",
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
            name="ck_announcementdelivery_attempt_count",
        ),
        sa.ForeignKeyConstraint(["announcement_id"], ["announcement.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "announcement_id", "user_id", name="uq_announcementdelivery_campaign_user"
        ),
    )
    op.create_index(
        "ix_announcementdelivery_announcement_id", "announcementdelivery", ["announcement_id"]
    )
    op.create_index("ix_announcementdelivery_user_id", "announcementdelivery", ["user_id"])
    op.create_index(
        "ix_announcementdelivery_due",
        "announcementdelivery",
        ["state", "next_attempt_at", "id"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index("ix_announcementdelivery_due", table_name="announcementdelivery")
    op.drop_index("ix_announcementdelivery_user_id", table_name="announcementdelivery")
    op.drop_index("ix_announcementdelivery_announcement_id", table_name="announcementdelivery")
    op.drop_table("announcementdelivery")
    op.drop_table("announcement")
    op.drop_column("user", "service_email_generation")
    op.drop_column("user", "service_email_key_version")
    op.drop_column("user", "service_email_ciphertext")
    op.drop_column("user", "has_service_email")
    if bind.dialect.name == "postgresql":
        postgresql.ENUM(name="announcementdeliverystate").drop(bind, checkfirst=False)
        postgresql.ENUM(name="announcementstate").drop(bind, checkfirst=False)
