"""Add durable public request rate-limit buckets.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ratelimitbucket",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(length=64), nullable=False),
        sa.Column("identifier_hash", sa.String(length=64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scope",
            "identifier_hash",
            "window_start",
            name="uq_ratelimitbucket_scope_identifier_window",
        ),
    )
    op.create_index(
        "ix_ratelimitbucket_expires_at_id",
        "ratelimitbucket",
        ["expires_at", "id"],
        unique=False,
    )
    op.create_table(
        "ratelimitmaintenance",
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("next_cleanup_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("bucket_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("ratelimitmaintenance")
    op.drop_index("ix_ratelimitbucket_expires_at_id", table_name="ratelimitbucket")
    op.drop_table("ratelimitbucket")
