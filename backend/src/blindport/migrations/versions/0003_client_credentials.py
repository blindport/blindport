"""Add durable client certificate credentials.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "clientcredential",
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("instance_id", sa.String(length=36), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("client_cert_pem", sa.String(), nullable=False),
        sa.Column("serial", sa.String(length=40), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False),
        sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("renew_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("instance_id", name="uq_clientcredential_instance_id"),
    )


def downgrade() -> None:
    op.drop_table("clientcredential")
