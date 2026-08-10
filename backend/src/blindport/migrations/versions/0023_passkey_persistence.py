"""Add passkey credentials, WebAuthn challenges, and browser sessions.

Revision ID: 0023
Revises: 0022
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023"
down_revision: str | None = "0022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "passkeycredential",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        sa.Column("credential_public_key", sa.LargeBinary(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("transports_json", sa.Text(), nullable=False),
        sa.Column("device_type", sa.String(length=32), nullable=True),
        sa.Column("backed_up", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("sign_count >= 0", name="ck_passkeycredential_sign_count_nonnegative"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_passkeycredential_user_id", "passkeycredential", ["user_id"])
    op.create_index(
        "ix_passkeycredential_credential_id",
        "passkeycredential",
        ["credential_id"],
        unique=True,
    )

    op.create_table(
        "webauthnchallenge",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("challenge", sa.LargeBinary(), nullable=False),
        sa.Column("ceremony_type", sa.String(length=16), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("binding_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "ceremony_type IN ('registration', 'authentication')",
            name="ck_webauthnchallenge_ceremony_type",
        ),
        sa.CheckConstraint(
            "length(binding_hash) = 64",
            name="ck_webauthnchallenge_binding_hash_length",
        ),
        sa.CheckConstraint(
            "(ceremony_type = 'registration' AND user_id IS NOT NULL) "
            "OR (ceremony_type = 'authentication' AND user_id IS NULL)",
            name="ck_webauthnchallenge_ceremony_user",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_webauthnchallenge_user_id", "webauthnchallenge", ["user_id"])
    op.create_index("ix_webauthnchallenge_expires_at", "webauthnchallenge", ["expires_at"])

    op.create_table(
        "browsersession",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("auth_method", sa.String(length=16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(token_hash) = 64", name="ck_browsersession_token_hash_length"),
        sa.CheckConstraint(
            "length(csrf_token_hash) = 64", name="ck_browsersession_csrf_token_hash_length"
        ),
        sa.CheckConstraint(
            "auth_method IN ('token', 'passkey')",
            name="ck_browsersession_auth_method",
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_browsersession_user_id", "browsersession", ["user_id"])
    op.create_index("ix_browsersession_token_hash", "browsersession", ["token_hash"], unique=True)
    op.create_index("ix_browsersession_expires_at", "browsersession", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_browsersession_expires_at", table_name="browsersession")
    op.drop_index("ix_browsersession_token_hash", table_name="browsersession")
    op.drop_index("ix_browsersession_user_id", table_name="browsersession")
    op.drop_table("browsersession")
    op.drop_index("ix_webauthnchallenge_expires_at", table_name="webauthnchallenge")
    op.drop_index("ix_webauthnchallenge_user_id", table_name="webauthnchallenge")
    op.drop_table("webauthnchallenge")
    op.drop_index("ix_passkeycredential_credential_id", table_name="passkeycredential")
    op.drop_index("ix_passkeycredential_user_id", table_name="passkeycredential")
    op.drop_table("passkeycredential")
