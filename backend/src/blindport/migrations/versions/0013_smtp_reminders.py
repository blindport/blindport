"""Replace the deployed paid-email outbox with generic SMTP state.

Revision ID: 0013
Revises: 0012
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0013"
down_revision: str | None = "0012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LEGACY_MARKERS = {"payment_hash", "provider_delivery_status", "invoice_ciphertext"}


def upgrade() -> None:
    bind = op.get_bind()
    op.execute(sa.text('UPDATE "user" SET is_suspended = TRUE WHERE is_admin = TRUE'))
    columns = {column["name"] for column in sa.inspect(bind).get_columns("reminderdelivery")}
    if not columns & _LEGACY_MARKERS:
        return
    if bind.dialect.name == "postgresql":
        _prepare_postgresql_names()
    else:
        op.drop_index("uq_reminderdelivery_payment_hash", table_name="reminderdelivery")
        op.drop_index("ix_reminderdelivery_due", table_name="reminderdelivery")
        op.drop_index("ix_reminderdelivery_subscription_id", table_name="reminderdelivery")

    _create_generic_table(bind.dialect.name)
    state_expression = _mapped_state_expression(bind.dialect.name)
    op.execute(
        sa.text(
            f"""
            INSERT INTO reminderdelivery_smtp (
                id, subscription_id, current_period_end, recipient_generation, kind, state,
                attempt_count, error_code, created_at, updated_at, last_attempt_at,
                next_attempt_at, sent_at, terminal_at, lease_token, lease_until
            )
            SELECT
                id, subscription_id, current_period_end, recipient_generation, kind,
                {state_expression}, attempt_count,
                CASE
                    WHEN CAST(state AS VARCHAR) = 'delivered' THEN NULL
                    WHEN CAST(state AS VARCHAR) IN ('cancelled', 'failed', 'expired') THEN error_code
                    WHEN CAST(state AS VARCHAR) = 'invoice_creation_ambiguous' THEN
                        COALESCE(error_code, 'legacy_delivery_ambiguous')
                    ELSE 'legacy_delivery_cancelled'
                END,
                created_at, updated_at, last_attempt_at, NULL, delivered_at,
                COALESCE(terminal_at, updated_at, created_at), NULL, NULL
            FROM reminderdelivery
            """
        )
    )
    op.drop_table("reminderdelivery")
    op.rename_table("reminderdelivery_smtp", "reminderdelivery")
    op.create_index(
        "ix_reminderdelivery_subscription_id",
        "reminderdelivery",
        ["subscription_id"],
        unique=False,
    )
    op.create_index(
        "ix_reminderdelivery_due",
        "reminderdelivery",
        ["state", "next_attempt_at", "id"],
        unique=False,
    )
    if bind.dialect.name == "postgresql":
        op.execute("DROP TYPE reminderdeliverystate_legacy")
        op.execute(
            "SELECT setval(pg_get_serial_sequence('reminderdelivery', 'id'), "
            "COALESCE((SELECT MAX(id) FROM reminderdelivery), 1), "
            "EXISTS (SELECT 1 FROM reminderdelivery))"
        )


def _prepare_postgresql_names() -> None:
    op.drop_index("uq_reminderdelivery_payment_hash", table_name="reminderdelivery")
    op.drop_index("ix_reminderdelivery_due", table_name="reminderdelivery")
    op.drop_index("ix_reminderdelivery_subscription_id", table_name="reminderdelivery")
    op.execute(
        "ALTER TABLE reminderdelivery RENAME CONSTRAINT "
        "uq_reminderdelivery_subscription_period_kind TO "
        "uq_reminderdelivery_subscription_period_kind_legacy"
    )
    op.execute(
        "ALTER TABLE reminderdelivery RENAME CONSTRAINT "
        "ck_reminderdelivery_attempt_count TO ck_reminderdelivery_attempt_count_legacy"
    )
    op.execute("ALTER TYPE reminderdeliverystate RENAME TO reminderdeliverystate_legacy")


def _create_generic_table(dialect_name: str) -> None:
    if dialect_name == "postgresql":
        state_type = postgresql.ENUM(
            "queued",
            "sending",
            "sent",
            "delivery_ambiguous",
            "cancelled",
            "failed",
            "expired",
            name="reminderdeliverystate",
        )
        state_type.create(op.get_bind(), checkfirst=False)
        state_column_type = postgresql.ENUM(name="reminderdeliverystate", create_type=False)
        kind_type = postgresql.ENUM(name="reminderkind", create_type=False)
    else:
        state_column_type = sa.Enum(
            "queued",
            "sending",
            "sent",
            "delivery_ambiguous",
            "cancelled",
            "failed",
            "expired",
            name="reminderdeliverystate",
        )
        kind_type = sa.Enum("7_day", "1_day", name="reminderkind")
    op.create_table(
        "reminderdelivery_smtp",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recipient_generation", sa.Integer(), nullable=False),
        sa.Column("kind", kind_type, nullable=False),
        sa.Column("state", state_column_type, nullable=False, server_default=sa.text("'queued'")),
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


def _mapped_state_expression(dialect_name: str) -> str:
    expression = """
        CASE
            WHEN CAST(state AS VARCHAR) = 'delivered' THEN 'sent'
            WHEN CAST(state AS VARCHAR) = 'invoice_creation_ambiguous' THEN 'delivery_ambiguous'
            WHEN CAST(state AS VARCHAR) IN ('cancelled', 'failed', 'expired')
                THEN CAST(state AS VARCHAR)
            ELSE 'cancelled'
        END
    """
    if dialect_name == "postgresql":
        return f"CAST(({expression}) AS reminderdeliverystate)"
    return expression


def downgrade() -> None:
    # Revision 0012 in this publication tree already uses the generic schema.
    # Never reconstruct scrubbed paid-provider fields during a downgrade.
    pass
