"""Add recoverable Lightning invoice identity.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("payment", sa.Column("invoice_idempotency_key", sa.String(), nullable=True))
    op.drop_index("ix_payment_payment_hash", table_name="payment")
    op.create_index(
        "uq_payment_payment_hash",
        "payment",
        ["payment_hash"],
        unique=True,
        sqlite_where=sa.text("payment_hash IS NOT NULL"),
        postgresql_where=sa.text("payment_hash IS NOT NULL"),
    )
    op.create_index(
        "uq_payment_invoice_idempotency_key",
        "payment",
        ["invoice_idempotency_key"],
        unique=True,
        sqlite_where=sa.text("invoice_idempotency_key IS NOT NULL"),
        postgresql_where=sa.text("invoice_idempotency_key IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("uq_payment_invoice_idempotency_key", table_name="payment")
    op.drop_index("uq_payment_payment_hash", table_name="payment")
    op.create_index("ix_payment_payment_hash", "payment", ["payment_hash"], unique=False)
    op.drop_column("payment", "invoice_idempotency_key")
