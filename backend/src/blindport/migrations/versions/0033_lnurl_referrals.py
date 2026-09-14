"""Receive-only LNURL invoices and optional referral accounting.

Revision ID: 0033
Revises: 0032
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033"
down_revision: str | None = "0032"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # NULL provider/address identifies historical rows. No invoice is recreated,
    # no historical commission is credited, and no provider is inferred on upgrade.
    op.add_column("subscription", sa.Column("referral_address", sa.String(254)))
    for column in (
        sa.Column("invoice_provider", sa.String(16)),
        sa.Column("lnurl_attempted_at", sa.DateTime(timezone=True)),
        sa.Column("lnurl_verify_url", sa.String(2048)),
        sa.Column("lnurl_metadata", sa.String()),
        sa.Column("invoice_expires_at", sa.DateTime(timezone=True)),
        sa.Column("settlement_verified_at", sa.DateTime(timezone=True)),
        sa.Column(
            "settlement_review_required", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("lnurl_last_checked_at", sa.DateTime(timezone=True)),
        sa.Column("referral_address", sa.String(254)),
        sa.Column("referral_commission_bps", sa.Integer(), nullable=False, server_default="0"),
    ):
        op.add_column("payment", column)
    op.create_table(
        "referralpayout",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("address", sa.String(254), nullable=False),
        sa.Column("amount_sats", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("external_reference", sa.String(128), unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("paid_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("amount_sats >= 10000", name="ck_referralpayout_minimum"),
        sa.CheckConstraint("status IN ('reserved', 'paid')", name="ck_referralpayout_status"),
    )
    op.create_index("ix_referralpayout_address", "referralpayout", ["address"])
    op.create_table(
        "referralcredit",
        sa.Column("payment_id", sa.Integer(), sa.ForeignKey("payment.id"), primary_key=True),
        sa.Column("address", sa.String(254), nullable=False),
        sa.Column("amount_sats", sa.Integer(), nullable=False),
        sa.Column("payout_id", sa.Uuid(), sa.ForeignKey("referralpayout.id")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("amount_sats > 0", name="ck_referralcredit_positive"),
    )
    op.create_index("ix_referralcredit_address", "referralcredit", ["address"])
    op.create_index("ix_referralcredit_payout_id", "referralcredit", ["payout_id"])


def downgrade() -> None:
    bind = op.get_bind()
    for query in (
        "SELECT COUNT(*) FROM referralcredit",
        "SELECT COUNT(*) FROM referralpayout",
        "SELECT COUNT(*) FROM payment WHERE invoice_provider IS NOT NULL OR referral_address IS NOT NULL",
        "SELECT COUNT(*) FROM subscription WHERE referral_address IS NOT NULL",
    ):
        if bind.execute(sa.text(query)).scalar_one():
            raise RuntimeError("cannot downgrade while LNURL or referral records exist")
    op.drop_table("referralcredit")
    op.drop_table("referralpayout")
    with op.batch_alter_table("payment") as batch:
        for name in (
            "invoice_provider",
            "lnurl_attempted_at",
            "lnurl_verify_url",
            "lnurl_metadata",
            "invoice_expires_at",
            "settlement_verified_at",
            "settlement_review_required",
            "lnurl_last_checked_at",
            "referral_address",
            "referral_commission_bps",
        ):
            batch.drop_column(name)
    with op.batch_alter_table("subscription") as batch:
        batch.drop_column("referral_address")
