"""Add fixed monthly and yearly billing snapshots.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ROLLING_TRIGGER = "trg_subscription_yearly_price_default"
_ROLLING_FUNCTION = "blindport_subscription_yearly_price_default"


def _billing_term_type() -> sa.Enum:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        return postgresql.ENUM("monthly", "yearly", name="billingterm", create_type=False)
    return sa.Enum("monthly", "yearly", name="billingterm")


def _create_rolling_insert_guard() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        op.execute(
            f"""CREATE TRIGGER {_ROLLING_TRIGGER}
            AFTER INSERT ON subscription
            FOR EACH ROW
            WHEN NEW.yearly_price_sats = 0
            BEGIN
                UPDATE subscription
                SET yearly_price_sats = NEW.monthly_price_sats * 10
                WHERE id = NEW.id;
            END"""
        )
    elif bind.dialect.name == "postgresql":
        op.execute(
            f"""CREATE FUNCTION {_ROLLING_FUNCTION}() RETURNS trigger AS $$
            BEGIN
                IF NEW.yearly_price_sats = 0 THEN
                    NEW.yearly_price_sats := NEW.monthly_price_sats * 10;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql"""
        )
        op.execute(
            f"""CREATE TRIGGER {_ROLLING_TRIGGER}
            BEFORE INSERT ON subscription
            FOR EACH ROW EXECUTE FUNCTION {_ROLLING_FUNCTION}()"""
        )


def _drop_rolling_insert_guard() -> None:
    bind = op.get_bind()
    op.execute(
        f"DROP TRIGGER IF EXISTS {_ROLLING_TRIGGER} ON subscription"
        if bind.dialect.name == "postgresql"
        else f"DROP TRIGGER IF EXISTS {_ROLLING_TRIGGER}"
    )
    if bind.dialect.name == "postgresql":
        op.execute(f"DROP FUNCTION IF EXISTS {_ROLLING_FUNCTION}()")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        postgresql.ENUM("monthly", "yearly", name="billingterm").create(bind, checkfirst=True)
    billing_term = _billing_term_type()
    op.add_column(
        "subscription",
        sa.Column(
            "billing_term",
            billing_term,
            nullable=False,
            server_default=sa.text("'monthly'"),
        ),
    )
    op.add_column(
        "subscription",
        sa.Column("yearly_price_sats", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.execute("UPDATE subscription SET yearly_price_sats = monthly_price_sats * 10")
    _create_rolling_insert_guard()

    op.add_column(
        "payment",
        sa.Column(
            "billing_term",
            billing_term,
            nullable=False,
            server_default=sa.text("'monthly'"),
        ),
    )
    op.add_column(
        "payment",
        sa.Column("period_days", sa.Integer(), nullable=False, server_default=sa.text("30")),
    )


def downgrade() -> None:
    _drop_rolling_insert_guard()
    op.drop_column("payment", "period_days")
    op.drop_column("payment", "billing_term")
    op.drop_column("subscription", "yearly_price_sats")
    op.drop_column("subscription", "billing_term")
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        postgresql.ENUM(name="billingterm").drop(bind, checkfirst=True)
