"""Persist exact Relay to wildcard upgrade snapshots.

Revision ID: 0029
Revises: 0028
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: str | None = "0028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _restore_sqlite_subscription_triggers() -> None:
    if op.get_bind().dialect.name != "sqlite":
        return
    op.execute(
        """CREATE TRIGGER trg_subscription_yearly_price_default
        AFTER INSERT ON subscription
        FOR EACH ROW
        WHEN NEW.yearly_price_sats = 0
        BEGIN
            UPDATE subscription
            SET yearly_price_sats = NEW.monthly_price_sats * 10
            WHERE id = NEW.id;
        END"""
    )
    op.execute(
        """CREATE TRIGGER trg_subscription_public_id_immutable
        BEFORE UPDATE OF public_id ON subscription
        FOR EACH ROW
        WHEN NEW.public_id IS NOT OLD.public_id
        BEGIN
            SELECT RAISE(ABORT, 'subscription public_id is immutable');
        END"""
    )


def upgrade() -> None:
    with op.batch_alter_table("subscription") as batch_op:
        batch_op.add_column(sa.Column("upgrade_from_subscription_id", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "upgrade_credit_sats", sa.Integer(), nullable=False, server_default=sa.text("0")
            )
        )
        batch_op.add_column(
            sa.Column("upgrade_source_period_end", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_subscription_upgrade_from_subscription",
            "subscription",
            ["upgrade_from_subscription_id"],
            ["id"],
        )
        batch_op.create_unique_constraint(
            "uq_subscription_upgrade_from_subscription", ["upgrade_from_subscription_id"]
        )
    _restore_sqlite_subscription_triggers()
    op.add_column(
        "payment",
        sa.Column("service_price_sats", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )
    op.add_column(
        "payment",
        sa.Column("discount_sats", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    connection = op.get_bind()
    upgrade_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM subscription WHERE upgrade_from_subscription_id IS NOT NULL")
    ).scalar_one()
    discount_count = connection.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE discount_sats <> 0")
    ).scalar_one()
    if upgrade_count or discount_count:
        raise RuntimeError(
            "cannot downgrade while Relay wildcard upgrades or discounted payments exist"
        )
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("discount_sats")
        batch_op.drop_column("service_price_sats")
    with op.batch_alter_table("subscription") as batch_op:
        batch_op.drop_constraint("uq_subscription_upgrade_from_subscription", type_="unique")
        batch_op.drop_constraint("fk_subscription_upgrade_from_subscription", type_="foreignkey")
        batch_op.drop_column("upgrade_source_period_end")
        batch_op.drop_column("upgrade_credit_sats")
        batch_op.drop_column("upgrade_from_subscription_id")
    _restore_sqlite_subscription_triggers()
