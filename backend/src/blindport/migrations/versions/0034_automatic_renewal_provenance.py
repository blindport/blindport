"""Persist automatic subscription renewal provenance.

Revision ID: 0034
Revises: 0033
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: str | None = "0033"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "payment",
        sa.Column("automatic_renewal", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    bind = op.get_bind()
    automatic_renewal_payments = bind.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE automatic_renewal = :value"),
        {"value": True},
    ).scalar_one()
    if automatic_renewal_payments:
        raise RuntimeError("cannot downgrade while automatic renewal payments exist")
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("automatic_renewal")
