"""Add durable account suspension state.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("user") as batch_op:
        batch_op.add_column(
            sa.Column("is_suspended", sa.Boolean(), nullable=False, server_default=sa.false())
        )
    with op.batch_alter_table("user") as batch_op:
        batch_op.alter_column("is_suspended", server_default=None)


def downgrade() -> None:
    with op.batch_alter_table("user") as batch_op:
        batch_op.drop_column("is_suspended")
