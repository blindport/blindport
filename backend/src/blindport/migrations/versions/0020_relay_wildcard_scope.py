"""Add Relay hostname scope for exact and wildcard claims.

Revision ID: 0020
Revises: 0019
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0020"
down_revision: str | None = "0019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _relay_hostname_scope_type() -> sa.Enum:
    if op.get_bind().dialect.name == "postgresql":
        return postgresql.ENUM("exact", "wildcard", name="relayhostnamescope", create_type=False)
    return sa.Enum("exact", "wildcard", name="relayhostnamescope")


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if bind.dialect.name == "postgresql":
        postgresql.ENUM("exact", "wildcard", name="relayhostnamescope").create(
            bind, checkfirst=True
        )
    scope = _relay_hostname_scope_type()
    op.add_column(
        "subscription",
        sa.Column(
            "relay_hostname_scope",
            scope,
            nullable=False,
            server_default=sa.text("'exact'"),
        ),
    )
    if inspector.has_table("agentorder"):
        op.add_column(
            "agentorder",
            sa.Column(
                "relay_hostname_scope",
                scope,
                nullable=False,
                server_default=sa.text("'exact'"),
            ),
        )
    op.create_index(
        "ix_subscription_relay_hostname_scope_domain",
        "subscription",
        ["relay_hostname_scope", "domain"],
    )


def downgrade() -> None:
    op.drop_index("ix_subscription_relay_hostname_scope_domain", table_name="subscription")
    if sa.inspect(op.get_bind()).has_table("agentorder"):
        op.drop_column("agentorder", "relay_hostname_scope")
    op.drop_column("subscription", "relay_hostname_scope")
    if op.get_bind().dialect.name == "postgresql":
        postgresql.ENUM(name="relayhostnamescope").drop(op.get_bind(), checkfirst=True)
