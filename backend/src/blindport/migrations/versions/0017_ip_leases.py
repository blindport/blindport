"""Add durable dedicated IP assignment episodes.

Revision ID: 0017
Revises: 0016
"""

from __future__ import annotations

from collections.abc import Sequence
from uuid import uuid4

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _delivery_type(dialect_name: str) -> sa.types.TypeEngine:
    if dialect_name == "postgresql":
        return postgresql.ENUM("framed", "wireguard", name="ipleasedelivery")
    return sa.Enum("framed", "wireguard", name="ipleasedelivery")


def upgrade() -> None:
    bind = op.get_bind()
    now = sa.func.now()
    op.create_table(
        "iplease",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("public_id", sa.Uuid(), nullable=False),
        sa.Column("subscription_id", sa.Integer(), nullable=False),
        sa.Column("reservation_payment_id", sa.Integer(), nullable=True),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("delivery", _delivery_type(bind.dialect.name), nullable=False),
        sa.Column(
            "state",
            sa.Enum("reserved", "active", "quarantined", "released", name="ipleasestate"),
            server_default=sa.text("'reserved'"),
            nullable=False,
        ),
        sa.Column("reserved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantined_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("quarantine_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.String(length=255), nullable=True),
        sa.Column("imported", sa.Boolean(), nullable=False),
        sa.Column("smtp_enabled", sa.Boolean(), nullable=False),
        sa.Column("smtp_intended_use", sa.String(length=500), nullable=True),
        sa.Column("smtp_fee_paid_sats", sa.Integer(), nullable=False),
        sa.Column("smtp_reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("smtp_reviewed_by", sa.String(length=100), nullable=True),
        sa.Column("smtp_review_reference", sa.String(length=200), nullable=True),
        sa.Column("smtp_revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("smtp_revocation_reason", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "state IN ('reserved', 'active', 'quarantined', 'released')",
            name="ck_iplease_state",
        ),
        sa.CheckConstraint("smtp_fee_paid_sats >= 0", name="ck_iplease_smtp_fee_nonnegative"),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscription.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_iplease_public_id", "iplease", ["public_id"], unique=True)
    op.create_index(
        "ix_iplease_reservation_payment_id",
        "iplease",
        ["reservation_payment_id"],
        unique=False,
    )
    op.create_index(
        "ix_iplease_subscription_created",
        "iplease",
        ["subscription_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_iplease_unreleased_address",
        "iplease",
        ["address"],
        unique=True,
        sqlite_where=sa.text("released_at IS NULL"),
        postgresql_where=sa.text("released_at IS NULL"),
    )
    op.create_index(
        "uq_iplease_unreleased_subscription",
        "iplease",
        ["subscription_id"],
        unique=True,
        sqlite_where=sa.text("released_at IS NULL"),
        postgresql_where=sa.text("released_at IS NULL"),
    )

    subscription = sa.table(
        "subscription",
        sa.column("id", sa.Integer()),
        sa.column("product", sa.String()),
        sa.column("delivery", sa.String()),
        sa.column("status", sa.String()),
        sa.column("assigned_ip", sa.String()),
        sa.column("reservation_payment_id", sa.Integer()),
        sa.column("resource_quarantined_until", sa.DateTime(timezone=True)),
        sa.column("current_period_start", sa.DateTime(timezone=True)),
        sa.column("current_period_end", sa.DateTime(timezone=True)),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    lease = sa.table(
        "iplease",
        sa.column("public_id", sa.Uuid()),
        sa.column("subscription_id", sa.Integer()),
        sa.column("reservation_payment_id", sa.Integer()),
        sa.column("address", sa.String()),
        sa.column("delivery", _delivery_type(bind.dialect.name)),
        sa.column(
            "state",
            sa.Enum("reserved", "active", "quarantined", "released", name="ipleasestate"),
        ),
        sa.column("reserved_at", sa.DateTime(timezone=True)),
        sa.column("activated_at", sa.DateTime(timezone=True)),
        sa.column("expired_at", sa.DateTime(timezone=True)),
        sa.column("quarantined_at", sa.DateTime(timezone=True)),
        sa.column("quarantine_until", sa.DateTime(timezone=True)),
        sa.column("imported", sa.Boolean()),
        sa.column("smtp_enabled", sa.Boolean()),
        sa.column("smtp_fee_paid_sats", sa.Integer()),
        sa.column("created_at", sa.DateTime(timezone=True)),
        sa.column("updated_at", sa.DateTime(timezone=True)),
    )
    rows = bind.execute(
        sa.select(subscription).where(
            sa.func.lower(sa.cast(subscription.c.product, sa.String())) == "ip",
            subscription.c.assigned_ip.is_not(None),
        )
    ).mappings()
    for row in rows:
        status = str(row["status"]).lower()
        anchor = row["created_at"] or row["updated_at"]
        state = "active" if status == "active" else "reserved"
        expired_at = None
        quarantined_at = None
        if status == "expired":
            state = "quarantined"
            expired_at = row["current_period_end"] or row["updated_at"]
            quarantined_at = row["updated_at"]
        bind.execute(
            lease.insert().values(
                public_id=uuid4(),
                subscription_id=row["id"],
                reservation_payment_id=row["reservation_payment_id"],
                address=row["assigned_ip"],
                delivery=str(row["delivery"]).lower(),
                state=state,
                reserved_at=anchor,
                activated_at=row["current_period_start"] if status == "active" else None,
                expired_at=expired_at,
                quarantined_at=quarantined_at,
                quarantine_until=row["resource_quarantined_until"],
                imported=True,
                smtp_enabled=False,
                smtp_fee_paid_sats=0,
                created_at=anchor,
                updated_at=row["updated_at"] or anchor or now,
            )
        )


def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index("uq_iplease_unreleased_subscription", table_name="iplease")
    op.drop_index("uq_iplease_unreleased_address", table_name="iplease")
    op.drop_index("ix_iplease_subscription_created", table_name="iplease")
    op.drop_index("ix_iplease_reservation_payment_id", table_name="iplease")
    op.drop_index("ix_iplease_public_id", table_name="iplease")
    op.drop_table("iplease")
    if bind.dialect.name == "postgresql":
        postgresql.ENUM(name="ipleasestate").drop(bind, checkfirst=False)
        postgresql.ENUM(name="ipleasedelivery").drop(bind, checkfirst=False)
