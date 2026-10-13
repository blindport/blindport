"""Persist encrypted notification resource identity snapshots.

Revision ID: 0035
Revises: 0034
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_KINDS = (
    "expiration_7_day",
    "expiration_1_day",
    "subscription_activated",
    "subscription_renewed",
    "subscription_expired",
    "service_announcement",
)
_NEW_KINDS = (
    *_OLD_KINDS,
    "automatic_renewal_failed",
    "automatic_renewal_unconfirmed",
)
_IDENTITY_PAIR_CONSTRAINT = "ck_notificationdelivery_resource_identity_pair"


def _notification_kind_enum(kinds: tuple[str, ...]) -> sa.Enum:
    return sa.Enum(*kinds, name="notificationkind")


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for kind in _NEW_KINDS[len(_OLD_KINDS) :]:
            op.execute(f"ALTER TYPE notificationkind ADD VALUE IF NOT EXISTS '{kind}'")
        op.add_column(
            "payment", sa.Column("automatic_renewal_period_end", sa.DateTime(timezone=True))
        )
        op.add_column("notificationdelivery", sa.Column("resource_identity_ciphertext", sa.Text()))
        op.add_column(
            "notificationdelivery", sa.Column("resource_identity_key_version", sa.String(length=32))
        )
        op.create_check_constraint(
            _IDENTITY_PAIR_CONSTRAINT,
            "notificationdelivery",
            "(resource_identity_ciphertext IS NULL) = (resource_identity_key_version IS NULL)",
        )
        return

    with op.batch_alter_table("notificationdelivery") as batch_op:
        batch_op.alter_column(
            "kind",
            existing_type=_notification_kind_enum(_OLD_KINDS),
            type_=_notification_kind_enum(_NEW_KINDS),
            existing_nullable=False,
        )
        batch_op.add_column(sa.Column("resource_identity_ciphertext", sa.Text()))
        batch_op.add_column(sa.Column("resource_identity_key_version", sa.String(length=32)))
        batch_op.create_check_constraint(
            _IDENTITY_PAIR_CONSTRAINT,
            "(resource_identity_ciphertext IS NULL) = (resource_identity_key_version IS NULL)",
        )
    op.add_column("payment", sa.Column("automatic_renewal_period_end", sa.DateTime(timezone=True)))


def downgrade() -> None:
    bind = op.get_bind()
    new_kinds = bind.execute(
        sa.text("SELECT COUNT(*) FROM notificationdelivery WHERE kind IN :kinds").bindparams(
            sa.bindparam("kinds", expanding=True)
        ),
        {"kinds": _NEW_KINDS[len(_OLD_KINDS) :]},
    ).scalar_one()
    identity_snapshots = bind.execute(
        sa.text(
            "SELECT COUNT(*) FROM notificationdelivery "
            "WHERE resource_identity_ciphertext IS NOT NULL "
            "OR resource_identity_key_version IS NOT NULL"
        )
    ).scalar_one()
    renewal_periods = bind.execute(
        sa.text("SELECT COUNT(*) FROM payment WHERE automatic_renewal_period_end IS NOT NULL")
    ).scalar_one()
    if new_kinds or identity_snapshots or renewal_periods:
        raise RuntimeError(
            "cannot downgrade while notification identity or renewal outcome data exists"
        )

    if bind.dialect.name != "postgresql":
        with op.batch_alter_table("notificationdelivery") as batch_op:
            batch_op.drop_constraint(_IDENTITY_PAIR_CONSTRAINT, type_="check")
            batch_op.drop_column("resource_identity_key_version")
            batch_op.drop_column("resource_identity_ciphertext")
            batch_op.alter_column(
                "kind",
                existing_type=_notification_kind_enum(_NEW_KINDS),
                type_=_notification_kind_enum(_OLD_KINDS),
                existing_nullable=False,
            )
    else:
        op.drop_constraint(_IDENTITY_PAIR_CONSTRAINT, "notificationdelivery", type_="check")
        op.drop_column("notificationdelivery", "resource_identity_key_version")
        op.drop_column("notificationdelivery", "resource_identity_ciphertext")
        op.execute(
            "ALTER TABLE notificationdelivery ALTER COLUMN kind TYPE VARCHAR(64) USING kind::text"
        )
        postgresql.ENUM(name="notificationkind").drop(bind, checkfirst=False)
        postgresql.ENUM(*_OLD_KINDS, name="notificationkind").create(bind, checkfirst=False)
        op.execute(
            "ALTER TABLE notificationdelivery ALTER COLUMN kind TYPE notificationkind "
            "USING kind::notificationkind"
        )
    with op.batch_alter_table("payment") as batch_op:
        batch_op.drop_column("automatic_renewal_period_end")
