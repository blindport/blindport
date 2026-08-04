"""Scrub persisted direct-client rate-limit identifiers.

Revision ID: 0015
Revises: 0014
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0015"
down_revision: str | None = "0014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_DIRECT_SCOPES = ("signup", "admin-login", "browser-login")


def upgrade() -> None:
    bucket = sa.table(
        "ratelimitbucket",
        sa.column("scope", sa.String()),
    )
    maintenance = sa.table(
        "ratelimitmaintenance",
        sa.column("name", sa.String()),
        sa.column("bucket_count", sa.Integer()),
    )
    op.execute(bucket.delete().where(bucket.c.scope.in_(_DIRECT_SCOPES)))
    remaining = sa.select(sa.func.count()).select_from(bucket).scalar_subquery()
    op.execute(
        maintenance.update()
        .where(maintenance.c.name == "rate-limit-buckets")
        .values(bucket_count=remaining)
    )


def downgrade() -> None:
    # Deleted pseudonymous request-source identifiers cannot and should not be restored.
    pass
