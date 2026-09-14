from __future__ import annotations

from uuid import UUID

from sqlmodel import Session, select

from blindport.core.models import Subscription


def subscription_by_public_id(
    session: Session,
    public_id: str,
    *,
    populate_existing: bool = False,
) -> Subscription:
    statement = select(Subscription).where(Subscription.public_id == UUID(public_id))
    if populate_existing:
        statement = statement.execution_options(populate_existing=True)
    return session.exec(statement).one()
