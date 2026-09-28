"""Shared proof checks for expiration and automatic-renewal alerts."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session, select

from ..core.models import (
    NotificationDelivery,
    NotificationKind,
    Payment,
    PaymentStatus,
    Subscription,
    SubscriptionStatus,
)


def has_period_automatic_renewal_failure(
    session: Session, subscription_id: int | None, period_end: datetime | None
) -> bool:
    """Whether a durable automatic-renewal failure was recorded for this period."""
    if subscription_id is None or period_end is None:
        return False
    return (
        session.exec(
            select(NotificationDelivery.id).where(
                NotificationDelivery.subscription_id == subscription_id,
                NotificationDelivery.kind == NotificationKind.AUTOMATIC_RENEWAL_FAILED,
                NotificationDelivery.event_at == _aware(period_end),
            )
        ).first()
        is not None
    )


def account_event_still_eligible(
    session: Session,
    delivery: NotificationDelivery,
    subscription: Subscription,
    payment: Payment | None,
    now: datetime,
) -> bool:
    """Recheck the paid-period contract both before claiming and immediately before SMTP."""
    period_end = subscription.current_period_end
    event_at = delivery.event_at
    if period_end is None or event_at is None or _aware(period_end) != _aware(event_at):
        return False
    if delivery.kind in (NotificationKind.EXPIRATION_7_DAY, NotificationKind.EXPIRATION_1_DAY):
        return bool(
            subscription.status == SubscriptionStatus.ACTIVE
            and _aware(period_end) > now
            and not subscription.auto_renew
            and not has_period_automatic_renewal_failure(session, subscription.id, period_end)
        )
    if delivery.kind == NotificationKind.AUTOMATIC_RENEWAL_FAILED:
        return bool(
            subscription.status in (SubscriptionStatus.ACTIVE, SubscriptionStatus.EXPIRED)
            and payment is not None
            and payment.status == PaymentStatus.FAILED
            and payment.automatic_renewal
            and payment.automatic_renewal_period_end is not None
            and _aware(payment.automatic_renewal_period_end) == _aware(period_end)
        )
    if delivery.kind == NotificationKind.AUTOMATIC_RENEWAL_UNCONFIRMED:
        return bool(
            subscription.status == SubscriptionStatus.ACTIVE
            and subscription.auto_renew
            and _aware(period_end) > now
            and delivery.payment_id is None
            and not has_period_automatic_renewal_failure(session, subscription.id, period_end)
        )
    if delivery.kind in (
        NotificationKind.SUBSCRIPTION_ACTIVATED,
        NotificationKind.SUBSCRIPTION_RENEWED,
    ):
        return subscription.status == SubscriptionStatus.ACTIVE
    if delivery.kind == NotificationKind.SUBSCRIPTION_EXPIRED:
        return subscription.status == SubscriptionStatus.EXPIRED
    return False


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
