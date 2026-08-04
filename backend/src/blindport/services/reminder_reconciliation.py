"""Bounded, leased reconciliation for SMTP expiration reminders."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from uuid import uuid4

from loguru import logger
from sqlalchemy import and_, func, or_, update
from sqlmodel import Session, select

from .. import config, db
from ..adapters.smtp import SmtpAdapter, SmtpSecurity
from ..core.models import (
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    User,
)
from .reminders import cancel_reminder, queue_reminder, send_reminder

_TERMINAL_STATES = (
    ReminderDeliveryState.SENT,
    ReminderDeliveryState.DELIVERY_AMBIGUOUS,
    ReminderDeliveryState.CANCELLED,
    ReminderDeliveryState.FAILED,
    ReminderDeliveryState.EXPIRED,
)
_PROCESSABLE_STATES = (ReminderDeliveryState.QUEUED, ReminderDeliveryState.SENDING)


@dataclass(frozen=True)
class ReminderReconciliationSummary:
    queued: int = 0
    scanned: int = 0
    sent: int = 0
    pending: int = 0
    failed: int = 0


@cache
def get_smtp_adapter() -> SmtpAdapter:
    return SmtpAdapter(
        config.settings.SMTP_HOST,
        config.settings.SMTP_PORT,
        SmtpSecurity(config.settings.SMTP_SECURITY),
        config.settings.SMTP_FROM_EMAIL,
        username=config.settings.SMTP_USERNAME,
        password=config.settings.SMTP_PASSWORD,
        timeout_seconds=config.settings.SMTP_TIMEOUT_SECONDS,
    )


def reset_reminder_adapters_for_tests() -> None:
    get_smtp_adapter.cache_clear()


def _queue_due_reminders(now: datetime, batch_size: int) -> int:
    one_day = now + timedelta(days=1)
    seven_days = now + timedelta(days=7)
    with Session(db.engine) as session:
        seven_day_exists = (
            select(ReminderDelivery.id)
            .where(
                ReminderDelivery.subscription_id == Subscription.id,
                ReminderDelivery.current_period_end == Subscription.current_period_end,
                ReminderDelivery.kind == ReminderKind.SEVEN_DAY,
                ReminderDelivery.state != ReminderDeliveryState.CANCELLED,
            )
            .exists()
        )
        one_day_exists = (
            select(ReminderDelivery.id)
            .where(
                ReminderDelivery.subscription_id == Subscription.id,
                ReminderDelivery.current_period_end == Subscription.current_period_end,
                ReminderDelivery.kind == ReminderKind.ONE_DAY,
                ReminderDelivery.state != ReminderDeliveryState.CANCELLED,
            )
            .exists()
        )
        subscriptions = list(
            session.exec(
                select(Subscription)
                .join(User, User.id == Subscription.user_id)
                .where(
                    Subscription.status == SubscriptionStatus.ACTIVE,
                    Subscription.current_period_end.is_not(None),  # type: ignore[union-attr]
                    Subscription.current_period_end > now,  # type: ignore[operator]
                    User.has_reminder_email,
                    User.is_suspended.is_(False),  # type: ignore[union-attr]
                    or_(
                        and_(
                            Subscription.current_period_end <= one_day,  # type: ignore[operator]
                            ~one_day_exists,
                        ),
                        and_(
                            Subscription.current_period_end > one_day,  # type: ignore[operator]
                            Subscription.current_period_end <= seven_days,  # type: ignore[operator]
                            ~seven_day_exists,
                        ),
                    ),
                )
                .order_by(Subscription.current_period_end, Subscription.id)
                .limit(batch_size)
            ).all()
        )
        queued = 0
        for subscription in subscriptions:
            assert subscription.current_period_end is not None
            remaining = _aware(subscription.current_period_end) - now
            kind = (
                ReminderKind.ONE_DAY if remaining <= timedelta(days=1) else ReminderKind.SEVEN_DAY
            )
            before = session.exec(
                select(ReminderDelivery.id).where(
                    ReminderDelivery.subscription_id == subscription.id,
                    ReminderDelivery.current_period_end == subscription.current_period_end,
                    ReminderDelivery.kind == kind,
                )
            ).first()
            queue_reminder(session, subscription, kind)
            queued += before is None
        session.commit()
    return queued


def _claim_due_delivery(now: datetime) -> tuple[int, str] | None:
    with Session(db.engine) as session:
        database_now = func.now() if session.get_bind().dialect.name == "postgresql" else now
        delivery_id = session.exec(
            select(ReminderDelivery.id)
            .where(
                ReminderDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    ReminderDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    ReminderDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    ReminderDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    ReminderDelivery.lease_until <= database_now,
                ),
            )
            .order_by(ReminderDelivery.next_attempt_at, ReminderDelivery.id)
            .limit(1)
        ).first()
        if delivery_id is None:
            return None
        token = uuid4().hex
        result = session.exec(
            update(ReminderDelivery)
            .where(
                ReminderDelivery.id == delivery_id,
                ReminderDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    ReminderDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    ReminderDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    ReminderDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    ReminderDelivery.lease_until <= database_now,
                ),
            )
            .values(
                lease_token=token,
                lease_until=database_now
                + timedelta(seconds=config.settings.REMINDER_DELIVERY_LEASE_SECONDS),
            )
        )
        session.commit()
        if result.rowcount != 1:  # type: ignore[attr-defined]
            return None
        return delivery_id, token


def _release_lease(delivery_id: int, token: str) -> None:
    with Session(db.engine) as session:
        session.exec(
            update(ReminderDelivery)
            .where(ReminderDelivery.id == delivery_id, ReminderDelivery.lease_token == token)
            .values(lease_token=None, lease_until=None)
        )
        session.commit()


def _process_claimed_delivery(delivery_id: int, token: str, now: datetime) -> ReminderDeliveryState:
    with Session(db.engine) as session:
        delivery = session.exec(
            select(ReminderDelivery)
            .where(ReminderDelivery.id == delivery_id, ReminderDelivery.lease_token == token)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if delivery is None:
            return ReminderDeliveryState.FAILED
        subscription = session.get(Subscription, delivery.subscription_id)
        user = session.get(User, subscription.user_id) if subscription is not None else None
        if delivery.state == ReminderDeliveryState.SENDING:
            delivery.state = ReminderDeliveryState.DELIVERY_AMBIGUOUS
            delivery.error_code = "worker_interrupted"
            delivery.updated_at = now
            delivery.terminal_at = now
            delivery.next_attempt_at = None
            session.add(delivery)
            session.commit()
        elif subscription is None or user is None:
            cancel_reminder(delivery, "recipient_unavailable", now)
            delivery.state = ReminderDeliveryState.FAILED
            session.add(delivery)
            session.commit()
        elif not _is_delivery_eligible(delivery, subscription, user, now):
            cancel_reminder(delivery, "reminder_no_longer_eligible", now)
            session.add(delivery)
            session.commit()
        else:
            send_reminder(session, delivery, user, get_smtp_adapter(), now=now)
        return delivery.state


def reconcile_reminders_once(batch_size: int | None = None) -> ReminderReconciliationSummary:
    if not config.settings.REMINDER_EMAIL_ENABLED:
        return ReminderReconciliationSummary()
    effective_batch_size = (
        config.settings.PAYMENT_RECONCILIATION_BATCH_SIZE if batch_size is None else batch_size
    )
    if not 1 <= effective_batch_size <= 1000:
        raise ValueError("reminder reconciliation batch size must be within 1-1000")
    now = datetime.now(UTC)
    queued = _queue_due_reminders(now, effective_batch_size)
    counts = {"scanned": 0, "sent": 0, "pending": 0, "failed": 0}
    for _ in range(effective_batch_size):
        attempted_at = datetime.now(UTC)
        claim = _claim_due_delivery(attempted_at)
        if claim is None:
            break
        delivery_id, token = claim
        counts["scanned"] += 1
        try:
            state = _process_claimed_delivery(delivery_id, token, attempted_at)
            if state == ReminderDeliveryState.SENT:
                counts["sent"] += 1
            elif state in _TERMINAL_STATES:
                counts["failed"] += 1
            else:
                counts["pending"] += 1
        except Exception as error:
            counts["failed"] += 1
            logger.opt(exception=error).error(
                "reminder reconciliation failed for delivery_id={}", delivery_id
            )
        finally:
            _release_lease(delivery_id, token)
    return ReminderReconciliationSummary(queued=queued, **counts)


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _is_delivery_eligible(
    delivery: ReminderDelivery,
    subscription: Subscription,
    user: User,
    now: datetime,
) -> bool:
    period_end = subscription.current_period_end
    return bool(
        subscription.status == SubscriptionStatus.ACTIVE
        and period_end is not None
        and _aware(period_end) == _aware(delivery.current_period_end)
        and _aware(period_end) > now
        and not user.is_suspended
        and user.has_reminder_email
        and delivery.recipient_generation == user.reminder_email_generation
    )
