"""Independent bounded reconciliation for unified email notifications."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from loguru import logger
from sqlalchemy import and_, func, or_, update
from sqlmodel import Session, select

from .. import config, db
from ..core.models import (
    Announcement,
    AnnouncementRecipientSnapshot,
    AnnouncementState,
    NotificationCategory,
    NotificationDelivery,
    NotificationDeliveryState,
    NotificationKind,
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    User,
)
from .announcement_reconciliation import reconcile_announcements_once
from .announcements import mark_announcement_completed_if_done
from .notifications import (
    cancel_notification,
    queue_notification,
    send_notification,
)
from .payment_reconciliation import ReconcilerHealth
from .reminder_reconciliation import get_smtp_adapter, reconcile_reminders_once

_TERMINAL_STATES = (
    NotificationDeliveryState.SENT,
    NotificationDeliveryState.DELIVERY_AMBIGUOUS,
    NotificationDeliveryState.CANCELLED,
    NotificationDeliveryState.FAILED,
    NotificationDeliveryState.EXPIRED,
)
_PROCESSABLE_STATES = (NotificationDeliveryState.QUEUED, NotificationDeliveryState.SENDING)


@dataclass(frozen=True)
class NotificationReconciliationSummary:
    queued: int = 0
    scanned: int = 0
    sent: int = 0
    pending: int = 0
    failed: int = 0


notification_reconciler_health = ReconcilerHealth()


def _expiration_idempotency_key(
    subscription_id: int, period_end: datetime, kind: NotificationKind
) -> str:
    return f"expiration:{subscription_id}:{_aware(period_end).isoformat()}:{kind.value}"


def _queue_due_expirations(now: datetime, batch_size: int) -> int:
    """Discover one bounded set of expiration events without storing message material."""
    one_day = now + timedelta(days=1)
    seven_days = now + timedelta(days=7)
    with Session(db.engine) as session:
        seven_day_exists = (
            select(NotificationDelivery.id)
            .where(
                NotificationDelivery.subscription_id == Subscription.id,
                NotificationDelivery.event_at == Subscription.current_period_end,
                NotificationDelivery.kind == NotificationKind.EXPIRATION_7_DAY,
            )
            .exists()
        )
        legacy_seven_day_exists = (
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
            select(NotificationDelivery.id)
            .where(
                NotificationDelivery.subscription_id == Subscription.id,
                NotificationDelivery.event_at == Subscription.current_period_end,
                NotificationDelivery.kind == NotificationKind.EXPIRATION_1_DAY,
            )
            .exists()
        )
        legacy_one_day_exists = (
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
                    User.reminder_email_generation >= 1,
                    User.is_suspended.is_(False),  # type: ignore[union-attr]
                    or_(
                        and_(
                            Subscription.current_period_end <= one_day,  # type: ignore[operator]
                            ~one_day_exists,
                            ~legacy_one_day_exists,
                        ),
                        and_(
                            Subscription.current_period_end > one_day,  # type: ignore[operator]
                            Subscription.current_period_end <= seven_days,  # type: ignore[operator]
                            ~seven_day_exists,
                            ~legacy_seven_day_exists,
                        ),
                    ),
                )
                .order_by(Subscription.current_period_end, Subscription.id)
                .limit(batch_size)
            ).all()
        )
        queued = 0
        for subscription in subscriptions:
            assert subscription.id is not None
            assert subscription.current_period_end is not None
            user = session.get(User, subscription.user_id)
            if user is None:  # pragma: no cover - FK integrity protects this path
                continue
            remaining = _aware(subscription.current_period_end) - now
            kind = (
                NotificationKind.EXPIRATION_1_DAY
                if remaining <= timedelta(days=1)
                else NotificationKind.EXPIRATION_7_DAY
            )
            key = _expiration_idempotency_key(
                subscription.id, subscription.current_period_end, kind
            )
            existed = session.exec(
                select(NotificationDelivery.id).where(NotificationDelivery.idempotency_key == key)
            ).first()
            queue_notification(
                session,
                user,
                NotificationCategory.ACCOUNT,
                kind,
                key,
                subscription=subscription,
                event_at=subscription.current_period_end,
            )
            queued += existed is None
        session.commit()
    return queued


def _cancel_invalid_queued_deliveries(now: datetime, batch_size: int) -> None:
    """Invalidate only pre-SMTP work when consent or eligibility changed."""
    with Session(db.engine) as session:
        deliveries = session.exec(
            select(NotificationDelivery, User)
            .join(User, User.id == NotificationDelivery.user_id)
            .where(NotificationDelivery.state == NotificationDeliveryState.QUEUED)
            .order_by(NotificationDelivery.id)
            .limit(batch_size)
        ).all()
        changed = False
        for delivery, user in deliveries:
            subscription = (
                session.get(Subscription, delivery.subscription_id)
                if delivery.subscription_id is not None
                else None
            )
            announcement = (
                session.get(Announcement, delivery.announcement_id)
                if delivery.announcement_id is not None
                else None
            )
            if not _is_delivery_eligible(delivery, user, subscription, announcement, now):
                cancel_notification(delivery, "notification_no_longer_eligible", now)
                session.add(delivery)
                changed = True
        if changed:
            session.commit()


def _expand_queued_announcements(batch_size: int) -> int:
    """Expand one bounded recipient page for each queued campaign cycle."""
    with Session(db.engine) as session:
        announcement = session.exec(
            select(Announcement)
            .where(
                Announcement.state == AnnouncementState.QUEUED,
                Announcement.expansion_complete.is_(False),  # type: ignore[union-attr]
            )
            .order_by(Announcement.id)
            .limit(1)
            .with_for_update()
        ).first()
        if announcement is None:
            return 0
        if announcement.id is None:
            announcement.expansion_complete = True
            session.add(announcement)
            session.commit()
            return 0
        recipients = session.exec(
            select(AnnouncementRecipientSnapshot, User)
            .join(User, User.id == AnnouncementRecipientSnapshot.user_id)
            .where(
                AnnouncementRecipientSnapshot.announcement_id == announcement.id,
                AnnouncementRecipientSnapshot.user_id > announcement.recipient_cursor,
            )
            .order_by(AnnouncementRecipientSnapshot.user_id)
            .limit(batch_size)
        ).all()
        if not recipients:
            announcement.expansion_complete = True
            session.add(announcement)
            session.commit()
            return 0
        for snapshot, user in recipients:
            assert user.id is not None
            queue_notification(
                session,
                user,
                NotificationCategory.SERVICE,
                NotificationKind.SERVICE_ANNOUNCEMENT,
                f"announcement:{announcement.id}:user:{user.id}",
                announcement=announcement,
                recipient_generation=snapshot.recipient_generation,
            )
        announcement.recipient_cursor = recipients[-1][0].user_id
        # A short page proves there can be no later recipient in the snapshot.
        if len(recipients) < batch_size:
            announcement.expansion_complete = True
        session.add(announcement)
        session.commit()
        return len(recipients)


def _claim_due_delivery(now: datetime) -> tuple[int, str] | None:
    with Session(db.engine) as session:
        database_now = func.now() if session.get_bind().dialect.name == "postgresql" else now
        delivery_id = session.exec(
            select(NotificationDelivery.id)
            .where(
                NotificationDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    NotificationDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    NotificationDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    NotificationDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    NotificationDelivery.lease_until <= database_now,
                ),
            )
            .order_by(NotificationDelivery.next_attempt_at, NotificationDelivery.id)
            .limit(1)
        ).first()
        if delivery_id is None:
            return None
        token = uuid4().hex
        result = session.exec(
            update(NotificationDelivery)
            .where(
                NotificationDelivery.id == delivery_id,
                NotificationDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    NotificationDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    NotificationDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    NotificationDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    NotificationDelivery.lease_until <= database_now,
                ),
            )
            .values(
                lease_token=token,
                lease_until=database_now
                + timedelta(seconds=config.settings.NOTIFICATION_DELIVERY_LEASE_SECONDS),
            )
        )
        session.commit()
        if result.rowcount != 1:  # type: ignore[attr-defined]
            return None
        return delivery_id, token


def _release_lease(delivery_id: int, token: str) -> None:
    with Session(db.engine) as session:
        session.exec(
            update(NotificationDelivery)
            .where(
                NotificationDelivery.id == delivery_id,
                NotificationDelivery.lease_token == token,
            )
            .values(lease_token=None, lease_until=None)
        )
        session.commit()


def _process_claimed_delivery(
    delivery_id: int, token: str, now: datetime
) -> NotificationDeliveryState:
    with Session(db.engine) as session:
        delivery = session.exec(
            select(NotificationDelivery)
            .where(
                NotificationDelivery.id == delivery_id, NotificationDelivery.lease_token == token
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if delivery is None:
            return NotificationDeliveryState.FAILED
        user = session.get(User, delivery.user_id)
        subscription = (
            session.get(Subscription, delivery.subscription_id)
            if delivery.subscription_id is not None
            else None
        )
        announcement = (
            session.get(Announcement, delivery.announcement_id)
            if delivery.announcement_id is not None
            else None
        )
        if delivery.state == NotificationDeliveryState.SENDING:
            delivery.state = NotificationDeliveryState.DELIVERY_AMBIGUOUS
            delivery.error_code = "worker_interrupted"
            delivery.updated_at = now
            delivery.terminal_at = now
            delivery.next_attempt_at = None
            delivery.lease_token = None
            delivery.lease_until = None
            session.add(delivery)
            session.commit()
        elif user is None:
            _fail_unavailable(session, delivery, now)
        elif not _is_delivery_eligible(delivery, user, subscription, announcement, now):
            cancel_notification(delivery, "notification_no_longer_eligible", now)
            session.add(delivery)
            session.commit()
        else:
            send_notification(
                session,
                delivery,
                user,
                get_smtp_adapter(),
                subscription=subscription,
                announcement=announcement,
                now=now,
            )
        return delivery.state


def reconcile_notifications_once(
    batch_size: int | None = None,
) -> NotificationReconciliationSummary:
    """Run one bounded independent notification reconciliation cycle."""
    if not (config.settings.REMINDER_EMAIL_ENABLED or config.settings.ANNOUNCEMENT_EMAIL_ENABLED):
        return NotificationReconciliationSummary()
    effective_batch_size = (
        config.settings.NOTIFICATION_RECONCILIATION_BATCH_SIZE if batch_size is None else batch_size
    )
    if not 1 <= effective_batch_size <= 1000:
        raise ValueError("notification reconciliation batch size must be within 1-1000")
    now = datetime.now(UTC)
    _cancel_invalid_queued_deliveries(now, effective_batch_size)
    # Existing rows retain their delivery implementation until they are terminal.
    # These calls no longer discover legacy rows.
    reconcile_reminders_once(effective_batch_size)
    reconcile_announcements_once(effective_batch_size)
    queued = (
        _queue_due_expirations(now, effective_batch_size)
        if config.settings.REMINDER_EMAIL_ENABLED
        else 0
    )
    queued += (
        _expand_queued_announcements(effective_batch_size)
        if config.settings.ANNOUNCEMENT_EMAIL_ENABLED
        else 0
    )
    if config.settings.ANNOUNCEMENT_EMAIL_ENABLED:
        with Session(db.engine) as session:
            for announcement_id in session.exec(
                select(Announcement.id)
                .where(
                    Announcement.state == AnnouncementState.QUEUED,
                    Announcement.expansion_complete,
                )
                .order_by(Announcement.id)
                .limit(effective_batch_size)
            ).all():
                if announcement_id is not None:
                    mark_announcement_completed_if_done(session, announcement_id)
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
            if state == NotificationDeliveryState.SENT:
                counts["sent"] += 1
            elif state in _TERMINAL_STATES:
                counts["failed"] += 1
            else:
                counts["pending"] += 1
        except Exception as error:
            counts["failed"] += 1
            logger.opt(exception=error).error(
                "notification reconciliation failed for delivery_id={}", delivery_id
            )
        finally:
            _release_lease(delivery_id, token)
    return NotificationReconciliationSummary(queued=queued, **counts)


async def run_notification_reconciler(
    stop_event: asyncio.Event,
    *,
    reconcile_once: Callable[[], NotificationReconciliationSummary] = reconcile_notifications_once,
    interval_seconds: float | None = None,
) -> None:
    """Run fixed-rate notification cycles independently from payment reconciliation."""
    interval = (
        config.settings.NOTIFICATION_RECONCILIATION_INTERVAL_SECONDS
        if interval_seconds is None
        else interval_seconds
    )
    next_cycle_at = time.monotonic()
    while not stop_event.is_set():
        try:
            summary = await asyncio.to_thread(reconcile_once)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.opt(exception=error).error("notification reconciliation cycle failed")
        else:
            notification_reconciler_health.record_completed_cycle()
            logger.debug(
                "notification reconciliation cycle complete: queued={}, scanned={}, sent={}, "
                "pending={}, failed={}",
                summary.queued,
                summary.scanned,
                summary.sent,
                summary.pending,
                summary.failed,
            )
        next_cycle_at += interval
        current = time.monotonic()
        if next_cycle_at <= current:
            next_cycle_at = current + interval
        with suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=next_cycle_at - current)


def _is_delivery_eligible(
    delivery: NotificationDelivery,
    user: User,
    subscription: Subscription | None,
    announcement: Announcement | None,
    now: datetime,
) -> bool:
    if delivery.category == NotificationCategory.ACCOUNT:
        period_end = subscription.current_period_end if subscription is not None else None
        account_consent = bool(
            config.settings.REMINDER_EMAIL_ENABLED
            and not user.is_suspended
            and user.has_reminder_email
            and delivery.recipient_generation == user.reminder_email_generation
        )
        if not account_consent or subscription is None or subscription.user_id != user.id:
            return False
        if delivery.kind in (NotificationKind.EXPIRATION_7_DAY, NotificationKind.EXPIRATION_1_DAY):
            return bool(
                subscription.status == SubscriptionStatus.ACTIVE
                and period_end is not None
                and delivery.event_at is not None
                and _aware(period_end) == _aware(delivery.event_at)
                and _aware(period_end) > now
            )
        if delivery.kind in (
            NotificationKind.SUBSCRIPTION_ACTIVATED,
            NotificationKind.SUBSCRIPTION_RENEWED,
        ):
            return bool(
                subscription.status == SubscriptionStatus.ACTIVE
                and period_end is not None
                and delivery.event_at is not None
                and _aware(period_end) == _aware(delivery.event_at)
            )
        if delivery.kind == NotificationKind.SUBSCRIPTION_EXPIRED:
            return bool(
                subscription.status == SubscriptionStatus.EXPIRED
                and period_end is not None
                and delivery.event_at is not None
                and _aware(period_end) == _aware(delivery.event_at)
            )
        return False
    return bool(
        config.settings.ANNOUNCEMENT_EMAIL_ENABLED
        and delivery.kind == NotificationKind.SERVICE_ANNOUNCEMENT
        and announcement is not None
        and announcement.state == AnnouncementState.QUEUED
        and not user.is_admin
        and not user.is_suspended
        and user.has_service_email
        and delivery.recipient_generation == user.service_email_generation
    )


def _fail_unavailable(session: Session, delivery: NotificationDelivery, now: datetime) -> None:
    delivery.state = NotificationDeliveryState.FAILED
    delivery.error_code = "recipient_unavailable"
    delivery.updated_at = now
    delivery.terminal_at = now
    delivery.next_attempt_at = None
    delivery.lease_token = None
    delivery.lease_until = None
    session.add(delivery)
    session.commit()


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
