"""Encrypted reminder preferences and durable SMTP delivery transitions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .. import config
from ..adapters.smtp import SmtpAdapter, SmtpDeliveryError
from ..core.credentials import CredentialCipher, CredentialError
from ..core.models import (
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    User,
)
from .notification_email import lock_and_decrypt_notification_email

MAX_REMINDER_ATTEMPTS = 20


@dataclass(frozen=True)
class RenderedReminder:
    subject: str
    body: str


def render_expiration_reminder(
    kind: ReminderKind, current_period_end: datetime
) -> RenderedReminder:
    period_end = _aware(current_period_end)
    if kind == ReminderKind.SEVEN_DAY:
        days = 7
    elif kind == ReminderKind.ONE_DAY:
        days = 1
    else:
        raise ValueError("reminder kind is invalid")
    day_word = "day" if days == 1 else "days"
    deadline = period_end.strftime("%Y-%m-%d %H:%M UTC")
    return RenderedReminder(
        subject=f"Blindport subscription expires within {days} {day_word}",
        body=(
            "Your Blindport subscription is approaching the end of its paid period.\n\n"
            f"It expires within {days} {day_word}, on {deadline}.\n\n"
            "Sign in to Blindport to renew it before expiration.\n\n"
            "This reminder was sent because expiration notices are enabled for your account."
        ),
    )


def queue_reminder(
    session: Session,
    subscription: Subscription,
    kind: ReminderKind,
) -> ReminderDelivery:
    if subscription.id is None or subscription.current_period_end is None:
        raise ValueError("subscription must be persisted with a current period end")
    user = session.get(User, subscription.user_id)
    if user is None or not user.has_notification_email or user.notification_email_generation < 1:
        raise ValueError("subscription account has no reminder recipient")
    statement = select(ReminderDelivery).where(
        ReminderDelivery.subscription_id == subscription.id,
        ReminderDelivery.current_period_end == subscription.current_period_end,
        ReminderDelivery.kind == kind,
    )
    existing = session.exec(statement).first()
    if existing is not None:
        if existing.state == ReminderDeliveryState.QUEUED:
            existing.recipient_generation = user.notification_email_generation
            session.add(existing)
        elif existing.state == ReminderDeliveryState.CANCELLED:
            existing.state = ReminderDeliveryState.QUEUED
            existing.recipient_generation = user.notification_email_generation
            existing.attempt_count = 0
            existing.error_code = None
            existing.last_attempt_at = None
            existing.next_attempt_at = None
            existing.terminal_at = None
            existing.lease_token = None
            existing.lease_until = None
            session.add(existing)
        return existing
    delivery = ReminderDelivery(
        subscription_id=subscription.id,
        current_period_end=subscription.current_period_end,
        recipient_generation=user.notification_email_generation,
        kind=kind,
    )
    try:
        with session.begin_nested():
            session.add(delivery)
            session.flush()
    except IntegrityError:
        existing = session.exec(statement).first()
        if existing is None:  # pragma: no cover
            raise
        return existing
    return delivery


def send_reminder(
    session: Session,
    delivery: ReminderDelivery,
    user: User,
    adapter: SmtpAdapter,
    *,
    cipher: CredentialCipher | None = None,
    now: datetime | None = None,
) -> ReminderDelivery:
    attempted_at = _aware(now or datetime.now(UTC))
    if delivery.state != ReminderDeliveryState.QUEUED:
        raise ValueError("reminder delivery is not queued")
    lease_token = delivery.lease_token
    if delivery.attempt_count >= MAX_REMINDER_ATTEMPTS:
        _terminal(delivery, ReminderDeliveryState.FAILED, "attempts_exhausted", attempted_at)
        session.add(delivery)
        session.commit()
        return delivery
    delivery.attempt_count += 1
    delivery.state = ReminderDeliveryState.SENDING
    delivery.last_attempt_at = attempted_at
    delivery.updated_at = attempted_at
    delivery.next_attempt_at = None
    session.add(delivery)
    session.commit()

    try:
        recipient = lock_and_decrypt_notification_email(
            session,
            user.id,
            delivery.recipient_generation,
            cipher=cipher,
        )
        rendered = render_expiration_reminder(delivery.kind, delivery.current_period_end)
        adapter.send_message(
            recipient,
            rendered.subject,
            rendered.body,
            reminder_message_id(delivery),
        )
    except CredentialError:
        if fence_reminder_lease(session, delivery, lease_token):
            _terminal(delivery, ReminderDeliveryState.FAILED, "recipient_unavailable", attempted_at)
            session.add(delivery)
            session.commit()
        return delivery
    except SmtpDeliveryError as error:
        if not fence_reminder_lease(session, delivery, lease_token):
            return delivery
        if error.ambiguous:
            _terminal(
                delivery,
                ReminderDeliveryState.DELIVERY_AMBIGUOUS,
                error.code,
                attempted_at,
            )
        elif error.retryable and delivery.attempt_count < MAX_REMINDER_ATTEMPTS:
            delivery.state = ReminderDeliveryState.QUEUED
            delivery.error_code = error.code
            delivery.updated_at = attempted_at
            delivery.next_attempt_at = attempted_at + _retry_delay(delivery.attempt_count)
        else:
            _terminal(delivery, ReminderDeliveryState.FAILED, error.code, attempted_at)
        session.add(delivery)
        session.commit()
        return delivery
    except Exception:
        if fence_reminder_lease(session, delivery, lease_token):
            _terminal(delivery, ReminderDeliveryState.FAILED, "smtp_internal_error", attempted_at)
            session.add(delivery)
            session.commit()
        return delivery

    if not fence_reminder_lease(session, delivery, lease_token):
        return delivery
    delivery.state = ReminderDeliveryState.SENT
    delivery.error_code = None
    delivery.updated_at = attempted_at
    delivery.sent_at = attempted_at
    delivery.terminal_at = attempted_at
    delivery.next_attempt_at = None
    session.add(delivery)
    session.commit()
    return delivery


def reminder_message_id(delivery: ReminderDelivery) -> str:
    identity = "|".join(
        (
            str(delivery.subscription_id),
            _aware(delivery.current_period_end).isoformat(),
            delivery.kind.value,
            str(delivery.recipient_generation),
        )
    )
    digest = hashlib.sha256(f"blindport-reminder-v1|{identity}".encode("ascii")).hexdigest()
    domain = config.settings.SMTP_FROM_EMAIL.rsplit("@", 1)[-1].lower()
    return f"<{digest}@{domain}>"


def cancel_pending_reminders(
    session: Session,
    user: User,
    *,
    now: datetime | None = None,
) -> None:
    """Cancel deliveries that have not crossed the SMTP side-effect boundary."""
    if user.id is None:
        return
    cancelled_at = _aware(now or datetime.now(UTC))
    subscription_ids = select(Subscription.id).where(Subscription.user_id == user.id)
    session.exec(
        update(ReminderDelivery)
        .where(
            ReminderDelivery.subscription_id.in_(subscription_ids),  # type: ignore[union-attr]
            ReminderDelivery.state == ReminderDeliveryState.QUEUED,
        )
        .values(
            state=ReminderDeliveryState.CANCELLED,
            error_code="reminders_disabled",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )


def fence_reminder_lease(
    session: Session,
    delivery: ReminderDelivery,
    expected_token: str | None,
) -> bool:
    """Renew an owned lease atomically or discard a stale worker's result."""
    if expected_token is None or delivery.id is None:
        return True
    fenced_at = datetime.now(UTC)
    result = session.exec(
        update(ReminderDelivery)
        .where(
            ReminderDelivery.id == delivery.id,
            ReminderDelivery.lease_token == expected_token,
        )
        .values(
            lease_until=fenced_at
            + timedelta(seconds=config.settings.REMINDER_DELIVERY_LEASE_SECONDS)
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:  # type: ignore[attr-defined]
        return True
    session.rollback()
    session.refresh(delivery)
    return False


def cancel_reminder(delivery: ReminderDelivery, code: str, now: datetime) -> None:
    _terminal(delivery, ReminderDeliveryState.CANCELLED, code, _aware(now))


def _terminal(
    delivery: ReminderDelivery,
    state: ReminderDeliveryState,
    error_code: str,
    recorded_at: datetime,
) -> None:
    delivery.state = state
    delivery.error_code = error_code
    delivery.updated_at = recorded_at
    delivery.terminal_at = recorded_at
    delivery.next_attempt_at = None
    delivery.lease_token = None
    delivery.lease_until = None


def _retry_delay(attempt_count: int) -> timedelta:
    return timedelta(seconds=min(3600, 5 * 2 ** min(attempt_count, 10)))


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
