"""Unified privacy-preserving SMTP notification outbox operations."""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .. import config
from ..adapters.smtp import SmtpAdapter, SmtpDeliveryError
from ..core.credentials import CredentialCipher, CredentialError
from ..core.models import (
    Announcement,
    NotificationCategory,
    NotificationDelivery,
    NotificationDeliveryState,
    NotificationKind,
    Payment,
    ProductType,
    Subscription,
    User,
)
from .notification_email import lock_and_decrypt_notification_email
from .notification_identity import (
    resource_identity,
    snapshot_resource_identity,
    store_resource_identity,
)
from .renewal_alerts import account_event_still_eligible

MAX_NOTIFICATION_ATTEMPTS = 20
_MESSAGE_ID_VERSION = "blindport-notification-v1"
_ERROR_CODE = re.compile(r"[a-z0-9_]{1,64}")
_EXPIRATION_KINDS = (
    NotificationKind.EXPIRATION_7_DAY,
    NotificationKind.EXPIRATION_1_DAY,
)
_ACCOUNT_KINDS = (
    *_EXPIRATION_KINDS,
    NotificationKind.SUBSCRIPTION_ACTIVATED,
    NotificationKind.SUBSCRIPTION_RENEWED,
    NotificationKind.AUTOMATIC_RENEWAL_FAILED,
    NotificationKind.AUTOMATIC_RENEWAL_UNCONFIRMED,
    NotificationKind.SUBSCRIPTION_EXPIRED,
)


@dataclass(frozen=True)
class RenderedNotification:
    subject: str
    body: str


def queue_notification(
    session: Session,
    user: User,
    category: NotificationCategory,
    kind: NotificationKind,
    idempotency_key: str,
    *,
    subscription: Subscription | None = None,
    payment: Payment | None = None,
    announcement: Announcement | None = None,
    event_at: datetime | None = None,
    recipient_generation: int | None = None,
) -> NotificationDelivery:
    """Insert one idempotent notification without committing the caller's transaction."""
    if user.id is None:
        raise ValueError("notification user must be persisted")
    _validate_idempotency_key(idempotency_key)
    _validate_notification_refs(category, kind, subscription, payment, announcement, event_at)
    if subscription is not None and (subscription.id is None or subscription.user_id != user.id):
        raise ValueError("notification subscription does not belong to the user")
    if payment is not None and payment.id is None:
        raise ValueError("notification payment must be persisted")
    if (
        payment is not None
        and subscription is not None
        and payment.subscription_id != subscription.id
    ):
        raise ValueError("notification payment does not belong to the subscription")
    if announcement is not None and announcement.id is None:
        raise ValueError("notification announcement must be persisted")
    generation = (
        _validate_recipient_generation_override(recipient_generation, category, kind, announcement)
        if recipient_generation is not None
        else _recipient_generation(user, category)
    )
    statement = select(NotificationDelivery).where(
        NotificationDelivery.idempotency_key == idempotency_key
    )
    existing = session.exec(statement).first()
    if existing is not None:
        return _reuse_queued_delivery(
            session,
            existing,
            user.id,
            generation,
            category,
            kind,
            subscription.id if subscription is not None else None,
            payment.id if payment is not None else None,
            announcement.id if announcement is not None else None,
            _aware(event_at) if event_at is not None else None,
        )

    delivery = NotificationDelivery(
        user_id=user.id,
        subscription_id=subscription.id if subscription is not None else None,
        payment_id=payment.id if payment is not None else None,
        announcement_id=announcement.id if announcement is not None else None,
        category=category,
        kind=kind,
        idempotency_key=idempotency_key,
        recipient_generation=generation,
        event_at=_aware(event_at) if event_at is not None else None,
    )
    try:
        with session.begin_nested():
            session.add(delivery)
            session.flush()
    except IntegrityError:
        existing = session.exec(statement).first()
        if existing is None:  # pragma: no cover - a database must report the winning row
            raise
        return _reuse_queued_delivery(
            session,
            existing,
            user.id,
            generation,
            category,
            kind,
            subscription.id if subscription is not None else None,
            payment.id if payment is not None else None,
            announcement.id if announcement is not None else None,
            _aware(event_at) if event_at is not None else None,
        )
    # Snapshot failures are deliberately nonfatal, see store_resource_identity.
    if subscription is not None:
        store_resource_identity(delivery, user, subscription)
    return delivery


def render_notification(
    delivery: NotificationDelivery,
    *,
    subscription: Subscription | None = None,
    payment: Payment | None = None,
    announcement: Announcement | None = None,
    user: User | None = None,
    cipher: CredentialCipher | None = None,
    now: datetime | None = None,
) -> RenderedNotification:
    """Render delivery content just before SMTP, keeping it out of durable state."""
    rendered_at = _aware(now or datetime.now(UTC))
    if delivery.kind in _EXPIRATION_KINDS:
        if delivery.event_at is None:
            raise ValueError("expiration notification has no period end")
        return _render_expiration(
            subscription.product if subscription is not None else None,
            delivery.event_at,
            rendered_at,
            _resource_details(delivery, subscription, user, cipher),
        )
    if delivery.kind == NotificationKind.SERVICE_ANNOUNCEMENT:
        if announcement is None:
            raise ValueError("service announcement is unavailable")
        _ensure_plaintext_limits(announcement.subject, announcement.body)
        return RenderedNotification(announcement.subject, announcement.body)
    if subscription is None:
        raise ValueError("subscription notification is unavailable")
    event_at = delivery.event_at or subscription.current_period_end
    return _render_subscription_event(
        delivery.kind,
        subscription.product,
        event_at,
        automatic_renewal=bool(payment and payment.automatic_renewal),
        resource_details=_resource_details(delivery, subscription, user, cipher),
        rendered_at=rendered_at,
    )


def send_notification(
    session: Session,
    delivery: NotificationDelivery,
    user: User,
    adapter: SmtpAdapter,
    *,
    subscription: Subscription | None = None,
    payment: Payment | None = None,
    announcement: Announcement | None = None,
    cipher: CredentialCipher | None = None,
    now: datetime | None = None,
) -> NotificationDelivery:
    """Cross the committed SMTP boundary and finalize only under the owned lease."""
    attempted_at = _aware(now or datetime.now(UTC))
    if delivery.state != NotificationDeliveryState.QUEUED:
        raise ValueError("notification delivery is not queued")
    lease_token = delivery.lease_token
    if delivery.attempt_count >= MAX_NOTIFICATION_ATTEMPTS:
        _terminal(delivery, NotificationDeliveryState.FAILED, "attempts_exhausted", attempted_at)
        session.add(delivery)
        session.commit()
        return delivery

    delivery.attempt_count += 1
    delivery.state = NotificationDeliveryState.SENDING
    delivery.last_attempt_at = attempted_at
    delivery.updated_at = attempted_at
    delivery.next_attempt_at = None
    session.add(delivery)
    session.commit()
    try:
        recipient = _locked_recipient(
            session,
            user,
            delivery.category,
            delivery.recipient_generation,
            cipher,
        )
        # Consent is locked above; reload all event state after the committed
        # SENDING transition so a payment settling during the lock cannot send
        # a stale warning alongside its successful renewal confirmation.
        session.expire_all()
        locked_user = session.get(User, user.id)
        subscription = (
            session.get(Subscription, delivery.subscription_id)
            if delivery.subscription_id is not None
            else None
        )
        payment = (
            session.get(Payment, delivery.payment_id) if delivery.payment_id is not None else None
        )
        if delivery.category == NotificationCategory.ACCOUNT and (
            locked_user is None
            or locked_user.is_suspended
            or not locked_user.has_notification_email
            or locked_user.notification_email_generation != delivery.recipient_generation
            or subscription is None
            or not account_event_still_eligible(
                session, delivery, subscription, payment, attempted_at
            )
        ):
            if fence_notification_lease(session, delivery, lease_token):
                cancel_notification(delivery, "notification_no_longer_eligible", attempted_at)
                session.add(delivery)
                session.commit()
            return delivery
        rendered = render_notification(
            delivery,
            subscription=subscription,
            payment=payment,
            announcement=announcement,
            user=locked_user,
            cipher=cipher,
            now=attempted_at,
        )
        adapter.send_message(
            recipient, rendered.subject, rendered.body, notification_message_id(delivery)
        )
    except CredentialError:
        if fence_notification_lease(session, delivery, lease_token):
            _terminal(
                delivery, NotificationDeliveryState.FAILED, "recipient_unavailable", attempted_at
            )
            session.add(delivery)
            session.commit()
        return delivery
    except SmtpDeliveryError as error:
        if not fence_notification_lease(session, delivery, lease_token):
            return delivery
        if error.ambiguous:
            _terminal(
                delivery,
                NotificationDeliveryState.DELIVERY_AMBIGUOUS,
                _sanitize_error_code(error.code),
                attempted_at,
            )
        elif error.retryable and delivery.attempt_count < MAX_NOTIFICATION_ATTEMPTS:
            delivery.state = NotificationDeliveryState.QUEUED
            delivery.error_code = _sanitize_error_code(error.code)
            delivery.updated_at = attempted_at
            delivery.next_attempt_at = attempted_at + _retry_delay(delivery.attempt_count)
        else:
            _terminal(
                delivery,
                NotificationDeliveryState.FAILED,
                _sanitize_error_code(error.code),
                attempted_at,
            )
        session.add(delivery)
        session.commit()
        return delivery
    except Exception:
        if fence_notification_lease(session, delivery, lease_token):
            _terminal(
                delivery, NotificationDeliveryState.FAILED, "smtp_internal_error", attempted_at
            )
            session.add(delivery)
            session.commit()
        return delivery

    if not fence_notification_lease(session, delivery, lease_token):
        return delivery
    _terminal(delivery, NotificationDeliveryState.SENT, "", attempted_at)
    delivery.error_code = None
    delivery.sent_at = attempted_at
    session.add(delivery)
    session.commit()
    return delivery


def notification_message_id(delivery: NotificationDelivery) -> str:
    """Return a stable Message-ID independent of SMTP configuration and content."""
    identity = f"{_MESSAGE_ID_VERSION}|{delivery.idempotency_key}|{delivery.recipient_generation}"
    digest = hashlib.sha256(identity.encode("ascii")).hexdigest()
    return f"<{digest}@blindport.invalid>"


def cancel_pending_notifications(
    session: Session,
    user: User,
    category: NotificationCategory,
    *,
    code: str = "notification_preference_changed",
    now: datetime | None = None,
) -> None:
    if user.id is None:
        return
    _cancel_queued(
        session,
        NotificationDelivery.user_id == user.id,
        NotificationDelivery.category == category,
        code=code,
        now=_aware(now or datetime.now(UTC)),
    )


def cancel_pending_announcement_notifications(
    session: Session,
    announcement_id: int,
    *,
    now: datetime | None = None,
) -> None:
    _cancel_queued(
        session,
        NotificationDelivery.announcement_id == announcement_id,
        code="announcement_cancelled",
        now=_aware(now or datetime.now(UTC)),
    )


def fence_notification_lease(
    session: Session,
    delivery: NotificationDelivery,
    expected_token: str | None,
) -> bool:
    """Atomically verify the lease owner before writing a SMTP result."""
    if expected_token is None or delivery.id is None:
        return True
    fenced_at = datetime.now(UTC)
    result = session.exec(
        update(NotificationDelivery)
        .where(
            NotificationDelivery.id == delivery.id,
            NotificationDelivery.lease_token == expected_token,
        )
        .values(
            lease_until=fenced_at
            + timedelta(seconds=config.settings.NOTIFICATION_DELIVERY_LEASE_SECONDS)
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount == 1:  # type: ignore[attr-defined]
        return True
    session.rollback()
    session.refresh(delivery)
    return False


def cancel_notification(delivery: NotificationDelivery, code: str, now: datetime) -> None:
    _terminal(
        delivery, NotificationDeliveryState.CANCELLED, _sanitize_error_code(code), _aware(now)
    )


def _reuse_queued_delivery(
    session: Session,
    delivery: NotificationDelivery,
    user_id: int,
    generation: int,
    category: NotificationCategory,
    kind: NotificationKind,
    subscription_id: int | None,
    payment_id: int | None,
    announcement_id: int | None,
    event_at: datetime | None,
) -> NotificationDelivery:
    if (
        delivery.user_id != user_id
        or delivery.category != category
        or delivery.kind != kind
        or delivery.subscription_id != subscription_id
        or delivery.payment_id != payment_id
        or delivery.announcement_id != announcement_id
        or _same_time(delivery.event_at, event_at) is False
    ):
        raise ValueError("notification idempotency key conflicts with another event")
    if delivery.state == NotificationDeliveryState.QUEUED and announcement_id is None:
        delivery.recipient_generation = generation
        session.add(delivery)
    return delivery


def _validate_notification_refs(
    category: NotificationCategory,
    kind: NotificationKind,
    subscription: Subscription | None,
    payment: Payment | None,
    announcement: Announcement | None,
    event_at: datetime | None,
) -> None:
    if category == NotificationCategory.ACCOUNT:
        if kind not in _ACCOUNT_KINDS or subscription is None or announcement is not None:
            raise ValueError("account notification references are invalid")
        if kind in _EXPIRATION_KINDS and event_at is None:
            raise ValueError("expiration notification requires an event time")
        if kind in (
            NotificationKind.AUTOMATIC_RENEWAL_FAILED,
            NotificationKind.AUTOMATIC_RENEWAL_UNCONFIRMED,
        ) and (
            event_at is None
            or (kind == NotificationKind.AUTOMATIC_RENEWAL_FAILED) != (payment is not None)
        ):
            raise ValueError("automatic renewal notification references are invalid")
        if kind == NotificationKind.SUBSCRIPTION_EXPIRED and payment is not None:
            raise ValueError("expired subscription notification cannot reference a payment")
        return
    if category == NotificationCategory.SERVICE:
        if (
            kind != NotificationKind.SERVICE_ANNOUNCEMENT
            or announcement is None
            or subscription is not None
            or payment is not None
            or event_at is not None
        ):
            raise ValueError("service notification references are invalid")
        return
    raise ValueError("notification category is invalid")


def _recipient_generation(user: User, category: NotificationCategory) -> int:
    if category not in (NotificationCategory.ACCOUNT, NotificationCategory.SERVICE):
        raise ValueError("notification category is invalid")
    if not user.has_notification_email or user.notification_email_generation < 1:
        raise ValueError("user has no notification recipient")
    return user.notification_email_generation


def _validate_recipient_generation_override(
    generation: int,
    category: NotificationCategory,
    kind: NotificationKind,
    announcement: Announcement | None,
) -> int:
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
        or category != NotificationCategory.SERVICE
        or kind != NotificationKind.SERVICE_ANNOUNCEMENT
        or announcement is None
    ):
        raise ValueError("notification recipient generation override is invalid")
    return generation


def _locked_recipient(
    session: Session,
    user: User,
    category: NotificationCategory,
    generation: int,
    cipher: CredentialCipher | None,
) -> str:
    if category not in (NotificationCategory.ACCOUNT, NotificationCategory.SERVICE):
        raise CredentialError("notification category is invalid")
    return lock_and_decrypt_notification_email(session, user.id, generation, cipher=cipher)


def _render_expiration(
    product: ProductType | None,
    period_end: datetime,
    rendered_at: datetime,
    resource_details: str,
) -> RenderedNotification:
    label = {
        ProductType.IP: "Blindport IP",
        ProductType.PORT: "Blindport Port",
        ProductType.RELAY: "Blindport Relay",
    }.get(product, "Blindport")
    remaining = _aware(period_end) - rendered_at
    deadline = _aware(period_end).strftime("%Y-%m-%d %H:%M UTC")
    if remaining <= timedelta(0):
        timing = "has expired"
    elif remaining <= timedelta(days=1):
        timing = "expires in less than one day"
    else:
        days = max(1, (remaining.days + (1 if remaining.seconds else 0)))
        timing = f"expires within {days} {'day' if days == 1 else 'days'}"
    return RenderedNotification(
        subject=f"{label} subscription {timing}",
        body=(
            f"Your {label} subscription is approaching the end of its paid period.\n\n"
            f"It {timing}, on {deadline}. Automatic renewal is not enabled.\n\n"
            f"{resource_details}\n\n"
            "Sign in to Blindport to renew it before expiration.\n\n"
            "This reminder was sent because expiration notices are enabled for your account."
        ),
    )


def _render_subscription_event(
    kind: NotificationKind,
    product: ProductType,
    event_at: datetime | None,
    *,
    automatic_renewal: bool = False,
    resource_details: str,
    rendered_at: datetime,
) -> RenderedNotification:
    label = {
        ProductType.IP: "Blindport IP",
        ProductType.PORT: "Blindport Port",
        ProductType.RELAY: "Blindport Relay",
    }[product]
    deadline = _aware(event_at).strftime("%Y-%m-%d %H:%M UTC") if event_at else None
    if kind == NotificationKind.SUBSCRIPTION_ACTIVATED:
        detail = f"Your {label} subscription is active."
        subject = "Blindport subscription activated"
        period_line = f"\n\nPaid through {deadline}." if deadline else ""
    elif kind == NotificationKind.SUBSCRIPTION_RENEWED:
        detail = (
            f"Your {label} subscription was automatically renewed."
            if automatic_renewal
            else f"Your {label} subscription has been renewed."
        )
        subject = (
            "Blindport subscription automatically renewed"
            if automatic_renewal
            else "Blindport subscription renewed"
        )
        period_line = f"\n\nPaid through {deadline}." if deadline else ""
    elif kind in (
        NotificationKind.AUTOMATIC_RENEWAL_FAILED,
        NotificationKind.AUTOMATIC_RENEWAL_UNCONFIRMED,
    ):
        failure = kind == NotificationKind.AUTOMATIC_RENEWAL_FAILED
        detail = (
            f"Automatic renewal failed for your {label} subscription. Check your payment settings."
            if failure
            else f"Automatic renewal is not yet confirmed for your {label} subscription."
        )
        subject = (
            "Blindport automatic renewal failed"
            if failure
            else "Blindport automatic renewal not yet confirmed"
        )
        remaining = _aware(event_at) - rendered_at if event_at else timedelta(0)
        period_line = (
            f"\n\nYour paid period ends on {deadline} "
            f"(about {max(1, math.ceil(remaining.total_seconds() / 3600))} hours remaining)."
            if remaining > timedelta(0) and deadline
            else f"\n\nYour paid period ended on {deadline}."
            if deadline
            else ""
        )
        period_line += (
            " Renew manually to restore or keep service."
            if failure
            else " Check your payment status before paying again; the automatic attempt may still succeed."
        )
    elif kind == NotificationKind.SUBSCRIPTION_EXPIRED:
        detail = f"Your {label} subscription has expired."
        subject = "Blindport subscription expired"
        period_line = (
            f"\n\nYour paid period ended on {deadline}. Renew to restore service."
            if deadline
            else "\n\nRenew to restore service."
        )
    else:
        raise ValueError("subscription notification kind is invalid")
    return RenderedNotification(
        subject=subject,
        body=(
            f"{detail}{period_line}\n\n{resource_details}\n\n"
            f"Sign in to Blindport: {config.settings.PUBLIC_SITE_URL}"
        ),
    )


def _resource_details(
    delivery: NotificationDelivery,
    subscription: Subscription | None,
    user: User | None,
    cipher: CredentialCipher | None,
) -> str:
    snapshot = snapshot_resource_identity(delivery, user, cipher=cipher)
    identity = snapshot[0] if snapshot is not None else None
    if (
        identity is None
        and delivery.resource_identity_ciphertext is None
        and delivery.resource_identity_key_version is None
        and subscription is not None
        and _same_time(delivery.event_at, subscription.current_period_end)
    ):
        identity = resource_identity(subscription)
    public_id = (
        snapshot[1]
        if snapshot is not None
        else str(subscription.public_id)
        if subscription is not None
        else "unavailable"
    )
    resource = identity or "Resource details unavailable"
    return f"{resource}\nSubscription ID: {public_id}"


def _cancel_queued(session: Session, *conditions: object, code: str, now: datetime) -> None:
    session.exec(
        update(NotificationDelivery)
        .where(NotificationDelivery.state == NotificationDeliveryState.QUEUED, *conditions)
        .values(
            state=NotificationDeliveryState.CANCELLED,
            error_code=_sanitize_error_code(code),
            updated_at=now,
            terminal_at=now,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )


def _terminal(
    delivery: NotificationDelivery,
    state: NotificationDeliveryState,
    error_code: str,
    recorded_at: datetime,
) -> None:
    delivery.state = state
    delivery.error_code = _sanitize_error_code(error_code) if error_code else None
    delivery.updated_at = recorded_at
    delivery.terminal_at = recorded_at
    delivery.next_attempt_at = None
    delivery.lease_token = None
    delivery.lease_until = None


def _retry_delay(attempt_count: int) -> timedelta:
    return timedelta(seconds=min(3600, 5 * 2 ** min(attempt_count, 10)))


def _validate_idempotency_key(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 255 or not value.isascii():
        raise ValueError("notification idempotency key is invalid")


def _sanitize_error_code(value: str) -> str:
    return value if _ERROR_CODE.fullmatch(value) else "notification_error"


def _ensure_plaintext_limits(subject: str, body: str) -> None:
    if len(subject) > 160 or len(body) > 10_000:
        raise ValueError("notification content exceeds plaintext limits")


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _same_time(left: datetime | None, right: datetime | None) -> bool:
    return (
        left is None
        and right is None
        or (left is not None and right is not None and _aware(left) == _aware(right))
    )
