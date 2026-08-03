"""Encrypted reminder preferences and durable delivery state transitions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.headerregistry import Address
from typing import Literal

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .. import config
from ..adapters.lnemail import (
    LnemailAdapter,
    LnemailError,
    LnemailHTTPError,
    LnemailInvoice,
    LnemailProtocolError,
    LnemailStatus,
    LnemailTransportError,
)
from ..core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from ..core.models import (
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    User,
)

MAX_REMINDER_ATTEMPTS = 20
_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class ReminderEmailError(ValueError):
    """A reminder address is invalid or unavailable without reflecting it."""


@dataclass(frozen=True)
class RenderedReminder:
    subject: str
    body: str


def _cipher() -> CredentialCipher:
    return CredentialCipher(config.settings.CREDENTIAL_ENCRYPTION_KEY)


def normalize_reminder_email(value: str) -> str:
    """Return a conservative addr-spec with a canonical lowercase DNS domain."""
    if not isinstance(value, str) or not value or value.strip() != value:
        raise ReminderEmailError("reminder email address is invalid")
    if len(value) > 254 or not value.isascii() or any(character.isspace() for character in value):
        raise ReminderEmailError("reminder email address is invalid")
    if value.count("@") != 1:
        raise ReminderEmailError("reminder email address is invalid")
    local_part, domain = value.rsplit("@", 1)
    labels = domain.split(".")
    if (
        not 1 <= len(local_part) <= 64
        or not _LOCAL_PART.fullmatch(local_part)
        or len(labels) < 2
        or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels)
        or not labels[-1].isalpha()
        or len(labels[-1]) < 2
    ):
        raise ReminderEmailError("reminder email address is invalid")
    normalized = f"{local_part}@{domain.lower()}"
    try:
        parsed = Address(addr_spec=normalized)
    except (TypeError, ValueError):
        raise ReminderEmailError("reminder email address is invalid") from None
    if parsed.display_name or parsed.addr_spec != normalized:
        raise ReminderEmailError("reminder email address is invalid")
    return normalized


def store_reminder_email(
    user: User,
    email: str,
    *,
    cipher: CredentialCipher | None = None,
) -> str:
    normalized = normalize_reminder_email(email)
    encrypted = (cipher or _cipher()).encrypt(
        user.public_id,
        normalized,
        purpose=CredentialPurpose.REMINDER_EMAIL,
    )
    user.reminder_email_ciphertext = encrypted.ciphertext
    user.reminder_email_key_version = encrypted.key_version
    user.reminder_email_generation += 1
    user.has_reminder_email = True
    return normalized


def decrypt_reminder_email(
    user: User,
    expected_generation: int | None = None,
    *,
    cipher: CredentialCipher | None = None,
) -> str:
    if expected_generation is not None and user.reminder_email_generation != expected_generation:
        raise CredentialError("reminder email generation changed")
    if (
        not user.has_reminder_email
        or not user.reminder_email_ciphertext
        or not user.reminder_email_key_version
    ):
        raise CredentialError("reminder email is unavailable")
    plaintext = (cipher or _cipher()).decrypt(
        user.public_id,
        EncryptedCredential(
            user.reminder_email_ciphertext,
            user.reminder_email_key_version,
        ),
        purpose=CredentialPurpose.REMINDER_EMAIL,
    )
    try:
        return normalize_reminder_email(plaintext)
    except ReminderEmailError as error:
        raise CredentialError("reminder email plaintext is invalid") from error


def clear_reminder_email(user: User) -> None:
    if (
        not user.has_reminder_email
        and user.reminder_email_ciphertext is None
        and user.reminder_email_key_version is None
    ):
        return
    user.has_reminder_email = False
    user.reminder_email_ciphertext = None
    user.reminder_email_key_version = None
    user.reminder_email_generation += 1


def render_payment_reminder(kind: ReminderKind, current_period_end: datetime) -> RenderedReminder:
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


def queue_payment_reminder(
    session: Session,
    subscription: Subscription,
    kind: ReminderKind,
) -> ReminderDelivery:
    if subscription.id is None or subscription.current_period_end is None:
        raise ValueError("subscription must be persisted with a current period end")
    user = session.get(User, subscription.user_id)
    if user is None or not user.has_reminder_email or user.reminder_email_generation < 1:
        raise ValueError("subscription account has no reminder recipient")
    statement = select(ReminderDelivery).where(
        ReminderDelivery.subscription_id == subscription.id,
        ReminderDelivery.current_period_end == subscription.current_period_end,
        ReminderDelivery.kind == kind,
    )
    existing = session.exec(statement).first()
    if existing is not None:
        if existing.state == ReminderDeliveryState.QUEUED:
            existing.recipient_generation = user.reminder_email_generation
            session.add(existing)
        elif (
            existing.state == ReminderDeliveryState.CANCELLED
            and existing.invoice_ciphertext is None
            and existing.payment_hash is None
        ):
            existing.state = ReminderDeliveryState.QUEUED
            existing.recipient_generation = user.reminder_email_generation
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
        recipient_generation=user.reminder_email_generation,
        kind=kind,
    )
    try:
        with session.begin_nested():
            session.add(delivery)
            session.flush()
    except IntegrityError:
        existing = session.exec(statement).first()
        if existing is None:  # pragma: no cover - defensive against an unrelated constraint
            raise
        return existing
    return delivery


def create_reminder_invoice(
    session: Session,
    delivery: ReminderDelivery,
    user: User,
    adapter: LnemailAdapter,
    *,
    cipher: CredentialCipher | None = None,
    now: datetime | None = None,
) -> ReminderDelivery:
    attempted_at = _aware(now or datetime.now(UTC))
    if delivery.state != ReminderDeliveryState.QUEUED:
        raise ValueError("reminder delivery is not queued")
    lease_token = delivery.lease_token
    if not _start_attempt(delivery, ReminderDeliveryState.CREATING_INVOICE, attempted_at):
        session.add(delivery)
        session.commit()
        return delivery
    session.add(delivery)
    session.commit()

    try:
        recipient = decrypt_reminder_email(
            user,
            delivery.recipient_generation,
            cipher=cipher,
        )
        rendered = render_payment_reminder(delivery.kind, delivery.current_period_end)
        invoice = adapter.create_send_invoice(recipient, rendered.subject, rendered.body)
    except (LnemailTransportError, LnemailProtocolError) as error:
        if not fence_reminder_lease(session, delivery, lease_token):
            return delivery
        pre_request = isinstance(error, LnemailProtocolError) and error.code in {
            "invalid_request",
            "request_too_large",
        }
        _record_invoice_error(delivery, error, attempted_at, ambiguous=not pre_request)
        session.add(delivery)
        session.commit()
        return delivery
    except LnemailHTTPError as error:
        if not fence_reminder_lease(session, delivery, lease_token):
            return delivery
        request_rejected = error.status_code in {
            400,
            401,
            403,
            404,
            405,
            409,
            413,
            415,
            422,
            425,
            429,
        }
        _record_invoice_error(delivery, error, attempted_at, ambiguous=not request_rejected)
        session.add(delivery)
        session.commit()
        return delivery
    except CredentialError:
        if not fence_reminder_lease(session, delivery, lease_token):
            return delivery
        _terminal(delivery, ReminderDeliveryState.FAILED, "recipient_unavailable", attempted_at)
        session.add(delivery)
        session.commit()
        return delivery

    if not fence_reminder_lease(session, delivery, lease_token):
        return delivery
    _record_invoice(delivery, user, invoice, attempted_at, cipher=cipher)
    session.add(delivery)
    session.commit()
    return delivery


def begin_nwc_payment(
    session: Session,
    delivery: ReminderDelivery,
    *,
    now: datetime | None = None,
) -> ReminderDelivery:
    """Commit the payment side-effect boundary before calling an admin wallet."""
    attempted_at = _aware(now or datetime.now(UTC))
    if delivery.state != ReminderDeliveryState.INVOICE_CREATED:
        raise ValueError("reminder delivery is not ready for payment")
    if not _start_attempt(delivery, ReminderDeliveryState.PAYING, attempted_at):
        session.add(delivery)
        session.commit()
        return delivery
    session.add(delivery)
    session.commit()
    return delivery


def record_nwc_payment_result(
    delivery: ReminderDelivery,
    result: Literal["settled", "pending", "failed", "unknown"],
    *,
    preimage: str | None = None,
    now: datetime | None = None,
) -> None:
    recorded_at = _aware(now or datetime.now(UTC))
    if delivery.state not in {
        ReminderDeliveryState.INVOICE_CREATED,
        ReminderDeliveryState.PAYING,
        ReminderDeliveryState.PAYMENT_AMBIGUOUS,
    }:
        raise ValueError("reminder delivery has no payable invoice")
    delivery.updated_at = recorded_at
    delivery.last_attempt_at = recorded_at
    delivery.nwc_state = result
    if preimage is not None:
        preimage_hash = _settlement_preimage_hash(preimage)
        if preimage_hash != delivery.payment_hash:
            delivery.nwc_retry_blocked = True
            delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
            delivery.error_code = "nwc_preimage_mismatch"
            delivery.next_attempt_at = recorded_at + _retry_delay(delivery.attempt_count)
            return
        delivery.nwc_preimage_hash = preimage_hash
        delivery.nwc_retry_blocked = True
        delivery.nwc_state = "settled"
        result = "settled"
    if result == "settled":
        if delivery.nwc_preimage_hash != delivery.payment_hash:
            delivery.nwc_retry_blocked = True
            delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
            delivery.error_code = "nwc_settlement_unconfirmed"
            delivery.next_attempt_at = recorded_at + _retry_delay(delivery.attempt_count)
            return
        delivery.state = ReminderDeliveryState.AWAITING_DELIVERY
        delivery.paid_at = recorded_at
        delivery.error_code = None
        delivery.next_attempt_at = recorded_at
    elif result in {"pending", "unknown"}:
        delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
        delivery.error_code = "nwc_payment_ambiguous"
        delivery.next_attempt_at = recorded_at + _retry_delay(delivery.attempt_count)
    else:
        _terminal(delivery, ReminderDeliveryState.FAILED, "nwc_payment_failed", recorded_at)


def poll_reminder_status(
    delivery: ReminderDelivery,
    adapter: LnemailAdapter,
    *,
    session: Session | None = None,
    lease_token: str | None = None,
    now: datetime | None = None,
) -> ReminderDelivery | None:
    attempted_at = _aware(now or datetime.now(UTC))
    if not delivery.payment_hash:
        raise ValueError("reminder delivery has no payment hash")
    if delivery.state in {
        ReminderDeliveryState.DELIVERED,
        ReminderDeliveryState.CANCELLED,
        ReminderDeliveryState.FAILED,
        ReminderDeliveryState.EXPIRED,
        ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS,
    }:
        return delivery
    if not _start_attempt(delivery, delivery.state, attempted_at):
        return delivery
    try:
        status = adapter.send_status(delivery.payment_hash)
    except LnemailError as error:
        if session is not None and not fence_reminder_lease(session, delivery, lease_token):
            return None
        _record_retryable_error(delivery, error, attempted_at)
        return delivery
    if session is not None and not fence_reminder_lease(session, delivery, lease_token):
        return None
    _record_status(delivery, status, attempted_at)
    return delivery


def _record_invoice(
    delivery: ReminderDelivery,
    user: User,
    invoice: LnemailInvoice,
    recorded_at: datetime,
    *,
    cipher: CredentialCipher | None = None,
) -> None:
    encrypted = (cipher or _cipher()).encrypt(
        user.public_id,
        invoice.payment_request,
        purpose=CredentialPurpose.REMINDER_INVOICE,
    )
    delivery.invoice_ciphertext = encrypted.ciphertext
    delivery.invoice_key_version = encrypted.key_version
    delivery.payment_hash = invoice.payment_hash
    delivery.price_sats = invoice.price_sats
    delivery.provider = invoice.provider
    delivery.state = ReminderDeliveryState.INVOICE_CREATED
    delivery.invoice_created_at = recorded_at
    delivery.updated_at = recorded_at
    delivery.error_code = None
    delivery.next_attempt_at = None


def decrypt_reminder_invoice(
    delivery: ReminderDelivery,
    user: User,
    *,
    cipher: CredentialCipher | None = None,
) -> str:
    if not delivery.invoice_ciphertext or not delivery.invoice_key_version:
        raise CredentialError("reminder invoice is unavailable")
    return (cipher or _cipher()).decrypt(
        user.public_id,
        EncryptedCredential(delivery.invoice_ciphertext, delivery.invoice_key_version),
        purpose=CredentialPurpose.REMINDER_INVOICE,
    )


def cancel_unfunded_reminders(
    session: Session,
    user: User,
    *,
    now: datetime | None = None,
) -> None:
    """Cancel work that has not crossed an LNemail or NWC side-effect boundary."""
    if user.id is None:
        return
    cancelled_at = _aware(now or datetime.now(UTC))
    subscription_ids = select(Subscription.id).where(Subscription.user_id == user.id)
    session.exec(
        update(ReminderDelivery)
        .where(
            ReminderDelivery.subscription_id.in_(subscription_ids),  # type: ignore[union-attr]
            ReminderDelivery.state.in_(  # type: ignore[union-attr]
                (ReminderDeliveryState.QUEUED, ReminderDeliveryState.INVOICE_CREATED)
            ),
        )
        .values(
            state=ReminderDeliveryState.CANCELLED,
            error_code="reminders_disabled",
            invoice_ciphertext=None,
            invoice_key_version=None,
            payment_hash=None,
            price_sats=None,
            provider=None,
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


def _record_status(
    delivery: ReminderDelivery, status: LnemailStatus, recorded_at: datetime
) -> None:
    delivery.provider_payment_status = status.payment_status
    delivery.provider_delivery_status = status.delivery_status
    delivery.updated_at = recorded_at
    delivery.error_code = None
    if status.delivery_status == "sent":
        delivery.state = ReminderDeliveryState.DELIVERED
        delivery.paid_at = delivery.paid_at or recorded_at
        delivery.delivered_at = _aware(status.sent_at) if status.sent_at else recorded_at
        delivery.terminal_at = recorded_at
        delivery.next_attempt_at = None
        _scrub_invoice(delivery)
    elif status.payment_status == "expired" or status.delivery_status == "expired":
        _terminal(delivery, ReminderDeliveryState.EXPIRED, "provider_expired", recorded_at)
    elif status.payment_status == "failed" or status.delivery_status == "failed":
        _terminal(delivery, ReminderDeliveryState.FAILED, "provider_failed", recorded_at)
    else:
        if status.payment_status == "paid":
            delivery.state = ReminderDeliveryState.AWAITING_DELIVERY
            delivery.paid_at = delivery.paid_at or recorded_at
        else:
            delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
        delivery.next_attempt_at = recorded_at + _retry_delay(delivery.attempt_count)


def _start_attempt(
    delivery: ReminderDelivery,
    state: ReminderDeliveryState,
    attempted_at: datetime,
) -> bool:
    if delivery.attempt_count >= MAX_REMINDER_ATTEMPTS:
        _terminal(delivery, ReminderDeliveryState.FAILED, "attempts_exhausted", attempted_at)
        return False
    delivery.attempt_count += 1
    delivery.state = state
    delivery.last_attempt_at = attempted_at
    delivery.updated_at = attempted_at
    delivery.next_attempt_at = None
    return True


def _record_invoice_error(
    delivery: ReminderDelivery,
    error: LnemailError,
    recorded_at: datetime,
    *,
    ambiguous: bool,
) -> None:
    if ambiguous:
        _terminal(
            delivery,
            ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS,
            error.code,
            recorded_at,
        )
    else:
        _record_retryable_error(delivery, error, recorded_at)


def _record_retryable_error(
    delivery: ReminderDelivery, error: LnemailError, recorded_at: datetime
) -> None:
    delivery.error_code = error.code
    delivery.updated_at = recorded_at
    if error.retryable and delivery.attempt_count < MAX_REMINDER_ATTEMPTS:
        if delivery.state == ReminderDeliveryState.CREATING_INVOICE:
            delivery.state = ReminderDeliveryState.QUEUED
        delivery.next_attempt_at = recorded_at + _retry_delay(delivery.attempt_count)
    else:
        _terminal(delivery, ReminderDeliveryState.FAILED, error.code, recorded_at)


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
    _scrub_invoice(delivery)


def cancel_reminder(delivery: ReminderDelivery, code: str, now: datetime) -> None:
    _terminal(delivery, ReminderDeliveryState.CANCELLED, code, _aware(now))


def _settlement_preimage_hash(preimage: str) -> str | None:
    try:
        raw = bytes.fromhex(preimage)
    except ValueError:
        return None
    if len(raw) != 32:
        return None
    return hashlib.sha256(raw).hexdigest()


def _scrub_invoice(delivery: ReminderDelivery) -> None:
    delivery.invoice_ciphertext = None
    delivery.invoice_key_version = None


def _retry_delay(attempt_count: int) -> timedelta:
    return timedelta(seconds=min(3600, 5 * 2 ** min(attempt_count, 10)))


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
