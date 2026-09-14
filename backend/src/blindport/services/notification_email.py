"""One encrypted notification recipient preference shared by all email categories."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from email.headerregistry import Address

from sqlalchemy import update
from sqlmodel import Session, select

from .. import config
from ..core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from ..core.models import (
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    NotificationDelivery,
    NotificationDeliveryState,
    ReminderDelivery,
    ReminderDeliveryState,
    Subscription,
    User,
)

_LOCAL_PART = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*")
_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")


class NotificationEmailError(ValueError):
    """A notification address is invalid without reflecting its value."""


def _cipher() -> CredentialCipher:
    return CredentialCipher(config.settings.CREDENTIAL_ENCRYPTION_KEY)


def normalize_notification_email(value: str) -> str:
    """Return a conservative addr-spec with a canonical lowercase DNS domain."""
    if not isinstance(value, str) or not value or value.strip() != value:
        raise NotificationEmailError("notification email address is invalid")
    if len(value) > 254 or not value.isascii() or any(character.isspace() for character in value):
        raise NotificationEmailError("notification email address is invalid")
    if value.count("@") != 1:
        raise NotificationEmailError("notification email address is invalid")
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
        raise NotificationEmailError("notification email address is invalid")
    normalized = f"{local_part}@{domain.lower()}"
    try:
        parsed = Address(addr_spec=normalized)
    except (TypeError, ValueError):
        raise NotificationEmailError("notification email address is invalid") from None
    if parsed.display_name or parsed.addr_spec != normalized:
        raise NotificationEmailError("notification email address is invalid")
    return normalized


def store_notification_email(
    user: User, email: str, *, cipher: CredentialCipher | None = None
) -> str:
    normalized = normalize_notification_email(email)
    encrypted = (cipher or _cipher()).encrypt(
        user.public_id, normalized, purpose=CredentialPurpose.NOTIFICATION_EMAIL
    )
    user.notification_email_ciphertext = encrypted.ciphertext
    user.notification_email_key_version = encrypted.key_version
    user.notification_email_generation += 1
    user.has_notification_email = True
    return normalized


def decrypt_notification_email(
    user: User,
    expected_generation: int | None = None,
    *,
    cipher: CredentialCipher | None = None,
) -> str:
    if (
        expected_generation is not None
        and user.notification_email_generation != expected_generation
    ):
        raise CredentialError("notification email generation changed")
    if (
        not user.has_notification_email
        or not user.notification_email_ciphertext
        or not user.notification_email_key_version
    ):
        raise CredentialError("notification email is unavailable")
    plaintext = (cipher or _cipher()).decrypt(
        user.public_id,
        EncryptedCredential(
            user.notification_email_ciphertext, user.notification_email_key_version
        ),
        purpose=CredentialPurpose.NOTIFICATION_EMAIL,
    )
    try:
        return normalize_notification_email(plaintext)
    except NotificationEmailError as error:
        raise CredentialError("notification email plaintext is invalid") from error


def lock_and_decrypt_notification_email(
    session: Session,
    user_id: int | None,
    expected_generation: int,
    *,
    cipher: CredentialCipher | None = None,
) -> str:
    """Lock the preference row through the caller's SMTP transaction."""
    if user_id is None:
        raise CredentialError("notification email is unavailable")
    user = session.exec(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if user is None:
        raise CredentialError("notification email is unavailable")
    return decrypt_notification_email(user, expected_generation, cipher=cipher)


def clear_notification_email(user: User) -> None:
    user.has_notification_email = False
    user.notification_email_ciphertext = None
    user.notification_email_key_version = None
    user.notification_email_generation += 1


def cancel_pending_notification_email_deliveries(
    session: Session, user: User, *, now: datetime | None = None
) -> None:
    if user.id is None:
        return
    cancelled_at = _aware(now or datetime.now(UTC))
    session.exec(
        update(NotificationDelivery)
        .where(
            NotificationDelivery.user_id == user.id,
            NotificationDelivery.state == NotificationDeliveryState.QUEUED,
        )
        .values(
            state=NotificationDeliveryState.CANCELLED,
            error_code="notification_preference_changed",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )
    session.exec(
        update(AnnouncementDelivery)
        .where(
            AnnouncementDelivery.user_id == user.id,
            AnnouncementDelivery.state == AnnouncementDeliveryState.QUEUED,
        )
        .values(
            state=AnnouncementDeliveryState.CANCELLED,
            error_code="notification_preference_changed",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )
    subscription_ids = select(Subscription.id).where(Subscription.user_id == user.id)
    session.exec(
        update(ReminderDelivery)
        .where(
            ReminderDelivery.subscription_id.in_(subscription_ids),  # type: ignore[union-attr]
            ReminderDelivery.state == ReminderDeliveryState.QUEUED,
        )
        .values(
            state=ReminderDeliveryState.CANCELLED,
            error_code="notification_preference_changed",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
