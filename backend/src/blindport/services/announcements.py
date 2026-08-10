"""Encrypted service announcement preferences and durable SMTP delivery transitions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, insert, literal, union, update
from sqlmodel import Session, select

from .. import config
from ..adapters.smtp import SmtpAdapter, SmtpDeliveryError
from ..core.credentials import CredentialCipher, CredentialError
from ..core.models import (
    Announcement,
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    AnnouncementRecipientSnapshot,
    AnnouncementState,
    NotificationCategory,
    NotificationDelivery,
    NotificationDeliveryState,
    User,
)
from .notification_email import lock_and_decrypt_notification_email

MAX_ANNOUNCEMENT_ATTEMPTS = 20
_TERMINAL_DELIVERY_STATES = (
    AnnouncementDeliveryState.SENT,
    AnnouncementDeliveryState.DELIVERY_AMBIGUOUS,
    AnnouncementDeliveryState.CANCELLED,
    AnnouncementDeliveryState.FAILED,
)


class AnnouncementError(ValueError):
    """An announcement is invalid without reflecting its contents."""


def validate_announcement_content(subject: str, body: str) -> tuple[str, str]:
    if (
        not isinstance(subject, str)
        or not 1 <= len(subject) <= 160
        or "\r" in subject
        or "\n" in subject
        or any(not character.isprintable() for character in subject)
    ):
        raise AnnouncementError("announcement subject is invalid")
    normalized_body = body.replace("\r\n", "\n") if isinstance(body, str) else ""
    if (
        not 1 <= len(normalized_body) <= 10_000
        or "\r" in normalized_body
        or any(
            not character.isprintable() and character not in {"\n", "\t"}
            for character in normalized_body
        )
    ):
        raise AnnouncementError("announcement body is invalid")
    return subject, normalized_body


def create_announcement(
    session: Session, subject: str, body: str, author_marker: str
) -> Announcement:
    subject, body = validate_announcement_content(subject, body)
    if (
        not author_marker
        or len(author_marker) > 100
        or not author_marker.isascii()
        or not author_marker.isprintable()
    ):
        raise AnnouncementError("announcement author is invalid")
    announcement = Announcement(subject=subject, body=body, author_marker=author_marker)
    session.add(announcement)
    session.commit()
    session.refresh(announcement)
    return announcement


def eligible_recipient_count(session: Session) -> int:
    return int(
        session.exec(
            select(func.count())
            .select_from(User)
            .where(
                User.has_notification_email,
                User.notification_email_generation >= 1,
                User.is_admin.is_(False),  # type: ignore[union-attr]
                User.is_suspended.is_(False),  # type: ignore[union-attr]
            )
        ).one()
        or 0
    )


def queue_announcement(
    session: Session, announcement_id: int, *, now: datetime | None = None
) -> Announcement:
    announcement = session.exec(
        select(Announcement)
        .where(Announcement.id == announcement_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if announcement is None:
        raise AnnouncementError("announcement not found")
    if announcement.state == AnnouncementState.QUEUED:
        return announcement
    if announcement.state != AnnouncementState.DRAFT:
        raise AnnouncementError("announcement cannot be queued")
    queued_at = _aware(now or datetime.now(UTC))
    assert announcement.id is not None
    eligible_recipients = select(
        literal(announcement.id), User.id, User.notification_email_generation
    ).where(
        User.has_notification_email,
        User.notification_email_generation >= 1,
        User.is_admin.is_(False),  # type: ignore[union-attr]
        User.is_suspended.is_(False),  # type: ignore[union-attr]
    )
    session.exec(
        insert(AnnouncementRecipientSnapshot).from_select(
            ["announcement_id", "user_id", "recipient_generation"], eligible_recipients
        )
    )
    recipient_count, recipient_max_user_id = session.exec(
        select(
            func.count(),
            func.max(AnnouncementRecipientSnapshot.user_id),
        ).where(AnnouncementRecipientSnapshot.announcement_id == announcement.id)
    ).one()
    announcement.state = AnnouncementState.QUEUED
    announcement.queued_at = queued_at
    announcement.recipient_count = int(recipient_count or 0)
    announcement.recipient_cursor = 0
    announcement.recipient_max_user_id = recipient_max_user_id
    announcement.expansion_complete = announcement.recipient_count == 0
    session.add(announcement)
    if announcement.expansion_complete:
        announcement.state = AnnouncementState.COMPLETED
        announcement.completed_at = queued_at
        session.add(announcement)
    session.commit()
    session.refresh(announcement)
    return announcement


def cancel_announcement(
    session: Session, announcement_id: int, *, now: datetime | None = None
) -> Announcement:
    from .notifications import cancel_pending_announcement_notifications

    announcement = session.exec(
        select(Announcement)
        .where(Announcement.id == announcement_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if announcement is None:
        raise AnnouncementError("announcement not found")
    if announcement.state in (AnnouncementState.COMPLETED, AnnouncementState.CANCELLED):
        return announcement
    cancelled_at = _aware(now or datetime.now(UTC))
    announcement.state = AnnouncementState.CANCELLED
    announcement.cancelled_at = cancelled_at
    session.add(announcement)
    session.exec(
        update(AnnouncementDelivery)
        .where(
            AnnouncementDelivery.announcement_id == announcement.id,
            AnnouncementDelivery.state == AnnouncementDeliveryState.QUEUED,
        )
        .values(
            state=AnnouncementDeliveryState.CANCELLED,
            error_code="announcement_cancelled",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )
    cancel_pending_announcement_notifications(session, announcement.id or 0, now=cancelled_at)
    session.commit()
    session.refresh(announcement)
    return announcement


def cancel_pending_announcements(
    session: Session, user: User, *, now: datetime | None = None
) -> None:
    from .notifications import cancel_pending_notifications

    if user.id is None:
        return
    cancelled_at = _aware(now or datetime.now(UTC))
    session.exec(
        update(AnnouncementDelivery)
        .where(
            AnnouncementDelivery.user_id == user.id,
            AnnouncementDelivery.state == AnnouncementDeliveryState.QUEUED,
        )
        .values(
            state=AnnouncementDeliveryState.CANCELLED,
            error_code="announcement_preference_changed",
            updated_at=cancelled_at,
            terminal_at=cancelled_at,
            next_attempt_at=None,
            lease_token=None,
            lease_until=None,
        )
    )
    cancel_pending_notifications(
        session,
        user,
        NotificationCategory.SERVICE,
        code="announcement_preference_changed",
        now=cancelled_at,
    )


def cancel_announcement_delivery(
    delivery: AnnouncementDelivery,
    code: str,
    now: datetime,
) -> None:
    _terminal(delivery, AnnouncementDeliveryState.CANCELLED, code, _aware(now))


def send_announcement(
    session: Session,
    delivery: AnnouncementDelivery,
    user: User,
    announcement: Announcement,
    adapter: SmtpAdapter,
    *,
    cipher: CredentialCipher | None = None,
    now: datetime | None = None,
) -> AnnouncementDelivery:
    attempted_at = _aware(now or datetime.now(UTC))
    if delivery.state != AnnouncementDeliveryState.QUEUED:
        raise ValueError("announcement delivery is not queued")
    lease_token = delivery.lease_token
    if delivery.attempt_count >= MAX_ANNOUNCEMENT_ATTEMPTS:
        _terminal(delivery, AnnouncementDeliveryState.FAILED, "attempts_exhausted", attempted_at)
        session.add(delivery)
        session.commit()
        return delivery
    delivery.attempt_count += 1
    delivery.state = AnnouncementDeliveryState.SENDING
    delivery.last_attempt_at = attempted_at
    delivery.updated_at = attempted_at
    delivery.next_attempt_at = None
    session.add(delivery)
    session.commit()
    try:
        recipient = lock_and_decrypt_notification_email(
            session, user.id, delivery.recipient_generation, cipher=cipher
        )
        adapter.send_message(
            recipient,
            announcement.subject,
            announcement.body,
            announcement_message_id(delivery),
        )
    except CredentialError:
        if fence_announcement_lease(session, delivery, lease_token):
            _terminal(
                delivery, AnnouncementDeliveryState.FAILED, "recipient_unavailable", attempted_at
            )
            session.add(delivery)
            session.commit()
        return delivery
    except SmtpDeliveryError as error:
        if not fence_announcement_lease(session, delivery, lease_token):
            return delivery
        if error.ambiguous:
            _terminal(
                delivery, AnnouncementDeliveryState.DELIVERY_AMBIGUOUS, error.code, attempted_at
            )
        elif error.retryable and delivery.attempt_count < MAX_ANNOUNCEMENT_ATTEMPTS:
            delivery.state = AnnouncementDeliveryState.QUEUED
            delivery.error_code = error.code
            delivery.updated_at = attempted_at
            delivery.next_attempt_at = attempted_at + _retry_delay(delivery.attempt_count)
        else:
            _terminal(delivery, AnnouncementDeliveryState.FAILED, error.code, attempted_at)
        session.add(delivery)
        session.commit()
        return delivery
    except Exception:
        if fence_announcement_lease(session, delivery, lease_token):
            _terminal(
                delivery, AnnouncementDeliveryState.FAILED, "smtp_internal_error", attempted_at
            )
            session.add(delivery)
            session.commit()
        return delivery
    if not fence_announcement_lease(session, delivery, lease_token):
        return delivery
    delivery.state = AnnouncementDeliveryState.SENT
    delivery.error_code = None
    delivery.updated_at = attempted_at
    delivery.sent_at = attempted_at
    delivery.terminal_at = attempted_at
    delivery.next_attempt_at = None
    session.add(delivery)
    session.commit()
    return delivery


def announcement_message_id(delivery: AnnouncementDelivery) -> str:
    identity = f"{delivery.announcement_id}|{delivery.user_id}|{delivery.recipient_generation}"
    digest = hashlib.sha256(f"blindport-announcement-v1|{identity}".encode("ascii")).hexdigest()
    domain = config.settings.SMTP_FROM_EMAIL.rsplit("@", 1)[-1].lower()
    return f"<{digest}@{domain}>"


def fence_announcement_lease(
    session: Session,
    delivery: AnnouncementDelivery,
    expected_token: str | None,
) -> bool:
    if expected_token is None or delivery.id is None:
        return True
    fenced_at = datetime.now(UTC)
    result = session.exec(
        update(AnnouncementDelivery)
        .where(
            AnnouncementDelivery.id == delivery.id,
            AnnouncementDelivery.lease_token == expected_token,
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


def mark_announcement_completed_if_done(session: Session, announcement_id: int) -> None:
    announcement = session.get(Announcement, announcement_id)
    if announcement is None or announcement.state != AnnouncementState.QUEUED:
        return
    if not announcement.expansion_complete:
        return
    snapshot_exists = (
        session.exec(
            select(AnnouncementRecipientSnapshot.announcement_id)
            .where(AnnouncementRecipientSnapshot.announcement_id == announcement_id)
            .limit(1)
        ).first()
        is not None
    )
    if snapshot_exists:
        snapshot_count = int(
            session.exec(
                select(func.count()).where(
                    AnnouncementRecipientSnapshot.announcement_id == announcement_id
                )
            ).one()
            or 0
        )
        delivery_users = union(
            select(AnnouncementDelivery.user_id).where(
                AnnouncementDelivery.announcement_id == announcement_id
            ),
            select(NotificationDelivery.user_id).where(
                NotificationDelivery.announcement_id == announcement_id
            ),
        ).subquery()
        accounted_count = int(
            session.exec(
                select(func.count())
                .select_from(AnnouncementRecipientSnapshot)
                .join(
                    delivery_users,
                    AnnouncementRecipientSnapshot.user_id == delivery_users.c.user_id,
                )
                .where(AnnouncementRecipientSnapshot.announcement_id == announcement_id)
            ).one()
            or 0
        )
        if snapshot_count != announcement.recipient_count or accounted_count != snapshot_count:
            return
    unfinished = session.exec(
        select(AnnouncementDelivery.id).where(
            AnnouncementDelivery.announcement_id == announcement_id,
            AnnouncementDelivery.state.not_in(_TERMINAL_DELIVERY_STATES),  # type: ignore[union-attr]
        )
    ).first()
    unified_unfinished = session.exec(
        select(NotificationDelivery.id).where(
            NotificationDelivery.announcement_id == announcement_id,
            NotificationDelivery.state.not_in(
                (
                    NotificationDeliveryState.SENT,
                    NotificationDeliveryState.DELIVERY_AMBIGUOUS,
                    NotificationDeliveryState.CANCELLED,
                    NotificationDeliveryState.FAILED,
                    NotificationDeliveryState.EXPIRED,
                )
            ),  # type: ignore[union-attr]
        )
    ).first()
    if unfinished is None and unified_unfinished is None:
        announcement.state = AnnouncementState.COMPLETED
        announcement.completed_at = datetime.now(UTC)
        session.add(announcement)
        session.commit()


def _terminal(
    delivery: AnnouncementDelivery,
    state: AnnouncementDeliveryState,
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
