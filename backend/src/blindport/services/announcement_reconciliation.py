"""Bounded, leased SMTP delivery for queued service announcements."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from loguru import logger
from sqlalchemy import func, or_, update
from sqlmodel import Session, select

from .. import config, db
from ..core.models import (
    Announcement,
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    AnnouncementState,
    User,
)
from .announcements import (
    cancel_announcement_delivery,
    mark_announcement_completed_if_done,
    send_announcement,
)
from .reminder_reconciliation import get_smtp_adapter

_TERMINAL_STATES = (
    AnnouncementDeliveryState.SENT,
    AnnouncementDeliveryState.DELIVERY_AMBIGUOUS,
    AnnouncementDeliveryState.CANCELLED,
    AnnouncementDeliveryState.FAILED,
)
_PROCESSABLE_STATES = (AnnouncementDeliveryState.QUEUED, AnnouncementDeliveryState.SENDING)


@dataclass(frozen=True)
class AnnouncementReconciliationSummary:
    scanned: int = 0
    sent: int = 0
    pending: int = 0
    failed: int = 0


def _claim_due_delivery(now: datetime) -> tuple[int, str] | None:
    with Session(db.engine) as session:
        database_now = func.now() if session.get_bind().dialect.name == "postgresql" else now
        delivery_id = session.exec(
            select(AnnouncementDelivery.id)
            .join(Announcement)
            .where(
                Announcement.state == AnnouncementState.QUEUED,
                AnnouncementDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    AnnouncementDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    AnnouncementDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    AnnouncementDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    AnnouncementDelivery.lease_until <= database_now,
                ),
            )
            .order_by(AnnouncementDelivery.next_attempt_at, AnnouncementDelivery.id)
            .limit(1)
        ).first()
        if delivery_id is None:
            return None
        token = uuid4().hex
        result = session.exec(
            update(AnnouncementDelivery)
            .where(
                AnnouncementDelivery.id == delivery_id,
                AnnouncementDelivery.state.in_(_PROCESSABLE_STATES),  # type: ignore[union-attr]
                or_(
                    AnnouncementDelivery.next_attempt_at.is_(None),  # type: ignore[union-attr]
                    AnnouncementDelivery.next_attempt_at <= database_now,
                ),
                or_(
                    AnnouncementDelivery.lease_until.is_(None),  # type: ignore[union-attr]
                    AnnouncementDelivery.lease_until <= database_now,
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
            update(AnnouncementDelivery)
            .where(
                AnnouncementDelivery.id == delivery_id,
                AnnouncementDelivery.lease_token == token,
            )
            .values(lease_token=None, lease_until=None)
        )
        session.commit()


def _process_claimed_delivery(
    delivery_id: int, token: str, now: datetime
) -> AnnouncementDeliveryState:
    with Session(db.engine) as session:
        delivery = session.exec(
            select(AnnouncementDelivery)
            .where(
                AnnouncementDelivery.id == delivery_id, AnnouncementDelivery.lease_token == token
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if delivery is None:
            return AnnouncementDeliveryState.FAILED
        announcement = session.get(Announcement, delivery.announcement_id)
        user = session.get(User, delivery.user_id)
        if delivery.state == AnnouncementDeliveryState.SENDING:
            delivery.state = AnnouncementDeliveryState.DELIVERY_AMBIGUOUS
            delivery.error_code = "worker_interrupted"
            delivery.updated_at = now
            delivery.terminal_at = now
            delivery.next_attempt_at = None
            session.add(delivery)
            session.commit()
        elif announcement is None or user is None:
            delivery.state = AnnouncementDeliveryState.FAILED
            delivery.error_code = "recipient_unavailable"
            delivery.updated_at = now
            delivery.terminal_at = now
            session.add(delivery)
            session.commit()
        elif announcement.state != AnnouncementState.QUEUED:
            cancel_announcement_delivery(delivery, "announcement_cancelled", now)
            session.add(delivery)
            session.commit()
        elif not _is_delivery_eligible(delivery, user):
            cancel_announcement_delivery(delivery, "announcement_no_longer_eligible", now)
            session.add(delivery)
            session.commit()
        else:
            send_announcement(session, delivery, user, announcement, get_smtp_adapter(), now=now)
        mark_announcement_completed_if_done(session, delivery.announcement_id)
        return delivery.state


def reconcile_announcements_once(
    batch_size: int | None = None,
) -> AnnouncementReconciliationSummary:
    if not config.settings.ANNOUNCEMENT_EMAIL_ENABLED:
        return AnnouncementReconciliationSummary()
    effective_batch_size = (
        config.settings.PAYMENT_RECONCILIATION_BATCH_SIZE if batch_size is None else batch_size
    )
    if not 1 <= effective_batch_size <= 1000:
        raise ValueError("announcement reconciliation batch size must be within 1-1000")
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
            if state == AnnouncementDeliveryState.SENT:
                counts["sent"] += 1
            elif state in _TERMINAL_STATES:
                counts["failed"] += 1
            else:
                counts["pending"] += 1
        except Exception as error:
            counts["failed"] += 1
            logger.opt(exception=error).error(
                "announcement reconciliation failed for delivery_id={}", delivery_id
            )
        finally:
            _release_lease(delivery_id, token)
    return AnnouncementReconciliationSummary(**counts)


def _is_delivery_eligible(delivery: AnnouncementDelivery, user: User) -> bool:
    return bool(
        not user.is_admin
        and not user.is_suspended
        and user.has_notification_email
        and delivery.recipient_generation == user.notification_email_generation
    )
