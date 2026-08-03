"""Bounded, leased reconciliation for paid expiration reminder delivery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import cache
from uuid import uuid4

from loguru import logger
from sqlalchemy import and_, func, or_, update
from sqlmodel import Session, select

from .. import config, db
from ..adapters.base import NwcAdapter, NwcAdapterError, NwcLookupState
from ..adapters.factory import get_nwc_adapter
from ..adapters.lnemail import LnemailAdapter
from ..core.models import (
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    User,
)
from .reminders import (
    begin_nwc_payment,
    cancel_reminder,
    create_reminder_invoice,
    decrypt_reminder_invoice,
    fence_reminder_lease,
    poll_reminder_status,
    queue_payment_reminder,
    record_nwc_payment_result,
)

_TERMINAL_STATES = (
    ReminderDeliveryState.DELIVERED,
    ReminderDeliveryState.CANCELLED,
    ReminderDeliveryState.FAILED,
    ReminderDeliveryState.EXPIRED,
    ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS,
)
_PROCESSABLE_STATES = (
    ReminderDeliveryState.QUEUED,
    ReminderDeliveryState.CREATING_INVOICE,
    ReminderDeliveryState.INVOICE_CREATED,
    ReminderDeliveryState.PAYING,
    ReminderDeliveryState.PAYMENT_AMBIGUOUS,
    ReminderDeliveryState.AWAITING_DELIVERY,
)


@dataclass(frozen=True)
class ReminderReconciliationSummary:
    queued: int = 0
    scanned: int = 0
    delivered: int = 0
    pending: int = 0
    failed: int = 0


@cache
def get_lnemail_adapter() -> LnemailAdapter:
    return LnemailAdapter(
        config.settings.LNEMAIL_BASE_URL,
        config.settings.LNEMAIL_ACCESS_TOKEN,
        timeout_seconds=config.settings.LNEMAIL_REQUEST_TIMEOUT_SECONDS,
    )


def reset_reminder_adapters_for_tests() -> None:
    get_lnemail_adapter.cache_clear()


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
                or_(
                    ReminderDelivery.state != ReminderDeliveryState.CANCELLED,
                    ReminderDelivery.payment_hash.is_not(None),  # type: ignore[union-attr]
                ),
            )
            .exists()
        )
        one_day_exists = (
            select(ReminderDelivery.id)
            .where(
                ReminderDelivery.subscription_id == Subscription.id,
                ReminderDelivery.current_period_end == Subscription.current_period_end,
                ReminderDelivery.kind == ReminderKind.ONE_DAY,
                or_(
                    ReminderDelivery.state != ReminderDeliveryState.CANCELLED,
                    ReminderDelivery.payment_hash.is_not(None),  # type: ignore[union-attr]
                ),
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
            queue_payment_reminder(session, subscription, kind)
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
            .where(
                ReminderDelivery.id == delivery_id,
                ReminderDelivery.lease_token == token,
            )
            .values(lease_token=None, lease_until=None)
        )
        session.commit()


def _fail(delivery: ReminderDelivery, code: str, now: datetime) -> None:
    delivery.state = ReminderDeliveryState.FAILED
    delivery.error_code = code
    delivery.updated_at = now
    delivery.terminal_at = now
    delivery.next_attempt_at = None
    delivery.lease_token = None
    delivery.lease_until = None
    delivery.invoice_ciphertext = None
    delivery.invoice_key_version = None


def _pay_invoice(
    session: Session,
    delivery: ReminderDelivery,
    user: User,
    nwc: NwcAdapter,
    now: datetime,
) -> None:
    if (
        not delivery.invoice_ciphertext
        or not delivery.invoice_key_version
        or not delivery.payment_hash
        or delivery.price_sats is None
        or delivery.price_sats > config.settings.LNEMAIL_MAX_SEND_PRICE_SATS
    ):
        _fail(delivery, "invoice_policy_rejected", now)
        session.add(delivery)
        session.commit()
        return
    try:
        invoice = decrypt_reminder_invoice(delivery, user)
    except ValueError:
        _fail(delivery, "invoice_unavailable", now)
        session.add(delivery)
        session.commit()
        return
    begin_nwc_payment(session, delivery, now=now)
    if delivery.state != ReminderDeliveryState.PAYING:
        return
    lease_token = delivery.lease_token
    try:
        result = nwc.pay_invoice(config.settings.LNEMAIL_ADMIN_NWC_URI, invoice)
    except NwcAdapterError as error:
        if not fence_reminder_lease(session, delivery, lease_token):
            return
        definitive = error.code in {
            "expired",
            "insufficient_balance",
            "invalid_request",
            "invalid_uri",
            "payment_failed",
            "quota_exceeded",
            "relay_not_allowed",
            "restricted",
            "unauthorized",
            "unsupported_capability",
            "unsupported_encryption",
        }
        result_state = "failed" if definitive else "unknown"
        record_nwc_payment_result(delivery, result_state, now=now)
        delivery.error_code = error.code
    else:
        if not fence_reminder_lease(session, delivery, lease_token):
            return
        bind_hash = getattr(nwc, "bind_payment_hash", None)
        if callable(bind_hash):
            bind_hash(invoice, delivery.payment_hash)
        record_nwc_payment_result(
            delivery,
            result.state.value,
            preimage=result.preimage,
            now=now,
        )
    session.add(delivery)
    session.commit()


def _lookup_ambiguous_payment(
    session: Session,
    delivery: ReminderDelivery,
    nwc: NwcAdapter,
    now: datetime,
    *,
    retry_allowed: bool,
    expected_lease_token: str | None = None,
) -> None:
    assert delivery.payment_hash is not None
    lease_token = expected_lease_token or delivery.lease_token
    try:
        result = nwc.lookup_invoice(config.settings.LNEMAIL_ADMIN_NWC_URI, delivery.payment_hash)
    except NwcAdapterError as error:
        if not fence_reminder_lease(session, delivery, lease_token):
            return
        delivery.error_code = error.code
        delivery.next_attempt_at = now + timedelta(
            seconds=config.settings.NWC_LOOKUP_INTERVAL_SECONDS
        )
    else:
        if not fence_reminder_lease(session, delivery, lease_token):
            return
        if result.payment_hash is not None and result.payment_hash != delivery.payment_hash:
            delivery.nwc_retry_blocked = True
            delivery.nwc_state = NwcLookupState.UNKNOWN.value
            delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
            delivery.error_code = "nwc_payment_hash_mismatch"
            delivery.next_attempt_at = now + timedelta(
                seconds=config.settings.NWC_LOOKUP_INTERVAL_SECONDS
            )
            delivery.updated_at = now
        elif result.preimage is not None or result.state == NwcLookupState.SETTLED:
            record_nwc_payment_result(
                delivery,
                "settled" if result.state == NwcLookupState.SETTLED else "unknown",
                preimage=result.preimage,
                now=now,
            )
        elif result.state in (NwcLookupState.NOT_FOUND, NwcLookupState.FAILED):
            delivery.nwc_state = result.state.value
            if not retry_allowed:
                cancel_reminder(delivery, "reminder_no_longer_eligible", now)
            elif delivery.nwc_retry_blocked:
                delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
                delivery.error_code = "nwc_settlement_unconfirmed"
                delivery.next_attempt_at = now + timedelta(
                    seconds=config.settings.NWC_LOOKUP_INTERVAL_SECONDS
                )
                delivery.updated_at = now
            else:
                delivery.state = ReminderDeliveryState.INVOICE_CREATED
                delivery.error_code = "nwc_payment_not_found"
                delivery.next_attempt_at = now + timedelta(
                    seconds=config.settings.NWC_RETRY_BASE_SECONDS
                )
                delivery.updated_at = now
        else:
            delivery.nwc_state = result.state.value
            delivery.state = ReminderDeliveryState.PAYMENT_AMBIGUOUS
            delivery.error_code = "nwc_payment_ambiguous"
            delivery.next_attempt_at = now + timedelta(
                seconds=config.settings.NWC_LOOKUP_INTERVAL_SECONDS
            )
            delivery.updated_at = now
    session.add(delivery)
    session.commit()


def _process_claimed_delivery(delivery_id: int, token: str, now: datetime) -> ReminderDeliveryState:
    lnemail = get_lnemail_adapter()
    nwc = get_nwc_adapter()
    with Session(db.engine) as session:
        snapshot = session.exec(
            select(ReminderDelivery).where(
                ReminderDelivery.id == delivery_id,
                ReminderDelivery.lease_token == token,
            )
        ).first()
        if snapshot is None:
            return ReminderDeliveryState.FAILED
        subscription_snapshot = session.get(Subscription, snapshot.subscription_id)
        if subscription_snapshot is None:
            delivery = session.exec(
                select(ReminderDelivery)
                .where(
                    ReminderDelivery.id == delivery_id,
                    ReminderDelivery.lease_token == token,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            ).first()
            if delivery is None:
                return ReminderDeliveryState.FAILED
            _fail(delivery, "recipient_unavailable", now)
            session.add(delivery)
            session.commit()
            return delivery.state
        user = session.exec(
            select(User)
            .where(User.id == subscription_snapshot.user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        subscription = session.exec(
            select(Subscription)
            .where(Subscription.id == snapshot.subscription_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        delivery = session.exec(
            select(ReminderDelivery)
            .where(
                ReminderDelivery.id == delivery_id,
                ReminderDelivery.lease_token == token,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if delivery is None:
            return ReminderDeliveryState.FAILED
        if subscription is None or user is None:
            _fail(delivery, "recipient_unavailable", now)
            session.add(delivery)
            session.commit()
            return delivery.state

        if delivery.state == ReminderDeliveryState.CREATING_INVOICE:
            delivery.state = ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS
            delivery.error_code = "worker_interrupted"
            delivery.terminal_at = now
            delivery.updated_at = now
            session.add(delivery)
            session.commit()
        elif delivery.state in (
            ReminderDeliveryState.QUEUED,
            ReminderDeliveryState.INVOICE_CREATED,
        ) and not _is_delivery_eligible(delivery, subscription, user, now):
            cancel_reminder(delivery, "reminder_no_longer_eligible", now)
            session.add(delivery)
            session.commit()
        elif delivery.state == ReminderDeliveryState.QUEUED:
            create_reminder_invoice(session, delivery, user, lnemail, now=now)
        elif delivery.state == ReminderDeliveryState.INVOICE_CREATED:
            _pay_invoice(session, delivery, user, nwc, now)
        elif delivery.state in (
            ReminderDeliveryState.PAYING,
            ReminderDeliveryState.PAYMENT_AMBIGUOUS,
        ):
            polled = poll_reminder_status(
                delivery,
                lnemail,
                session=session,
                lease_token=token,
                now=now,
            )
            if polled is None:
                return delivery.state
            session.add(delivery)
            session.commit()
            if delivery.state == ReminderDeliveryState.PAYMENT_AMBIGUOUS:
                _lookup_ambiguous_payment(
                    session,
                    delivery,
                    nwc,
                    now,
                    retry_allowed=_is_delivery_eligible(delivery, subscription, user, now),
                    expected_lease_token=token,
                )
        elif delivery.state == ReminderDeliveryState.AWAITING_DELIVERY:
            polled = poll_reminder_status(
                delivery,
                lnemail,
                session=session,
                lease_token=token,
                now=now,
            )
            if polled is None:
                return delivery.state
            session.add(delivery)
            session.commit()
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
    counts = {"scanned": 0, "delivered": 0, "pending": 0, "failed": 0}
    for _ in range(effective_batch_size):
        attempted_at = datetime.now(UTC)
        claim = _claim_due_delivery(attempted_at)
        if claim is None:
            break
        delivery_id, token = claim
        counts["scanned"] += 1
        try:
            state = _process_claimed_delivery(delivery_id, token, attempted_at)
            if state == ReminderDeliveryState.DELIVERED:
                counts["delivered"] += 1
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
    recipient_matches = (
        delivery.state != ReminderDeliveryState.QUEUED
        or delivery.recipient_generation == user.reminder_email_generation
    )
    return bool(
        subscription.status == SubscriptionStatus.ACTIVE
        and period_end is not None
        and _aware(period_end) == _aware(delivery.current_period_end)
        and _aware(period_end) > now
        and not user.is_suspended
        and user.has_reminder_email
        and recipient_matches
    )
