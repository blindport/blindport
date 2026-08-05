"""Background reconciliation for provider-backed pending payments."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from loguru import logger
from sqlalchemy import and_, or_
from sqlmodel import Session, select

from ..config import settings
from ..core.models import (
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..db import engine
from .domain_verification import get_domain_verifier
from .payments import check_and_settle_payment, create_payment
from .reminder_reconciliation import reconcile_reminders_once
from .subscriptions import (
    reap_expired_domain_claims,
    uses_unique_cname_target,
    verify_subscription_domain,
)


@dataclass(frozen=True)
class ReconciliationSummary:
    """Sanitized counts from one bounded database scan."""

    scanned: int = 0
    paid: int = 0
    expired: int = 0
    pending: int = 0
    skipped: int = 0
    failed: int = 0
    auto_renewed: int = 0
    reminders_queued: int = 0
    reminders_sent: int = 0


def _create_due_auto_renewals(batch_size: int) -> tuple[int, int]:
    if not settings.is_payment_method_enabled(PaymentMethod.NWC):
        return 0, 0
    due_before = datetime.now(UTC) + timedelta(seconds=settings.NWC_AUTO_RENEW_LEAD_SECONDS)
    with Session(engine) as session:
        subscription_pks = list(
            session.exec(
                select(Subscription.id)
                .join(User, User.id == Subscription.user_id)
                .where(
                    Subscription.auto_renew,
                    Subscription.status == SubscriptionStatus.ACTIVE,
                    Subscription.current_period_end.is_not(None),  # type: ignore[union-attr]
                    Subscription.current_period_end <= due_before,  # type: ignore[operator]
                    User.has_nwc,
                    User.is_admin.is_(False),  # type: ignore[union-attr]
                    User.is_suspended.is_(False),  # type: ignore[union-attr]
                )
                .order_by(Subscription.current_period_end, Subscription.id)
                .limit(batch_size)
            ).all()
        )
    created = 0
    failed = 0
    for subscription_pk in subscription_pks:
        public_id = "unknown"
        try:
            with Session(engine) as session:
                subscription = session.get(Subscription, subscription_pk)
                if subscription is not None:
                    public_id = str(subscription.public_id)
                period_end = (
                    _aware(subscription.current_period_end) if subscription is not None else None
                )
                if (
                    subscription is None
                    or not subscription.auto_renew
                    or subscription.status != SubscriptionStatus.ACTIVE
                    or period_end is None
                    or period_end > due_before
                ):
                    continue
                user = session.get(User, subscription.user_id)
                if user is None or not user.has_nwc or user.is_admin or user.is_suspended:
                    continue
                open_payment = session.exec(
                    select(Payment.id).where(
                        Payment.subscription_id == subscription.id,
                        Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
                    )
                ).first()
                if open_payment is not None:
                    continue
                if (
                    subscription.product == ProductType.RELAY
                    and not subscription.domain_is_managed
                    and uses_unique_cname_target(subscription)
                ):
                    verification = verify_subscription_domain(
                        session,
                        subscription,
                        get_domain_verifier,
                        force=True,
                    )
                    if not verification.verified:
                        continue
                user = session.exec(
                    select(User)
                    .where(User.id == subscription.user_id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                ).one_or_none()
                session.refresh(subscription)
                period_end = _aware(subscription.current_period_end)
                if (
                    user is None
                    or not user.has_nwc
                    or user.is_admin
                    or user.is_suspended
                    or not subscription.auto_renew
                    or subscription.status != SubscriptionStatus.ACTIVE
                    or period_end is None
                    or period_end > due_before
                ):
                    continue
                open_payment = session.exec(
                    select(Payment.id).where(
                        Payment.subscription_id == subscription.id,
                        Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
                    )
                ).first()
                if open_payment is not None:
                    continue
                create_payment(
                    session,
                    subscription,
                    PaymentMethod.NWC,
                    subscription.billing_term,
                )
                created += 1
        except ValueError:
            # An open payment won the uniqueness race or the subscription stopped
            # being eligible between the bounded scan and the locked create path.
            continue
        except Exception as error:
            failed += 1
            logger.opt(exception=error).error(
                "automatic renewal failed for subscription_id={}", public_id
            )
    return created, failed


def _aware(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class ReconcilerHealth:
    """Small locked state shared by the worker thread and readiness requests."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._enabled = False
        self._started_at: float | None = None
        self._last_completed_at: float | None = None
        self._startup_grace_seconds = 0.0
        self._stale_after_seconds = 0.0

    def configure(
        self,
        *,
        enabled: bool,
        startup_grace_seconds: float,
        stale_after_seconds: float,
    ) -> None:
        now = self._clock()
        with self._lock:
            self._enabled = enabled
            self._started_at = now if enabled else None
            self._last_completed_at = None
            self._startup_grace_seconds = startup_grace_seconds
            self._stale_after_seconds = stale_after_seconds

    def record_completed_cycle(self) -> None:
        with self._lock:
            self._last_completed_at = self._clock()

    def status(self, *, now: float | None = None) -> str:
        checked_at = self._clock() if now is None else now
        with self._lock:
            if not self._enabled:
                return "disabled"
            if self._started_at is None:
                return "unavailable"
            if self._last_completed_at is None:
                elapsed = checked_at - self._started_at
                return "starting" if elapsed <= self._startup_grace_seconds else "unavailable"
            if checked_at - self._last_completed_at > self._stale_after_seconds:
                return "unavailable"
            return "ok"


reconciler_health = ReconcilerHealth()


def reconcile_pending_payments_once(batch_size: int | None = None) -> ReconciliationSummary:
    """Reconcile one deterministic bounded batch, isolating each payment in its own session."""
    effective_batch_size = (
        settings.PAYMENT_RECONCILIATION_BATCH_SIZE if batch_size is None else batch_size
    )
    if not 1 <= effective_batch_size <= 1000:
        raise ValueError("payment reconciliation batch size must be within 1-1000")

    with Session(engine) as session:
        reap_expired_domain_claims(session)

    reconcilable_methods = tuple(
        method
        for method in (
            PaymentMethod.LIGHTNING,
            PaymentMethod.NWC,
            PaymentMethod.STABLECOIN_SWAP,
        )
        if method == PaymentMethod.STABLECOIN_SWAP or settings.is_payment_method_enabled(method)
    )
    if not reconcilable_methods and not settings.REMINDER_EMAIL_ENABLED:
        return ReconciliationSummary()

    now = datetime.now(UTC)
    nwc_lookup_before = now - timedelta(seconds=settings.NWC_LOOKUP_INTERVAL_SECONDS)
    payment_ids: list[int] = []
    if reconcilable_methods:
        with Session(engine) as session:
            payment_ids = list(
                session.exec(
                    select(Payment.id)
                    .where(
                        Payment.status == PaymentStatus.PENDING,
                        Payment.method.in_(reconcilable_methods),  # type: ignore[union-attr]
                        or_(
                            Payment.method != PaymentMethod.NWC,
                            and_(
                                or_(
                                    Payment.nwc_lease_until.is_(None),  # type: ignore[union-attr]
                                    Payment.nwc_lease_until <= now,
                                ),
                                or_(
                                    Payment.nwc_attempt_count == 0,
                                    Payment.nwc_last_lookup_at.is_(None),  # type: ignore[union-attr]
                                    Payment.nwc_last_lookup_at <= nwc_lookup_before,
                                ),
                            ),
                        ),
                    )
                    .order_by(Payment.id)
                    .limit(effective_batch_size)
                ).all()
            )

    counts = {
        "paid": 0,
        "expired": 0,
        "pending": 0,
        "skipped": 0,
        "failed": 0,
    }
    for payment_id in payment_ids:
        try:
            with Session(engine) as session:
                payment = session.get(Payment, payment_id)
                if payment is None:
                    counts["skipped"] += 1
                    continue
                if (
                    payment.method != PaymentMethod.STABLECOIN_SWAP
                    and not settings.is_payment_method_enabled(payment.method)
                ):
                    counts["skipped"] += 1
                    continue
                reconciled = check_and_settle_payment(session, payment)
                if reconciled.status == PaymentStatus.PAID:
                    counts["paid"] += 1
                elif reconciled.status == PaymentStatus.EXPIRED:
                    counts["expired"] += 1
                elif reconciled.status == PaymentStatus.PENDING:
                    counts["pending"] += 1
                else:
                    counts["skipped"] += 1
        except Exception as error:
            counts["failed"] += 1
            logger.opt(exception=error).error(
                "payment reconciliation failed for payment_id={}", payment_id
            )

    auto_renewed, auto_failed = _create_due_auto_renewals(effective_batch_size)
    counts["failed"] += auto_failed
    reminders = reconcile_reminders_once(effective_batch_size)
    counts["failed"] += reminders.failed
    return ReconciliationSummary(
        scanned=len(payment_ids),
        auto_renewed=auto_renewed,
        reminders_queued=reminders.queued,
        reminders_sent=reminders.sent,
        **counts,
    )


async def run_payment_reconciler(
    stop_event: asyncio.Event,
    *,
    reconcile_once: Callable[[], ReconciliationSummary] = reconcile_pending_payments_once,
    interval_seconds: float | None = None,
) -> None:
    """Run prompt fixed-rate reconciliation cycles until shutdown is requested."""
    interval = (
        settings.PAYMENT_RECONCILIATION_INTERVAL_SECONDS
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
            logger.opt(exception=error).error("payment reconciliation cycle failed")
        else:
            reconciler_health.record_completed_cycle()
            logger.debug(
                "payment reconciliation cycle complete: scanned={}, paid={}, expired={}, "
                "pending={}, skipped={}, failed={}, auto_renewed={}, reminders_queued={}, "
                "reminders_sent={}",
                summary.scanned,
                summary.paid,
                summary.expired,
                summary.pending,
                summary.skipped,
                summary.failed,
                summary.auto_renewed,
                summary.reminders_queued,
                summary.reminders_sent,
            )

        next_cycle_at += interval
        now = time.monotonic()
        if next_cycle_at <= now:
            # Skip missed ticks after a slow provider cycle instead of running
            # catch-up scans in a hot loop.
            next_cycle_at = now + interval
        delay = next_cycle_at - now
        with suppress(TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=delay)
