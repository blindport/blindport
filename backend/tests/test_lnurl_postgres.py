"""PostgreSQL concurrency regressions for LNURL payments and referral payouts."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete
from sqlmodel import Session, create_engine, select

from blindport.adapters.base import LightningInvoiceState
from blindport.adapters.lnurl import LnurlInvoice
from blindport.core.models import (
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    ReferralCredit,
    ReferralPayout,
    Subscription,
    SubscriptionStatus,
    User,
)
from blindport.migrations import upgrade_database
from blindport.services.payments import check_and_settle_payment, ensure_lightning_invoice
from blindport.services.referrals import (
    ReferralBalanceTooLowError,
    ReferralPayoutConflictError,
    list_referral_balances,
    mark_payout_paid,
    reserve_payout,
)

POSTGRES_URL = os.getenv("TEST_POSTGRES_DATABASE_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL test URL is not configured")


@pytest.fixture(scope="module")
def postgres_engine():
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    yield engine
    engine.dispose()


def _create_user_and_subscription(engine, marker: str) -> tuple[int, int]:
    now = datetime.now(UTC)
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        assert user.id is not None
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.PORT,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="198.51.100.252",
            assigned_port=45252,
            monthly_price_sats=20_000,
            yearly_price_sats=200_000,
            current_period_start=now,
            current_period_end=now + timedelta(days=5),
        )
        session.add(subscription)
        session.commit()
        assert subscription.id is not None
        return user.id, subscription.id


def _cleanup_user(engine, user_id: int) -> None:
    with Session(engine) as session:
        payment_ids = list(
            session.exec(
                select(Payment.id).join(Subscription).where(Subscription.user_id == user_id)
            ).all()
        )
        payout_ids = [
            payout_id
            for payout_id in session.exec(
                select(ReferralCredit.payout_id).where(ReferralCredit.payment_id.in_(payment_ids))
            ).all()
            if payout_id is not None
        ]
        if payment_ids:
            session.execute(
                delete(ReferralCredit).where(ReferralCredit.payment_id.in_(payment_ids))
            )
        if payout_ids:
            session.execute(delete(ReferralPayout).where(ReferralPayout.id.in_(payout_ids)))
        session.execute(delete(Payment).where(Payment.id.in_(payment_ids)))
        session.execute(delete(Subscription).where(Subscription.user_id == user_id))
        session.execute(delete(User).where(User.id == user_id))
        session.commit()


def _lnurl_payment(session: Session, subscription_id: int, **values: object) -> Payment:
    payment = Payment(
        subscription_id=subscription_id,
        method=PaymentMethod.LIGHTNING,
        amount_sats=20_000,
        service_price_sats=20_000,
        invoice_provider="lnurl",
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        **values,
    )
    session.add(payment)
    session.commit()
    assert payment.id is not None
    return payment


def _invoice(payment_hash: str) -> LnurlInvoice:
    return LnurlInvoice(
        payment_request=f"lnbc1lnurlrace{payment_hash[:16]}",
        payment_hash=payment_hash,
        amount_sats=20_000,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        verify_url=f"https://coinos.io/api/lnurl/verify/{payment_hash[:16]}",
        metadata='[["text/plain","Blindport PostgreSQL race test"]]',
    )


def test_postgres_lnurl_invoice_creation_attempt_is_single_and_durable(
    postgres_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = f"postgres-lnurl-create-{uuid4()}"
    user_id, subscription_id = _create_user_and_subscription(postgres_engine, marker)
    payment_hash = uuid4().hex
    with Session(postgres_engine) as session:
        payment = _lnurl_payment(session, subscription_id)
        payment_id = payment.id
    assert payment_id is not None

    from blindport.services import payments as payments_service

    provider_entered = threading.Event()
    release_provider = threading.Event()
    provider_lock = threading.Lock()
    provider_calls = 0
    invoice = _invoice(payment_hash)

    class SlowLnurlAdapter:
        def create_invoice(self, amount_sats: int) -> LnurlInvoice:
            nonlocal provider_calls
            assert amount_sats == 20_000
            with provider_lock:
                provider_calls += 1
            provider_entered.set()
            assert release_provider.wait(timeout=10)
            return invoice

    monkeypatch.setattr(payments_service, "get_lnurl_adapter", lambda: SlowLnurlAdapter())

    def issue() -> str | None:
        with Session(postgres_engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            return ensure_lightning_invoice(session, stored).invoice

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(issue)
            assert provider_entered.wait(timeout=10)
            with Session(postgres_engine) as session:
                pending = session.get(Payment, payment_id)
                assert pending is not None
                assert pending.lnurl_attempted_at is not None
                assert pending.invoice is None
            second = executor.submit(issue)
            assert second.result(timeout=10) is None
            assert provider_calls == 1
            release_provider.set()
            assert first.result(timeout=20) == invoice.payment_request

        with Session(postgres_engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            assert (
                stored.invoice,
                stored.payment_hash,
                stored.lnurl_verify_url,
                stored.lnurl_metadata,
            ) == (
                invoice.payment_request,
                invoice.payment_hash,
                invoice.verify_url,
                invoice.metadata,
            )
            assert ensure_lightning_invoice(session, stored).invoice == invoice.payment_request
        assert provider_calls == 1
    finally:
        release_provider.set()
        _cleanup_user(postgres_engine, user_id)


def test_postgres_lnurl_settlement_renews_once_and_credits_verified_receipt(
    postgres_engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = f"postgres-lnurl-settlement-{uuid4()}"
    user_id, subscription_id = _create_user_and_subscription(postgres_engine, marker)
    payment_hash = uuid4().hex
    with Session(postgres_engine) as session:
        subscription = session.get(Subscription, subscription_id)
        assert subscription is not None
        period_end = subscription.current_period_end
        assert period_end is not None
        payment = _lnurl_payment(
            session,
            subscription_id,
            referral_address="alice@wallet.co",
            referral_commission_bps=1_000,
        )
        payment_id = payment.id
    assert payment_id is not None

    from blindport.services import payments as payments_service

    verification_entered = threading.Event()
    release_verification = threading.Event()
    adapter_lock = threading.Lock()
    create_calls = 0
    verification_calls = 0
    invoice = _invoice(payment_hash)

    class SettledLnurlAdapter:
        def create_invoice(self, amount_sats: int) -> LnurlInvoice:
            nonlocal create_calls
            assert amount_sats == 20_000
            with adapter_lock:
                create_calls += 1
            return invoice

        def invoice_state(
            self,
            *,
            payment_request: str,
            payment_hash: str,
            verify_url: str,
        ) -> LightningInvoiceState:
            nonlocal verification_calls
            assert (payment_request, payment_hash, verify_url) == (
                invoice.payment_request,
                invoice.payment_hash,
                invoice.verify_url,
            )
            with adapter_lock:
                verification_calls += 1
            verification_entered.set()
            assert release_verification.wait(timeout=10)
            return LightningInvoiceState.SETTLED

    monkeypatch.setattr(payments_service, "get_lnurl_adapter", lambda: SettledLnurlAdapter())

    def settle() -> PaymentStatus:
        with Session(postgres_engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            return check_and_settle_payment(session, stored).status

    try:
        with Session(postgres_engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            assert ensure_lightning_invoice(session, stored).invoice == invoice.payment_request

        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(settle)
            assert verification_entered.wait(timeout=10)
            second = executor.submit(settle)
            assert second.result(timeout=10) == PaymentStatus.PENDING
            release_verification.set()
            assert first.result(timeout=20) == PaymentStatus.PAID

        with Session(postgres_engine) as session:
            stored_payment = session.get(Payment, payment_id)
            stored_subscription = session.get(Subscription, subscription_id)
            assert stored_payment is not None
            assert stored_subscription is not None
            assert stored_payment.status == PaymentStatus.PAID
            assert stored_payment.settlement_verified_at is not None
            assert not stored_payment.settlement_review_required
            assert stored_subscription.current_period_end == period_end + timedelta(days=30)
            credits = session.exec(
                select(ReferralCredit).where(ReferralCredit.payment_id == payment_id)
            ).all()
            assert [(credit.address, credit.amount_sats) for credit in credits] == [
                ("alice@wallet.co", 2_000)
            ]
        assert (create_calls, verification_calls) == (1, 1)
    finally:
        release_verification.set()
        _cleanup_user(postgres_engine, user_id)


def test_postgres_concurrent_payout_reservations_claim_one_balance(postgres_engine) -> None:
    marker = f"postgres-referral-reservation-{uuid4()}"
    address = "alice@wallet.co"
    user_id, subscription_id = _create_user_and_subscription(postgres_engine, marker)
    with Session(postgres_engine) as session:
        payments = [
            _lnurl_payment(session, subscription_id, status=PaymentStatus.PAID) for _ in range(2)
        ]
        session.add_all(
            [
                ReferralCredit(payment_id=payments[0].id, address=address, amount_sats=6_000),
                ReferralCredit(payment_id=payments[1].id, address=address, amount_sats=6_000),
            ]
        )
        session.commit()

    start = threading.Event()
    ready = [threading.Event(), threading.Event()]
    payout_ids = (uuid4(), uuid4())

    def reserve_once(payout_id: UUID, worker_ready: threading.Event) -> tuple[str, UUID]:
        with Session(postgres_engine) as session:
            worker_ready.set()
            assert start.wait(timeout=10)
            try:
                reserve_payout(session, payout_id=payout_id, address=address)
                session.commit()
                return "reserved", payout_id
            except (ReferralBalanceTooLowError, ReferralPayoutConflictError):
                session.rollback()
                return "conflict", payout_id

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(reserve_once, payout_id, worker_ready)
                for payout_id, worker_ready in zip(payout_ids, ready, strict=True)
            ]
            assert all(worker_ready.wait(timeout=10) for worker_ready in ready)
            start.set()
            results = [future.result(timeout=20) for future in futures]

        assert sorted(result for result, _ in results) == ["conflict", "reserved"]
        winner = next(payout_id for result, payout_id in results if result == "reserved")
        with Session(postgres_engine) as session:
            payouts = session.exec(select(ReferralPayout)).all()
            credits = session.exec(select(ReferralCredit).order_by(ReferralCredit.payment_id)).all()
            balances, total = list_referral_balances(session, offset=0, limit=10)
            assert [(payout.id, payout.amount_sats, payout.status) for payout in payouts] == [
                (winner, 12_000, "reserved")
            ]
            assert [credit.payout_id for credit in credits] == [winner, winner]
            assert total == 1
            assert [
                (balance.address, balance.available_sats, balance.reserved_sats, balance.paid_sats)
                for balance in balances
            ] == [(address, 0, 12_000, 0)]
    finally:
        _cleanup_user(postgres_engine, user_id)


def test_postgres_concurrent_paid_payout_replay_is_idempotent(postgres_engine) -> None:
    marker = f"postgres-referral-paid-{uuid4()}"
    address = "alice@wallet.co"
    user_id, subscription_id = _create_user_and_subscription(postgres_engine, marker)
    payout_id = uuid4()
    with Session(postgres_engine) as session:
        payment = _lnurl_payment(session, subscription_id, status=PaymentStatus.PAID)
        session.add(ReferralCredit(payment_id=payment.id, address=address, amount_sats=10_000))
        session.commit()
        reserve_payout(session, payout_id=payout_id, address=address)
        session.commit()

    start = threading.Event()
    ready = [threading.Event(), threading.Event()]
    reference = "postgres-ledger:2026-09-09"

    def mark_paid(worker_ready: threading.Event) -> tuple[str, str | None]:
        with Session(postgres_engine) as session:
            worker_ready.set()
            assert start.wait(timeout=10)
            payout = mark_payout_paid(
                session,
                payout_id=payout_id,
                external_reference=reference,
            )
            session.commit()
            return payout.status, payout.external_reference

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(mark_paid, worker_ready) for worker_ready in ready]
            assert all(worker_ready.wait(timeout=10) for worker_ready in ready)
            start.set()
            results = [future.result(timeout=20) for future in futures]

        assert results == [("paid", reference), ("paid", reference)]
        with Session(postgres_engine) as session:
            payout = session.get(ReferralPayout, payout_id)
            balances, total = list_referral_balances(session, offset=0, limit=10)
            assert payout is not None
            assert payout.status == "paid"
            assert payout.external_reference == reference
            assert payout.paid_at is not None
            assert total == 1
            assert [
                (balance.available_sats, balance.reserved_sats, balance.paid_sats)
                for balance in balances
            ] == [(0, 0, 10_000)]
    finally:
        _cleanup_user(postgres_engine, user_id)
