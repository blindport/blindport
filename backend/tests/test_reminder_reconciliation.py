"""End-to-end state transitions for expiration reminder reconciliation."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select

from blindport.adapters.base import (
    NwcLookupResult,
    NwcLookupState,
    NwcPaymentState,
    NwcPayResult,
    NwcValidationResult,
)
from blindport.adapters.lnemail import LnemailInvoice, LnemailStatus
from blindport.core.models import (
    ProductType,
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    User,
)
from blindport.services.reminders import store_reminder_email


class _Lnemail:
    def __init__(self, payment_hash: str, price_sats: int = 100) -> None:
        self.payment_hash = payment_hash
        self.price_sats = price_sats
        self.create_calls = 0
        self.status_calls = 0

    def create_send_invoice(self, recipient: str, subject: str, body: str) -> LnemailInvoice:
        self.create_calls += 1
        assert recipient == "person@example.com"
        assert "expires" in subject
        assert "Sign in to Blindport" in body
        return LnemailInvoice("lnbc1reminder", self.payment_hash, self.price_sats, "provider")

    def send_status(self, payment_hash: str) -> LnemailStatus:
        self.status_calls += 1
        assert payment_hash == self.payment_hash
        return LnemailStatus("paid", "sent", datetime.now(UTC), 0)


class _Nwc:
    def __init__(self, preimage: str) -> None:
        self.preimage = preimage
        self.pay_calls = 0
        self.lookup_calls = 0

    def validate_connection(self, nwc_uri: str) -> NwcValidationResult:
        assert nwc_uri == "nostr+walletconnect://admin"
        return NwcValidationResult(("pay_invoice", "lookup_invoice"), ("nip44_v2",))

    def pay_invoice(self, nwc_uri: str, bolt11: str) -> NwcPayResult:
        self.pay_calls += 1
        assert bolt11 == "lnbc1reminder"
        return NwcPayResult(NwcPaymentState.SETTLED, self.preimage, 0)

    def lookup_invoice(self, nwc_uri: str, payment_hash: str) -> NwcLookupResult:
        self.lookup_calls += 1
        return NwcLookupResult(NwcLookupState.SETTLED, payment_hash, self.preimage, 0)


def _setup(monkeypatch, tmp_path, *, period_delta: timedelta, price_sats: int = 100):
    from blindport import config
    from blindport.services import reminder_reconciliation

    local_engine = create_engine(f"sqlite:///{tmp_path / 'reminders.db'}")
    SQLModel.metadata.create_all(local_engine)
    monkeypatch.setattr(reminder_reconciliation.db, "engine", local_engine)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(config.settings, "LNEMAIL_ADMIN_NWC_URI", "nostr+walletconnect://admin")
    monkeypatch.setattr(config.settings, "LNEMAIL_MAX_SEND_PRICE_SATS", 100)
    preimage = "42" * 32
    payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    lnemail = _Lnemail(payment_hash, price_sats)
    nwc = _Nwc(preimage)
    monkeypatch.setattr(reminder_reconciliation, "get_lnemail_adapter", lambda: lnemail)
    monkeypatch.setattr(reminder_reconciliation, "get_nwc_adapter", lambda: nwc)

    with Session(local_engine) as session:
        user = User(hashed_token="reminder-worker")
        store_reminder_email(user, "person@example.com")
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=datetime.now(UTC) + period_delta,
        )
        session.add(subscription)
        session.commit()
    return reminder_reconciliation, local_engine, lnemail, nwc


def test_reconciler_queues_pays_and_delivers_seven_day_notice(monkeypatch, tmp_path) -> None:
    worker, local_engine, lnemail, nwc = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
    )

    summary = worker.reconcile_reminders_once(batch_size=10)

    assert summary.queued == 1
    assert summary.delivered == 1
    assert (lnemail.create_calls, lnemail.status_calls, nwc.pay_calls) == (1, 1, 1)
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.kind == ReminderKind.SEVEN_DAY
        assert delivery.state == ReminderDeliveryState.DELIVERED
        assert delivery.lease_token is None

    repeated = worker.reconcile_reminders_once(batch_size=10)
    assert repeated.queued == 0
    assert lnemail.create_calls == 1


def test_reconciler_uses_one_day_notice_inside_final_day(monkeypatch, tmp_path) -> None:
    worker, local_engine, _, _ = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(hours=12),
    )

    worker.reconcile_reminders_once(batch_size=10)

    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.kind == ReminderKind.ONE_DAY


def test_same_paid_period_queues_distinct_seven_and_one_day_notices(monkeypatch, tmp_path) -> None:
    worker, local_engine, _, _ = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
    )
    with Session(local_engine) as session:
        subscription = session.exec(select(Subscription)).one()
        period_end = subscription.current_period_end
    assert period_end is not None
    period_end = period_end.replace(tzinfo=UTC) if period_end.tzinfo is None else period_end

    assert worker._queue_due_reminders(datetime.now(UTC), 10) == 1
    assert worker._queue_due_reminders(period_end - timedelta(hours=12), 10) == 1

    with Session(local_engine) as session:
        assert {delivery.kind for delivery in session.exec(select(ReminderDelivery)).all()} == {
            ReminderKind.SEVEN_DAY,
            ReminderKind.ONE_DAY,
        }


def test_reconciler_rejects_provider_invoice_over_operator_cap(monkeypatch, tmp_path) -> None:
    worker, local_engine, _, nwc = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
        price_sats=101,
    )

    summary = worker.reconcile_reminders_once(batch_size=10)

    assert summary.failed == 1
    assert nwc.pay_calls == 0
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.state == ReminderDeliveryState.FAILED
        assert delivery.error_code == "invoice_policy_rejected"


def test_due_queue_does_not_starve_later_subscriptions_at_batch_boundary(
    monkeypatch, tmp_path
) -> None:
    worker, local_engine, _, _ = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
    )
    period_end = datetime.now(UTC) + timedelta(days=6)
    with Session(local_engine) as session:
        for index in range(2):
            user = User(hashed_token=f"later-reminder-{index}")
            store_reminder_email(user, "person@example.com")
            session.add(user)
            session.flush()
            session.add(
                Subscription(
                    user_id=user.id,
                    product=ProductType.IP,
                    status=SubscriptionStatus.ACTIVE,
                    monthly_price_sats=1000,
                    current_period_end=period_end,
                )
            )
        session.commit()

    now = datetime.now(UTC)
    assert [worker._queue_due_reminders(now, 1) for _ in range(3)] == [1, 1, 1]
    with Session(local_engine) as session:
        assert len(session.exec(select(ReminderDelivery)).all()) == 3


def test_recovered_invoice_creation_boundary_is_terminal_without_duplicate_post(
    monkeypatch, tmp_path
) -> None:
    worker, local_engine, lnemail, _ = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
    )
    now = datetime.now(UTC)
    assert worker._queue_due_reminders(now, 10) == 1
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        delivery.state = ReminderDeliveryState.CREATING_INVOICE
        delivery.attempt_count = 1
        session.add(delivery)
        session.commit()

    summary = worker.reconcile_reminders_once(batch_size=10)

    assert summary.failed == 1
    assert lnemail.create_calls == 0
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.state == ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS
        assert delivery.error_code == "worker_interrupted"


def test_retry_blocked_settlement_is_never_returned_to_payable_state(monkeypatch, tmp_path) -> None:
    worker, local_engine, _, _ = _setup(
        monkeypatch,
        tmp_path,
        period_delta=timedelta(days=6),
    )

    class NotFoundNwc(_Nwc):
        def lookup_invoice(self, nwc_uri: str, payment_hash: str) -> NwcLookupResult:
            return NwcLookupResult(NwcLookupState.NOT_FOUND, payment_hash, None, None)

    with Session(local_engine) as session:
        subscription = session.exec(select(Subscription)).one()
        delivery = ReminderDelivery(
            subscription_id=subscription.id,
            current_period_end=subscription.current_period_end,
            recipient_generation=1,
            kind=ReminderKind.SEVEN_DAY,
            state=ReminderDeliveryState.PAYMENT_AMBIGUOUS,
            payment_hash="ab" * 32,
            nwc_retry_blocked=True,
        )
        session.add(delivery)
        session.commit()
        worker._lookup_ambiguous_payment(
            session,
            delivery,
            NotFoundNwc("42" * 32),
            datetime.now(UTC),
            retry_allowed=True,
        )
        assert delivery.state == ReminderDeliveryState.PAYMENT_AMBIGUOUS
        assert delivery.error_code == "nwc_settlement_unconfirmed"
