"""End-to-end SMTP reminder reconciliation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select

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


class _Smtp:
    def __init__(self) -> None:
        self.calls = 0

    def send_message(self, recipient: str, subject: str, body: str, message_id: str) -> None:
        self.calls += 1
        assert recipient == "person@example.com"
        assert "expires" in subject
        assert "Sign in to Blindport" in body
        assert message_id.startswith("<")


def _setup(monkeypatch, tmp_path, *, period_delta: timedelta):
    from blindport import config
    from blindport.services import reminder_reconciliation

    local_engine = create_engine(f"sqlite:///{tmp_path / 'reminders.db'}")
    SQLModel.metadata.create_all(local_engine)
    monkeypatch.setattr(reminder_reconciliation.db, "engine", local_engine)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(config.settings, "SMTP_FROM_EMAIL", "notices@example.com")
    smtp = _Smtp()
    monkeypatch.setattr(reminder_reconciliation, "get_smtp_adapter", lambda: smtp)
    with Session(local_engine) as session:
        user = User(hashed_token="reminder-worker")
        store_reminder_email(user, "person@example.com")
        session.add(user)
        session.flush()
        session.add(
            Subscription(
                user_id=user.id,
                product=ProductType.IP,
                status=SubscriptionStatus.ACTIVE,
                monthly_price_sats=1000,
                current_period_end=datetime.now(UTC) + period_delta,
            )
        )
        session.commit()
    return reminder_reconciliation, local_engine, smtp


def test_reconciler_queues_and_sends_once(monkeypatch, tmp_path) -> None:
    worker, local_engine, smtp = _setup(monkeypatch, tmp_path, period_delta=timedelta(days=6))
    summary = worker.reconcile_reminders_once(batch_size=10)
    assert (summary.queued, summary.sent, smtp.calls) == (1, 1, 1)
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.kind == ReminderKind.SEVEN_DAY
        assert delivery.state == ReminderDeliveryState.SENT
        assert delivery.lease_token is None
    assert worker.reconcile_reminders_once(batch_size=10).queued == 0
    assert smtp.calls == 1


def test_same_period_queues_seven_and_one_day_notices(monkeypatch, tmp_path) -> None:
    worker, local_engine, _ = _setup(monkeypatch, tmp_path, period_delta=timedelta(days=6))
    with Session(local_engine) as session:
        period_end = session.exec(select(Subscription)).one().current_period_end
    assert period_end is not None
    period_end = period_end.replace(tzinfo=UTC) if period_end.tzinfo is None else period_end
    assert worker._queue_due_reminders(datetime.now(UTC), 10) == 1
    assert worker._queue_due_reminders(period_end - timedelta(hours=12), 10) == 1


def test_recovered_sending_boundary_is_terminal_without_duplicate_send(
    monkeypatch, tmp_path
) -> None:
    worker, local_engine, smtp = _setup(monkeypatch, tmp_path, period_delta=timedelta(days=6))
    now = datetime.now(UTC)
    assert worker._queue_due_reminders(now, 10) == 1
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        delivery.state = ReminderDeliveryState.SENDING
        delivery.attempt_count = 1
        session.add(delivery)
        session.commit()
    summary = worker.reconcile_reminders_once(batch_size=10)
    assert summary.failed == 1
    assert smtp.calls == 0
    with Session(local_engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.state == ReminderDeliveryState.DELIVERY_AMBIGUOUS
        assert delivery.error_code == "worker_interrupted"
