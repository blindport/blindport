"""Focused unified notification outbox and reconciliation coverage."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine, update
from sqlmodel import Session, SQLModel, select

from blindport.adapters.smtp import SmtpDeliveryError
from blindport.core.models import (
    Announcement,
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    AnnouncementRecipientSnapshot,
    NotificationCategory,
    NotificationDelivery,
    NotificationDeliveryState,
    NotificationKind,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    User,
)
from blindport.services.announcements import (
    cancel_announcement,
    create_announcement,
    queue_announcement,
    store_service_announcement_email,
)
from blindport.services.notifications import (
    notification_message_id,
    queue_notification,
    render_notification,
    send_notification,
)
from blindport.services.reminders import clear_reminder_email, store_reminder_email


class _Smtp:
    def __init__(self, error: SmtpDeliveryError | None = None) -> None:
        self.error = error
        self.calls = 0

    def send_message(self, recipient: str, subject: str, body: str, message_id: str) -> None:
        self.calls += 1
        assert recipient == "person@example.com"
        assert subject
        assert body
        assert message_id.startswith("<")
        if self.error is not None:
            raise self.error


def _setup(tmp_path, *, period_delta: timedelta = timedelta(days=6)) -> tuple[object, int, int]:
    engine = create_engine(f"sqlite:///{tmp_path / 'notifications.db'}")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        user = User(hashed_token="notification-user")
        store_reminder_email(user, "person@example.com")
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id or 0,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=datetime.now(UTC) + period_delta,
        )
        session.add(subscription)
        session.commit()
        return engine, user.id or 0, subscription.id or 0


def _queue_expiration(
    session: Session, user: User, subscription: Subscription, key: str
) -> NotificationDelivery:
    assert subscription.current_period_end is not None
    return queue_notification(
        session,
        user,
        NotificationCategory.ACCOUNT,
        NotificationKind.EXPIRATION_7_DAY,
        key,
        subscription=subscription,
        event_at=subscription.current_period_end,
    )


def test_outbox_schema_excludes_recipient_and_message_material(tmp_path) -> None:
    engine, _, _ = _setup(tmp_path)
    columns = {column.name for column in NotificationDelivery.__table__.columns}
    assert columns.isdisjoint(
        {"recipient", "email", "subject", "body", "invoice", "token", "domain", "ip"}
    )
    snapshot_columns = {column.name for column in AnnouncementRecipientSnapshot.__table__.columns}
    assert snapshot_columns == {"announcement_id", "user_id", "recipient_generation"}
    with Session(engine) as session:
        assert session.exec(select(NotificationDelivery)).all() == []


def test_queue_is_idempotent_and_uses_account_generation(tmp_path) -> None:
    engine, user_id, subscription_id = _setup(tmp_path)
    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        first = _queue_expiration(session, user, subscription, "expiration:one")
        second = _queue_expiration(session, user, subscription, "expiration:one")
        session.commit()
        assert first is second
        assert first.recipient_generation == user.reminder_email_generation
        assert len(session.exec(select(NotificationDelivery)).all()) == 1
        with pytest.raises(ValueError, match="idempotency"):
            queue_notification(
                session,
                user,
                NotificationCategory.ACCOUNT,
                NotificationKind.SUBSCRIPTION_EXPIRED,
                "expiration:one",
                subscription=subscription,
            )


def test_idempotency_rejects_changed_references_and_event_time(tmp_path) -> None:
    engine, user_id, subscription_id = _setup(tmp_path)
    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        store_service_announcement_email(user, "service@example.com")
        alternate = Subscription(
            user_id=user.id or 0,
            product=ProductType.PORT,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=subscription.current_period_end,
        )
        first_announcement = create_announcement(session, "First", "Body", "test")
        second_announcement = create_announcement(session, "Second", "Body", "test")
        session.add(alternate)
        session.flush()
        assert subscription.current_period_end is not None
        first_payment = Payment(
            subscription_id=subscription.id or 0,
            method=PaymentMethod.LIGHTNING,
            status=PaymentStatus.PAID,
            amount_sats=1000,
        )
        second_payment = Payment(
            subscription_id=subscription.id or 0,
            method=PaymentMethod.CASHU,
            status=PaymentStatus.PAID,
            amount_sats=1000,
        )
        session.add_all([first_payment, second_payment])
        session.flush()
        queue_notification(
            session,
            user,
            NotificationCategory.ACCOUNT,
            NotificationKind.EXPIRATION_7_DAY,
            "reference:subscription",
            subscription=subscription,
            event_at=subscription.current_period_end,
        )
        with pytest.raises(ValueError, match="idempotency"):
            queue_notification(
                session,
                user,
                NotificationCategory.ACCOUNT,
                NotificationKind.EXPIRATION_7_DAY,
                "reference:subscription",
                subscription=alternate,
                event_at=subscription.current_period_end,
            )
        queue_notification(
            session,
            user,
            NotificationCategory.SERVICE,
            NotificationKind.SERVICE_ANNOUNCEMENT,
            "reference:announcement",
            announcement=first_announcement,
        )
        with pytest.raises(ValueError, match="idempotency"):
            queue_notification(
                session,
                user,
                NotificationCategory.SERVICE,
                NotificationKind.SERVICE_ANNOUNCEMENT,
                "reference:announcement",
                announcement=second_announcement,
            )
        queue_notification(
            session,
            user,
            NotificationCategory.ACCOUNT,
            NotificationKind.SUBSCRIPTION_ACTIVATED,
            "reference:payment",
            subscription=subscription,
            payment=first_payment,
            event_at=subscription.current_period_end,
        )
        with pytest.raises(ValueError, match="idempotency"):
            queue_notification(
                session,
                user,
                NotificationCategory.ACCOUNT,
                NotificationKind.SUBSCRIPTION_ACTIVATED,
                "reference:payment",
                subscription=subscription,
                payment=second_payment,
                event_at=subscription.current_period_end,
            )


@pytest.mark.parametrize(
    ("kind", "status", "subject"),
    [
        (NotificationKind.SUBSCRIPTION_ACTIVATED, SubscriptionStatus.ACTIVE, "activated"),
        (NotificationKind.SUBSCRIPTION_RENEWED, SubscriptionStatus.ACTIVE, "renewed"),
        (NotificationKind.SUBSCRIPTION_EXPIRED, SubscriptionStatus.EXPIRED, "expired"),
    ],
)
def test_lifecycle_notification_eligibility_and_rendering(
    monkeypatch, tmp_path, kind, status, subject
) -> None:
    from blindport import config
    from blindport.services.notification_reconciliation import _is_delivery_eligible

    engine, user_id, subscription_id = _setup(tmp_path)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert (
            user is not None
            and subscription is not None
            and subscription.current_period_end is not None
        )
        subscription.status = status
        delivery = queue_notification(
            session,
            user,
            NotificationCategory.ACCOUNT,
            kind,
            f"lifecycle:{kind.value}",
            subscription=subscription,
            event_at=subscription.current_period_end,
        )
        rendered = render_notification(delivery, subscription=subscription)
        assert subject in rendered.subject
        assert "Blindport IP" in rendered.body
        assert _is_delivery_eligible(delivery, user, subscription, None, datetime.now(UTC))


def test_delayed_expiration_rendering_is_truthful_and_message_id_is_stable(tmp_path) -> None:
    engine, user_id, subscription_id = _setup(tmp_path, period_delta=timedelta(days=2, hours=2))
    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        delivery = _queue_expiration(session, user, subscription, "expiration:delayed")
        session.commit()
        rendered = render_notification(delivery, now=datetime.now(UTC))
        assert "within 3 days" in rendered.subject
        assert "7 days" not in rendered.subject
        message_id = notification_message_id(delivery)
        assert message_id == notification_message_id(delivery)
        delivery.recipient_generation += 1
        assert message_id != notification_message_id(delivery)


@pytest.mark.parametrize(
    "error,state",
    [
        (None, NotificationDeliveryState.SENT),
        (SmtpDeliveryError("smtp_transient", retryable=True), NotificationDeliveryState.QUEUED),
        (SmtpDeliveryError("smtp_rejected", retryable=False), NotificationDeliveryState.FAILED),
        (
            SmtpDeliveryError("smtp_delivery_ambiguous", retryable=False, ambiguous=True),
            NotificationDeliveryState.DELIVERY_AMBIGUOUS,
        ),
    ],
)
def test_smtp_delivery_transitions(tmp_path, error, state) -> None:
    engine, user_id, subscription_id = _setup(tmp_path)
    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        delivery = _queue_expiration(session, user, subscription, f"smtp:{state.value}")
        session.commit()
        send_notification(session, delivery, user, _Smtp(error), subscription=subscription)
        assert delivery.state == state
        assert delivery.attempt_count == 1
        assert delivery.last_attempt_at is not None
        if state == NotificationDeliveryState.QUEUED:
            assert delivery.next_attempt_at is not None
        else:
            assert delivery.terminal_at is not None


def test_stale_lease_cannot_finalize_smtp_result(tmp_path) -> None:
    engine, user_id, subscription_id = _setup(tmp_path)
    with Session(engine) as first:
        user = first.get(User, user_id)
        subscription = first.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        delivery = _queue_expiration(first, user, subscription, "smtp:stale")
        delivery.lease_token = "old"
        first.commit()
        with Session(engine) as second:
            second.exec(
                update(NotificationDelivery)
                .where(NotificationDelivery.id == delivery.id)
                .values(lease_token="new")
            )
            second.commit()
        send_notification(first, delivery, user, _Smtp(), subscription=subscription)
        first.refresh(delivery)
        assert delivery.state == NotificationDeliveryState.SENDING
        assert delivery.lease_token == "new"


def test_reconciliation_discovers_once_cancels_generation_change_and_recovers_sending(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker

    engine, user_id, subscription_id = _setup(tmp_path)
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(config.settings, "SMTP_FROM_EMAIL", "notices@example.com")
    smtp = _Smtp()
    monkeypatch.setattr(worker, "get_smtp_adapter", lambda: smtp)
    summary = worker.reconcile_notifications_once(batch_size=1)
    assert (summary.queued, summary.sent, smtp.calls) == (1, 1, 1)
    assert worker.reconcile_notifications_once(batch_size=1).queued == 0

    with Session(engine) as session:
        user = session.get(User, user_id)
        subscription = session.get(Subscription, subscription_id)
        assert user is not None and subscription is not None
        delivery = _queue_expiration(session, user, subscription, "expiration:change")
        session.commit()
        changed_delivery_id = delivery.id
        assert changed_delivery_id is not None
        clear_reminder_email(user)
        session.add(user)
        session.commit()
    worker.reconcile_notifications_once(batch_size=1)
    with Session(engine) as session:
        changed = session.exec(
            select(NotificationDelivery).where(NotificationDelivery.id == changed_delivery_id)
        ).one()
        assert changed.state == NotificationDeliveryState.CANCELLED

        user = session.get(User, user_id)
        assert user is not None
        store_reminder_email(user, "person@example.com")
        session.add(user)
        subscription = session.get(Subscription, subscription_id)
        assert subscription is not None
        interrupted = _queue_expiration(session, user, subscription, "expiration:interrupted")
        interrupted.state = NotificationDeliveryState.SENDING
        interrupted.attempt_count = 1
        session.add(interrupted)
        session.commit()
        interrupted_delivery_id = interrupted.id
        assert interrupted_delivery_id is not None
    summary = worker.reconcile_notifications_once(batch_size=1)
    assert summary.failed == 1
    with Session(engine) as session:
        interrupted = session.exec(
            select(NotificationDelivery).where(NotificationDelivery.id == interrupted_delivery_id)
        ).one()
        assert interrupted.state == NotificationDeliveryState.DELIVERY_AMBIGUOUS
        assert interrupted.error_code == "worker_interrupted"


def test_expiration_discovery_respects_batch_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker

    engine, user_id, _ = _setup(tmp_path)
    with Session(engine) as session:
        session.add(
            Subscription(
                user_id=user_id,
                product=ProductType.PORT,
                status=SubscriptionStatus.ACTIVE,
                monthly_price_sats=1000,
                current_period_end=datetime.now(UTC) + timedelta(days=6),
            )
        )
        session.commit()
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    assert worker._queue_due_expirations(datetime.now(UTC), 1) == 1
    with Session(engine) as session:
        assert len(session.exec(select(NotificationDelivery)).all()) == 1


def test_non_cancelled_legacy_reminder_suppresses_unified_discovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker

    engine, user_id, subscription_id = _setup(tmp_path)
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    with Session(engine) as session:
        subscription = session.get(Subscription, subscription_id)
        assert subscription is not None and subscription.current_period_end is not None
        session.add(
            ReminderDelivery(
                subscription_id=subscription_id,
                current_period_end=subscription.current_period_end,
                recipient_generation=1,
                kind=ReminderKind.SEVEN_DAY,
            )
        )
        session.commit()
    assert worker._queue_due_expirations(datetime.now(UTC), 10) == 0
    with Session(engine) as session:
        legacy = session.exec(select(ReminderDelivery)).one()
        legacy.state = ReminderDeliveryState.CANCELLED
        session.add(legacy)
        session.commit()
    assert worker._queue_due_expirations(datetime.now(UTC), 10) == 1


def test_campaign_expansion_snapshot_opt_out_completion_and_cancellation(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker
    from blindport.services.announcements import mark_announcement_completed_if_done

    engine = create_engine(f"sqlite:///{tmp_path / 'campaigns.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    with Session(engine) as session:
        users = [User(hashed_token=f"campaign-{index}") for index in range(2)]
        for user in users:
            store_service_announcement_email(user, f"campaign-{user.hashed_token}@example.com")
            session.add(user)
        session.commit()
        preexisting_ineligible = User(hashed_token="campaign-preexisting-ineligible")
        session.add(preexisting_ineligible)
        session.commit()
        campaign = queue_announcement(
            session, create_announcement(session, "Notice", "Body", "test").id or 0
        )
        assert campaign.recipient_count == 2
        snapshot = session.exec(
            select(AnnouncementRecipientSnapshot)
            .where(AnnouncementRecipientSnapshot.announcement_id == campaign.id)
            .order_by(AnnouncementRecipientSnapshot.user_id)
        ).all()
        assert [(row.user_id, row.recipient_generation) for row in snapshot] == [
            (user.id, user.service_email_generation) for user in users
        ]
        store_service_announcement_email(preexisting_ineligible, "opted-in@example.com")
        late = User(hashed_token="campaign-late")
        store_service_announcement_email(late, "late@example.com")
        session.add(late)
        session.commit()
        snapshotted_generation = users[1].service_email_generation
        store_service_announcement_email(users[1], "changed@example.com")
        session.add(users[1])
        session.commit()
        legacy = AnnouncementDelivery(
            announcement_id=campaign.id or 0,
            user_id=users[0].id or 0,
            recipient_generation=users[0].service_email_generation,
        )
        session.add(legacy)
        session.commit()
        user_ids = [user.id for user in users]
        late_id = late.id
        preexisting_ineligible_id = preexisting_ineligible.id
        campaign_id = campaign.id
        legacy_id = legacy.id

    assert worker._expand_queued_announcements(1) == 1
    assert worker._expand_queued_announcements(1) == 1
    assert worker._expand_queued_announcements(1) == 0
    assert worker._expand_queued_announcements(1) == 0
    with Session(engine) as session:
        expanded = session.exec(
            select(NotificationDelivery).order_by(NotificationDelivery.user_id)
        ).all()
        assert [delivery.user_id for delivery in expanded] == user_ids
        assert all(delivery.user_id != late_id for delivery in expanded)
        assert all(delivery.user_id != preexisting_ineligible_id for delivery in expanded)
        changed_delivery = next(
            delivery for delivery in expanded if delivery.user_id == user_ids[1]
        )
        assert changed_delivery.recipient_generation == snapshotted_generation
        stored = session.get(Announcement, campaign_id)
        assert stored is not None and stored.expansion_complete
        changed_user = session.get(User, user_ids[1])
        assert changed_user is not None
        reused = queue_notification(
            session,
            changed_user,
            NotificationCategory.SERVICE,
            NotificationKind.SERVICE_ANNOUNCEMENT,
            f"announcement:{campaign_id}:user:{changed_user.id}",
            announcement=stored,
        )
        assert reused.recipient_generation == snapshotted_generation
        worker._cancel_invalid_queued_deliveries(datetime.now(UTC), 10)
        session.refresh(changed_delivery)
        assert changed_delivery.state == NotificationDeliveryState.CANCELLED
        expanded[0].state = NotificationDeliveryState.SENT
        session.add(expanded[0])
        session.commit()
        mark_announcement_completed_if_done(session, campaign_id or 0)
        assert session.get(Announcement, campaign_id).state.value == "queued"  # type: ignore[union-attr]
        legacy = session.get(AnnouncementDelivery, legacy_id)
        assert legacy is not None
        legacy.state = AnnouncementDeliveryState.SENT
        session.add(legacy)
        session.commit()
        mark_announcement_completed_if_done(session, campaign_id or 0)
        assert session.get(Announcement, campaign_id).state.value == "completed"  # type: ignore[union-attr]


def test_campaign_cancellation_cancels_legacy_and_unified_deliveries(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker

    engine = create_engine(f"sqlite:///{tmp_path / 'campaign-cancellation.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    with Session(engine) as session:
        user = User(hashed_token="campaign-cancellation")
        store_service_announcement_email(user, "campaign-cancellation@example.com")
        session.add(user)
        session.commit()
        campaign = queue_announcement(
            session, create_announcement(session, "Notice", "Body", "test").id or 0
        )
        legacy = AnnouncementDelivery(
            announcement_id=campaign.id or 0,
            user_id=user.id or 0,
            recipient_generation=user.service_email_generation,
        )
        session.add(legacy)
        session.commit()
        campaign_id = campaign.id
        legacy_id = legacy.id

    assert worker._expand_queued_announcements(10) == 1
    with Session(engine) as session:
        cancel_announcement(session, campaign_id or 0)
        legacy = session.get(AnnouncementDelivery, legacy_id)
        assert legacy is not None
        session.refresh(legacy)
        assert legacy.state == AnnouncementDeliveryState.CANCELLED
        assert (
            session.exec(select(NotificationDelivery)).one().state
            == NotificationDeliveryState.CANCELLED
        )


def test_campaign_completes_only_after_unified_delivery_is_terminal(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    from blindport import config
    from blindport.services import notification_reconciliation as worker
    from blindport.services.announcements import mark_announcement_completed_if_done

    engine = create_engine(f"sqlite:///{tmp_path / 'completion.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(worker.db, "engine", engine)
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    with Session(engine) as session:
        user = User(hashed_token="completion-user")
        store_service_announcement_email(user, "completion@example.com")
        session.add(user)
        session.commit()
        campaign = queue_announcement(
            session, create_announcement(session, "Notice", "Body", "test").id or 0
        )
    assert worker._expand_queued_announcements(10) == 1
    assert worker._expand_queued_announcements(10) == 0
    with Session(engine) as session:
        mark_announcement_completed_if_done(session, campaign.id or 0)
        assert session.get(Announcement, campaign.id).state.value == "queued"  # type: ignore[union-attr]
        delivery = session.exec(select(NotificationDelivery)).one()
        delivery.state = NotificationDeliveryState.SENT
        session.add(delivery)
        session.commit()
        mark_announcement_completed_if_done(session, campaign.id or 0)
        assert session.get(Announcement, campaign.id).state.value == "completed"  # type: ignore[union-attr]


def test_settlement_and_expiry_queue_one_lifecycle_notification(app_client, monkeypatch) -> None:
    client, factory = app_client
    from blindport.db import engine
    from blindport.services import payments, subscriptions

    monkeypatch.setattr(payments.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    client.post(
        "/api/v1/me/reminder-email",
        json={"email": "person@example.com"},
        headers={"Authorization": f"Bearer {token}"},
    )
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    reconcile_pending_payments_once()
    reconcile_pending_payments_once()
    with Session(engine) as session:
        activated = session.exec(
            select(NotificationDelivery).where(
                NotificationDelivery.kind == NotificationKind.SUBSCRIPTION_ACTIVATED
            )
        ).all()
        assert len(activated) == 1
        stored = session.get(Subscription, activated[0].subscription_id)
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
        subscriptions.expire_elapsed_subscriptions(session, [stored])
        subscriptions.expire_elapsed_subscriptions(session, [stored])
        assert (
            len(
                session.exec(
                    select(NotificationDelivery).where(
                        NotificationDelivery.kind == NotificationKind.SUBSCRIPTION_EXPIRED
                    )
                ).all()
            )
            == 1
        )


@pytest.mark.asyncio
async def test_notification_health_loop_records_completed_cycle() -> None:
    from blindport.services import notification_reconciliation as worker

    worker.notification_reconciler_health.configure(
        enabled=True, startup_grace_seconds=1, stale_after_seconds=2
    )
    stop_event = asyncio.Event()
    calls = 0

    def reconcile_once():
        nonlocal calls
        calls += 1
        stop_event.set()
        return worker.NotificationReconciliationSummary()

    await worker.run_notification_reconciler(
        stop_event,
        reconcile_once=reconcile_once,
        interval_seconds=0.01,
    )
    assert calls == 1
    assert worker.notification_reconciler_health.status() == "ok"
