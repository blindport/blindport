"""Durable provider-backed payment reconciliation behavior."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta

from fastapi import FastAPI
from sqlmodel import Session, select
from subscription_helpers import subscription_by_public_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_payment(client, token: str, product: str = "ip") -> tuple[dict, dict]:
    subscription_response = client.post(
        "/api/v1/subscriptions",
        json={"product": product},
        headers=_auth(token),
    )
    assert subscription_response.status_code == 200, subscription_response.text
    subscription = subscription_response.json()
    payment_response = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment_response.status_code == 200, payment_response.text
    return subscription, payment_response.json()


def test_reconciler_activates_paid_lightning_without_payment_get(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription, payment = _create_payment(client, token)
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])

    from blindport.core.models import Payment, PaymentStatus, SubscriptionStatus
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    summary = reconcile_pending_payments_once()

    assert summary.paid == 1
    with Session(engine) as session:
        assert session.get(Payment, payment["id"]).status == PaymentStatus.PAID  # type: ignore[union-attr]
        assert (
            subscription_by_public_id(session, subscription["id"]).status
            == SubscriptionStatus.ACTIVE
        )


def test_reconciler_recovers_paid_invoice_after_crash_before_local_binding(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=_auth(token),
    ).json()
    adapter = factory.get_lightning_adapter()
    original = adapter.create_or_lookup_invoice

    def create_then_crash(*args, **kwargs):
        original(*args, **kwargs)
        raise RuntimeError("process stopped before invoice binding")

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", create_then_crash)
    failed = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert failed.status_code == 502

    from blindport.core.models import Payment, PaymentStatus, SubscriptionStatus
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    with Session(engine) as session:
        staged = session.exec(select(Payment)).one()
        assert staged.invoice is None
        assert staged.payment_hash is not None
        payment_id = staged.id
        adapter.mark_paid(staged.payment_hash)
        staged.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(staged)
        session.commit()

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", original)
    summary = reconcile_pending_payments_once()

    assert summary.paid == 1
    with Session(engine) as session:
        stored_payment = session.get(Payment, payment_id)
        stored_subscription = subscription_by_public_id(session, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        assert stored_payment.invoice is not None
        assert stored_payment.status == PaymentStatus.PAID
        assert stored_subscription.status == SubscriptionStatus.ACTIVE


def test_reconciler_expiry_releases_only_the_expired_payments_reservation(app_client) -> None:
    client, _ = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    second_token = client.post("/api/v1/signup").json()["token"]
    first_subscription, first_payment = _create_payment(client, first_token, "port")
    second_subscription, second_payment = _create_payment(client, second_token, "port")

    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    with Session(engine) as session:
        payment = session.get(Payment, first_payment["id"])
        subscription = subscription_by_public_id(session, first_subscription["id"])
        assert payment is not None and subscription is not None
        elapsed = datetime.now(UTC) - timedelta(seconds=1)
        payment.expires_at = elapsed
        subscription.reservation_expires_at = elapsed
        session.add(payment)
        session.add(subscription)
        session.commit()

    summary = reconcile_pending_payments_once()

    assert summary.expired == 1
    with Session(engine) as session:
        first_stored = subscription_by_public_id(session, first_subscription["id"])
        second_stored = subscription_by_public_id(session, second_subscription["id"])
        assert first_stored is not None and second_stored is not None
        assert session.get(Payment, first_payment["id"]).status == PaymentStatus.EXPIRED  # type: ignore[union-attr]
        assert first_stored.reservation_payment_id is None
        assert first_stored.assigned_port is None
        assert second_stored.reservation_payment_id == second_payment["id"]
        assert second_stored.assigned_port == 10001


def test_reconciler_isolates_provider_failure_per_payment(app_client, monkeypatch) -> None:
    client, factory = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    second_token = client.post("/api/v1/signup").json()["token"]
    _, first = _create_payment(client, first_token)
    _, second = _create_payment(client, second_token)
    adapter = factory.get_lightning_adapter()
    adapter.mark_paid(second["payment_hash"])
    original_check = adapter.is_invoice_paid

    def provider_check(payment_hash: str) -> bool:
        if payment_hash == first["payment_hash"]:
            raise RuntimeError("provider unavailable")
        return original_check(payment_hash)

    monkeypatch.setattr(adapter, "is_invoice_paid", provider_check)

    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    summary = reconcile_pending_payments_once()

    assert summary.failed == 1
    assert summary.paid == 1
    with Session(engine) as session:
        assert session.get(Payment, first["id"]).status == PaymentStatus.PENDING  # type: ignore[union-attr]
        assert session.get(Payment, second["id"]).status == PaymentStatus.PAID  # type: ignore[union-attr]


def test_reconciler_skips_disabled_provider_method(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    _, payment = _create_payment(client, token)

    from blindport.services import payment_reconciliation

    monkeypatch.setattr(payment_reconciliation.settings, "PAYMENT_ENABLED_METHODS", "nwc")

    def unexpected_provider_call(payment_hash: str) -> bool:
        raise AssertionError("disabled payment provider must not be called")

    monkeypatch.setattr(
        factory.get_lightning_adapter(),
        "is_invoice_paid",
        unexpected_provider_call,
    )

    summary = payment_reconciliation.reconcile_pending_payments_once()

    assert summary.scanned == 0
    assert summary.skipped == 0
    assert summary.failed == 0
    assert payment["status"] == "pending"


def test_disabled_old_payment_does_not_starve_enabled_batch(app_client, monkeypatch) -> None:
    client, factory = app_client
    lightning_token = client.post("/api/v1/signup").json()["token"]
    _, lightning = _create_payment(client, lightning_token)

    nwc_token = client.post("/api/v1/signup").json()["token"]
    client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://reconciler-fairness"},
        headers=_auth(nwc_token),
    )
    nwc_subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=_auth(nwc_token),
    ).json()
    nwc = client.post(
        "/api/v1/payments",
        json={"subscription_id": nwc_subscription["id"], "method": "nwc"},
        headers=_auth(nwc_token),
    ).json()
    factory.get_nwc_adapter().mark_settled(nwc["payment_hash"])

    from blindport.services import payment_reconciliation

    monkeypatch.setattr(payment_reconciliation.settings, "PAYMENT_ENABLED_METHODS", "nwc")
    summary = payment_reconciliation.reconcile_pending_payments_once(batch_size=1)

    assert lightning["id"] < nwc["id"]
    assert summary.scanned == 1
    assert summary.paid == 1


def test_reconciler_uses_bounded_id_order(app_client, monkeypatch) -> None:
    client, _ = app_client
    payments = []
    for product in ("ip", "ip", "port"):
        token = client.post("/api/v1/signup").json()["token"]
        _, payment = _create_payment(client, token, product)
        payments.append(payment)

    from blindport.services import payment_reconciliation

    visited: list[int] = []

    def record_payment(session, payment):
        visited.append(payment.id)
        return payment

    monkeypatch.setattr(payment_reconciliation, "check_and_settle_payment", record_payment)

    summary = payment_reconciliation.reconcile_pending_payments_once(batch_size=2)

    expected_ids = sorted(payment["id"] for payment in payments)[:2]
    assert summary.scanned == 2
    assert visited == expected_ids


def test_operator_reminders_run_without_customer_lightning_or_nwc_enabled(
    app_client, monkeypatch
) -> None:
    del app_client
    from blindport.services import payment_reconciliation
    from blindport.services.reminder_reconciliation import ReminderReconciliationSummary

    monkeypatch.setattr(payment_reconciliation.settings, "PAYMENT_ENABLED_METHODS", "cashu")
    monkeypatch.setattr(payment_reconciliation.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(
        payment_reconciliation,
        "reconcile_reminders_once",
        lambda batch_size: ReminderReconciliationSummary(queued=2, sent=1),
    )

    summary = payment_reconciliation.reconcile_pending_payments_once(batch_size=10)

    assert summary.scanned == 0
    assert summary.reminders_queued == 2
    assert summary.reminders_sent == 1


def test_repeated_reconciliation_does_not_double_renew(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription, initial = _create_payment(client, token)

    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    reconcile_pending_payments_once()
    renewal_response = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal_response.status_code == 200, renewal_response.text
    renewal = renewal_response.json()
    factory.get_lightning_adapter().mark_paid(renewal["payment_hash"])

    with Session(engine) as session:
        period_before = subscription_by_public_id(session, subscription["id"]).current_period_end

    reconcile_pending_payments_once()
    reconcile_pending_payments_once()

    with Session(engine) as session:
        period_after = subscription_by_public_id(session, subscription["id"]).current_period_end
    assert period_before is not None and period_after is not None
    assert period_after - period_before == timedelta(days=30)


def test_reconciler_health_startup_and_staleness_without_sleeping() -> None:
    from blindport.services.payment_reconciliation import ReconcilerHealth

    now = 100.0
    state = ReconcilerHealth(clock=lambda: now)
    state.configure(enabled=True, startup_grace_seconds=5, stale_after_seconds=10)
    assert state.status(now=104) == "starting"
    assert state.status(now=106) == "unavailable"

    now = 107
    state.record_completed_cycle()
    assert state.status(now=117) == "ok"
    assert state.status(now=117.01) == "unavailable"


async def test_reconciler_worker_runs_promptly_and_stops_during_interval() -> None:
    from blindport.services.payment_reconciliation import (
        ReconciliationSummary,
        reconciler_health,
        run_payment_reconciler,
    )

    called = threading.Event()

    def reconcile_once() -> ReconciliationSummary:
        called.set()
        return ReconciliationSummary()

    reconciler_health.configure(enabled=True, startup_grace_seconds=5, stale_after_seconds=120)
    stop_event = asyncio.Event()
    task = asyncio.create_task(
        run_payment_reconciler(
            stop_event,
            reconcile_once=reconcile_once,
            interval_seconds=60,
        )
    )
    assert await asyncio.wait_for(asyncio.to_thread(called.wait), timeout=1)
    stop_event.set()
    await asyncio.wait_for(task, timeout=1)
    assert reconciler_health.status() == "ok"


async def test_lifespan_starts_reconciler_after_database_and_stops_it(
    monkeypatch,
) -> None:
    from blindport import main

    events: list[str] = []

    monkeypatch.setattr(main, "get_lightning_adapter", lambda: events.append("adapter"))
    monkeypatch.setattr(main, "prepare_database", lambda: events.append("database"))
    monkeypatch.setattr(main.settings, "PAYMENT_RECONCILIATION_ENABLED", True)

    async def worker(stop_event: asyncio.Event) -> None:
        events.append("worker-started")
        await stop_event.wait()
        events.append("worker-stopped")

    monkeypatch.setattr(main, "run_payment_reconciler", worker)
    app = FastAPI()

    async with main.lifespan(app):
        await asyncio.sleep(0)
        assert events == ["adapter", "database", "worker-started"]
        assert app.state.payment_reconciler_task is not None

    assert events[-1] == "worker-stopped"


async def test_lifespan_initializes_smtp_and_customer_nwc_independently(monkeypatch) -> None:
    from blindport import main

    events: list[str] = []

    monkeypatch.setattr(main.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(main.settings, "PAYMENT_ENABLED_METHODS", "lightning,nwc")
    monkeypatch.setattr(main.settings, "PAYMENT_RECONCILIATION_ENABLED", False)
    monkeypatch.setattr(main, "get_lightning_adapter", lambda: events.append("lightning"))
    monkeypatch.setattr(main, "get_smtp_adapter", lambda: events.append("smtp"))
    monkeypatch.setattr(main, "get_nwc_adapter", lambda: events.append("nwc"))
    monkeypatch.setattr(main, "prepare_database", lambda: events.append("database"))

    async with main.lifespan(FastAPI()):
        pass

    assert events == ["lightning", "smtp", "nwc", "database"]
