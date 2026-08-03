"""Regression tests for reservation ownership and one-time payment settlement."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _subscription(client, token: str, product: str = "port") -> dict:
    response = client.post("/api/v1/subscriptions", json={"product": product}, headers=_auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def _payment(client, token: str, subscription_id: int, method: str = "lightning") -> dict:
    response = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription_id, "method": method},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_old_expired_payment_read_does_not_release_newer_reservation(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)
    first = _payment(client, token, subscription["id"])

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored_payment = session.get(Payment, first["id"])
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        stored_payment.expires_at = expired_at
        stored_subscription.reservation_expires_at = expired_at
        session.add(stored_payment)
        session.add(stored_subscription)
        session.commit()

    expired = client.get(f"/api/v1/payments/{first['id']}", headers=_auth(token))
    assert expired.json()["status"] == "expired"
    second = _payment(client, token, subscription["id"])

    reread = client.get(f"/api/v1/payments/{first['id']}", headers=_auth(token))
    assert reread.json()["status"] == "expired"
    with Session(engine) as session:
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_subscription is not None
        assert stored_subscription.reservation_payment_id == second["id"]
        assert stored_subscription.assigned_port == 10000


def test_old_failed_payment_read_does_not_release_newer_reservation(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)
    failed_payment = _payment(client, token, subscription["id"], "cashu")
    failed = client.post(
        "/api/v1/payments/cashu-submit",
        json={"payment_id": failed_payment["id"], "cashu_token": "invalid"},
        headers=_auth(token),
    )
    assert failed.json()["status"] == "failed"
    newer = _payment(client, token, subscription["id"])

    reread = client.get(f"/api/v1/payments/{failed_payment['id']}", headers=_auth(token))
    assert reread.json()["status"] == "failed"

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        assert stored.reservation_payment_id == newer["id"]


def test_delayed_invoice_binding_uses_provider_expiry_not_staging_deadline(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)
    payment = _payment(client, token, subscription["id"])

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine
    from blindport.services.payments import ensure_lightning_invoice

    now = datetime.now(UTC)
    staged_deadline = now + timedelta(seconds=10)
    eligibility_deadline = now + timedelta(minutes=15)
    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        stored_payment.invoice = None
        stored_payment.expires_at = staged_deadline
        stored_subscription.reservation_expires_at = eligibility_deadline
        session.add(stored_payment)
        session.add(stored_subscription)
        session.commit()

    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        assert stored_payment is not None
        rebound = ensure_lightning_invoice(session, stored_payment)

    assert rebound.invoice == payment["invoice"]
    rebound_deadline = rebound.expires_at
    assert rebound_deadline is not None
    if rebound_deadline.tzinfo is None:
        rebound_deadline = rebound_deadline.replace(tzinfo=UTC)
    assert rebound_deadline > staged_deadline + timedelta(minutes=5)
    assert rebound_deadline <= eligibility_deadline


@pytest.mark.parametrize("method", ["lightning", "nwc"])
def test_provider_settlement_wins_at_local_expiry(app_client, method: str) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    if method == "nwc":
        client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://boundary"},
            headers=_auth(token),
        )
    subscription = _subscription(client, token)
    payment = _payment(client, token, subscription["id"], method)

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        stored_payment.expires_at = expired_at
        stored_subscription.reservation_expires_at = expired_at
        session.add(stored_payment)
        session.add(stored_subscription)
        session.commit()

    if method == "lightning":
        factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    else:
        factory.get_nwc_adapter().mark_settled(payment["payment_hash"])

    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"
    assert (
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]["status"]
        == "active"
    )


def test_stale_concurrent_poll_grants_only_one_renewal_period(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "ip")
    initial = _payment(client, token, subscription["id"])
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    renewal_response = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    )
    assert renewal_response.status_code == 200, renewal_response.text
    renewal = renewal_response.json()
    factory.get_lightning_adapter().mark_paid(renewal["payment_hash"])

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine
    from blindport.services.payments import check_and_settle_payment

    with Session(engine) as session:
        stored_subscription = session.get(Subscription, subscription["id"])
        stale_payment = session.get(Payment, renewal["id"])
        assert stored_subscription is not None and stale_payment is not None
        period_before = stored_subscription.current_period_end
        session.expunge(stale_payment)

    with Session(engine) as session:
        current_payment = session.get(Payment, renewal["id"])
        assert current_payment is not None
        assert check_and_settle_payment(session, current_payment).status.value == "paid"

    with Session(engine) as session:
        assert check_and_settle_payment(session, stale_payment).status.value == "paid"

    with Session(engine) as session:
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_subscription is not None
        assert stored_subscription.current_period_end is not None
        assert period_before is not None
        assert stored_subscription.current_period_end - period_before == timedelta(days=365)


def test_stale_cashu_submitter_cannot_redeem_or_settle_twice(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "ip")
    payment = _payment(client, token, subscription["id"], "cashu")
    adapter = factory.get_cashu_adapter()
    adapter.register_test_token("cashu-once", payment["amount_sats"])
    original_redeem = adapter.validate_and_redeem
    redeem_calls = 0

    def counting_redeem(token_value: str, amount_sats: int) -> bool:
        nonlocal redeem_calls
        redeem_calls += 1
        return original_redeem(token_value, amount_sats)

    monkeypatch.setattr(adapter, "validate_and_redeem", counting_redeem)

    from blindport.core.models import Payment
    from blindport.db import engine
    from blindport.services.payments import submit_cashu_token

    with Session(engine) as session:
        stale_payment = session.get(Payment, payment["id"])
        assert stale_payment is not None
        session.expunge(stale_payment)
    with Session(engine) as session:
        current_payment = session.get(Payment, payment["id"])
        assert current_payment is not None
        assert submit_cashu_token(session, current_payment, "cashu-once").status.value == "paid"
    with Session(engine) as session:
        assert submit_cashu_token(session, stale_payment, "cashu-once").status.value == "paid"
    assert redeem_calls == 1


def test_uncertain_cashu_failure_is_terminal_and_releases_only_its_hold(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "ip")
    payment = _payment(client, token, subscription["id"], "cashu")

    def uncertain_failure(token_value: str, amount_sats: int) -> bool:
        raise RuntimeError("mint response lost")

    monkeypatch.setattr(factory.get_cashu_adapter(), "validate_and_redeem", uncertain_failure)
    with pytest.raises(RuntimeError, match="mint response lost"):
        client.post(
            "/api/v1/payments/cashu-submit",
            json={"payment_id": payment["id"], "cashu_token": "cashu-uncertain"},
            headers=_auth(token),
        )

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        assert stored_payment.status.value == "failed"
        assert stored_subscription.reservation_payment_id is None
        assert stored_subscription.assigned_ip is None


def test_stale_cashu_failure_cannot_overwrite_paid(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "ip")
    payment = _payment(client, token, subscription["id"], "cashu")

    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services.payments import (
        _claim_cashu_payment,
        _fail_claimed_cashu_payment,
        _finalize_payment,
    )

    with Session(engine) as session:
        pending = session.get(Payment, payment["id"])
        assert pending is not None
        claimed = _claim_cashu_payment(session, pending)
        assert claimed is not None
        session.expunge(claimed)

    with Session(engine) as session:
        assert (
            _finalize_payment(session, claimed, PaymentStatus.PROCESSING).status
            == PaymentStatus.PAID
        )

    with Session(engine) as session:
        assert _fail_claimed_cashu_payment(session, claimed).status == PaymentStatus.PAID


def test_payment_expiry_is_bounded_by_owned_reservation(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)
    payment = _payment(client, token, subscription["id"])

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        stored_subscription = session.get(Subscription, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        assert stored_payment.expires_at is not None
        assert stored_subscription.reservation_expires_at is not None
        assert stored_payment.expires_at <= stored_subscription.reservation_expires_at
        assert stored_subscription.reservation_payment_id == stored_payment.id


def test_elapsed_quarantine_reconciles_paid_renewal_before_resource_release(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "port")
    initial = _payment(client, token, subscription["id"])
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    renewal = _payment(client, token, subscription["id"])

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine
    from blindport.services.subscriptions import (
        expire_elapsed_subscriptions,
        reap_elapsed_resource_holds,
    )

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        stored_renewal = session.get(Payment, renewal["id"])
        assert stored is not None and stored_renewal is not None
        assigned = (stored.assigned_ip, stored.assigned_port)
        stored_renewal.created_at = datetime.now(UTC) - timedelta(seconds=10)
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.add(stored_renewal)
        session.commit()
        expire_elapsed_subscriptions(session, [stored])
        stored.resource_quarantined_until = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    factory.get_lightning_adapter().mark_paid(renewal["payment_hash"])
    with Session(engine) as session:
        reap_elapsed_resource_holds(session)
        stored = session.get(Subscription, subscription["id"])
        stored_payment = session.get(Payment, renewal["id"])
        assert stored is not None and stored_payment is not None
        assert stored_payment.status.value == "paid"
        assert stored.status.value == "active"
        assert (stored.assigned_ip, stored.assigned_port) == assigned
        assert stored.resource_quarantined_until is None


def test_elapsed_quarantine_retains_assignment_for_open_renewal(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token, "ip")
    initial = _payment(client, token, subscription["id"])
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    renewal = _payment(client, token, subscription["id"])

    from blindport.core.models import Payment, Subscription, SubscriptionStatus
    from blindport.db import engine
    from blindport.services.subscriptions import reap_elapsed_resource_holds

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        stored_renewal = session.get(Payment, renewal["id"])
        assert stored is not None and stored_renewal is not None
        assigned_ip = stored.assigned_ip
        stored.status = SubscriptionStatus.EXPIRED
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        stored.resource_quarantined_until = datetime.now(UTC) - timedelta(seconds=1)
        stored_renewal.created_at = datetime.now(UTC) - timedelta(seconds=10)
        stored_renewal.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        session.add(stored)
        session.add(stored_renewal)
        session.commit()

        reap_elapsed_resource_holds(session)
        session.refresh(stored)
        session.refresh(stored_renewal)
        assert stored_renewal.status.value == "pending"
        assert stored.status.value == "expired"
        assert stored.assigned_ip == assigned_ip
        assert stored.resource_quarantined_until is not None


@pytest.mark.parametrize("method", ["lightning", "nwc"])
def test_relay_invoice_and_local_expiry_are_bounded_by_claim(
    app_client, monkeypatch, method: str
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    if method == "nwc":
        client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://bounded"},
            headers=_auth(token),
        )
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": f"bounded-{method}.relay.test"},
        headers=_auth(token),
    ).json()

    from blindport.core.models import Subscription
    from blindport.db import engine

    claim_deadline = datetime.now(UTC) + timedelta(seconds=120)
    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        stored.domain_claim_expires_at = claim_deadline
        session.add(stored)
        session.commit()

    adapter = factory.get_lightning_adapter()
    original = adapter.create_or_lookup_invoice
    requested_expiries: list[int | None] = []

    def capture_expiry(
        amount_sats: int,
        memo: str,
        payment_preimage: bytes,
        expiry_seconds: int | None = None,
    ):
        requested_expiries.append(expiry_seconds)
        return original(amount_sats, memo, payment_preimage, expiry_seconds)

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", capture_expiry)
    payment = _payment(client, token, subscription["id"], method)

    assert len(requested_expiries) == 1
    assert requested_expiries[0] is not None
    from blindport.config import settings

    assert 30 <= requested_expiries[0] <= 119 - settings.PAYMENT_EXPIRY_SAFETY_SECONDS
    assert datetime.fromisoformat(payment["expires_at"]).replace(tzinfo=UTC) <= claim_deadline


def test_too_short_domain_window_is_rejected_before_invoice_creation(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "too-short.relay.test"},
        headers=_auth(token),
    ).json()

    from blindport.config import settings
    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        stored.domain_claim_expires_at = datetime.now(UTC) + timedelta(
            seconds=settings.PAYMENT_MIN_PAYABLE_SECONDS
            + settings.PAYMENT_EXPIRY_SAFETY_SECONDS
            - 1
        )
        session.add(stored)
        session.commit()

    calls = 0

    def unexpected_invoice(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("invoice adapter must not be called")

    monkeypatch.setattr(factory.get_lightning_adapter(), "create_invoice", unexpected_invoice)
    response = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert "too short" in response.json()["detail"]
    assert calls == 0


def test_cashu_quote_and_redeem_are_blocked_after_domain_eligibility(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "cashu-expiry.relay.test"},
        headers=_auth(token),
    ).json()
    payment = _payment(client, token, subscription["id"], "cashu")

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored_sub = session.get(Subscription, subscription["id"])
        stored_payment = session.get(Payment, payment["id"])
        assert stored_sub is not None and stored_payment is not None
        stored_sub.domain_claim_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        stored_payment.expires_at = datetime.now(UTC) + timedelta(minutes=5)
        session.add(stored_sub)
        session.add(stored_payment)
        session.commit()

    adapter = factory.get_cashu_adapter()
    quote_calls = 0
    mint_calls = 0

    def unexpected_quote(amount_sats: int):
        nonlocal quote_calls
        quote_calls += 1
        raise AssertionError("expired payment must not issue a quote")

    def unexpected_mint(*args, **kwargs):
        nonlocal mint_calls
        mint_calls += 1
        raise AssertionError("expired payment must not mint or redeem")

    monkeypatch.setattr(adapter, "request_mint_quote", unexpected_quote)
    monkeypatch.setattr(adapter, "check_mint_quote", unexpected_mint, raising=False)
    monkeypatch.setattr(adapter, "mint_against_quote", unexpected_mint, raising=False)

    quote = client.post(
        "/api/v1/payments/cashu-quote",
        json={"payment_id": payment["id"]},
        headers=_auth(token),
    )
    assert quote.status_code == 400
    assert quote.json()["detail"] == "payment expired"
    redeem = client.post(
        "/api/v1/payments/cashu-mint-and-redeem",
        json={"payment_id": payment["id"], "quote_id": "late", "mint_url": None},
        headers=_auth(token),
    )
    assert redeem.status_code == 400
    assert redeem.json()["detail"] == "payment is not pending"
    assert quote_calls == 0
    assert mint_calls == 0
