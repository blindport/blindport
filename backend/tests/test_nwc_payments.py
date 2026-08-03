"""NWC payment correctness, retry, reconciliation, and lease behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select

from blindport.adapters.base import (
    NwcAdapterError,
    NwcLookupResult,
    NwcLookupState,
    NwcPaymentState,
    NwcPayResult,
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _wallet_subscription(client) -> tuple[str, dict]:
    token = client.post("/api/v1/signup").json()["token"]
    response = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://payment-test"},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()
    return token, subscription


def _create_nwc(client, token: str, subscription_id: int):
    return client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription_id, "method": "nwc"},
        headers=_auth(token),
    )


def test_nwc_success_uses_lnd_and_verifies_returned_preimage(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    fixed_preimage = b"\x44" * 32

    from blindport.services import payments

    monkeypatch.setattr(payments, "_invoice_preimage", lambda payment: fixed_preimage)

    def settle(uri: str, invoice: str) -> NwcPayResult:
        del uri
        del invoice
        payment_hash = __import__("hashlib").sha256(fixed_preimage).hexdigest()
        factory.get_lightning_adapter().mark_paid(payment_hash)
        return NwcPayResult(
            NwcPaymentState.SETTLED,
            preimage=fixed_preimage.hex(),
            fees_paid_msats=21,
        )

    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", settle)

    response = _create_nwc(client, token, subscription["id"])

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "paid"
    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.get(Payment, response.json()["id"])
        assert payment is not None
        assert payment.nwc_preimage_hash == payment.payment_hash
        assert payment.nwc_fees_paid_msats == 21
        assert payment.nwc_attempt_count == 1


def test_nwc_preimage_mismatch_remains_pending_for_lnd_reconciliation(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "pay_invoice",
        lambda uri, invoice=None: NwcPayResult(NwcPaymentState.SETTLED, preimage="55" * 32),
    )

    response = _create_nwc(client, token, subscription["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "pending"
    assert response.json()["nwc_state"] == "unknown"
    assert response.json()["nwc_error_code"] == "preimage_mismatch"


def test_unknown_pay_and_lookup_never_resend(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    adapter = factory.get_nwc_adapter()
    pay_calls = 0

    def uncertain_pay(uri: str, invoice: str) -> NwcPayResult:
        nonlocal pay_calls
        pay_calls += 1
        raise NwcAdapterError("timeout", "wallet operation timed out", retryable=True)

    monkeypatch.setattr(adapter, "pay_invoice", uncertain_pay)
    created = _create_nwc(client, token, subscription["id"])
    assert created.status_code == 502

    def uncertain_lookup(uri: str, payment_hash: str) -> NwcLookupResult:
        raise NwcAdapterError("timeout", "wallet operation timed out", retryable=True)

    monkeypatch.setattr(adapter, "lookup_invoice", uncertain_lookup)
    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        payment_id = payment.id
        assert payment.nwc_state == "unknown"
        assert payment.nwc_attempt_count == 1

    checked = client.get(f"/api/v1/payments/{payment_id}", headers=_auth(token))
    assert checked.status_code == 502
    assert pay_calls == 1


def test_explicit_not_found_after_backoff_authorizes_one_retry(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    adapter = factory.get_nwc_adapter()
    pay_calls = 0

    def pay(uri: str, invoice: str) -> NwcPayResult:
        nonlocal pay_calls
        pay_calls += 1
        if pay_calls == 1:
            raise NwcAdapterError("transport", "wallet transport is unavailable", retryable=True)
        return NwcPayResult(NwcPaymentState.PENDING)

    monkeypatch.setattr(adapter, "pay_invoice", pay)
    assert _create_nwc(client, token, subscription["id"]).status_code == 502
    monkeypatch.setattr(
        adapter,
        "lookup_invoice",
        lambda uri, payment_hash: NwcLookupResult(NwcLookupState.NOT_FOUND),
    )

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        payment.nwc_next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        payment_id = payment.id
        session.add(payment)
        session.commit()

    checked = client.get(f"/api/v1/payments/{payment_id}", headers=_auth(token))

    assert checked.status_code == 200, checked.text
    assert checked.json()["nwc_attempt_count"] == 2
    assert pay_calls == 2


def test_terminal_lookup_error_is_inconclusive_without_resend(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    adapter = factory.get_nwc_adapter()
    pay_calls = 0

    def uncertain_pay(uri: str, invoice: str) -> NwcPayResult:
        nonlocal pay_calls
        pay_calls += 1
        raise NwcAdapterError("internal", "wallet operation failed", retryable=True)

    monkeypatch.setattr(adapter, "pay_invoice", uncertain_pay)
    assert _create_nwc(client, token, subscription["id"]).status_code == 502
    monkeypatch.setattr(
        adapter,
        "lookup_invoice",
        lambda uri, payment_hash: (_ for _ in ()).throw(
            NwcAdapterError("unauthorized", "wallet connection is unauthorized", retryable=False)
        ),
    )

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment_id = session.exec(select(Payment.id)).one()
    checked = client.get(f"/api/v1/payments/{payment_id}", headers=_auth(token))

    assert checked.status_code == 502
    with Session(engine) as session:
        stored = session.get(Payment, payment_id)
        assert stored is not None
        assert stored.status.value == "pending"
        assert stored.nwc_state == "unknown"
        assert stored.nwc_error_code == "unauthorized"
    assert pay_calls == 1


def test_pending_lookup_and_active_lease_prevent_duplicate_pay(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    created = _create_nwc(client, token, subscription["id"])
    assert created.status_code == 200
    adapter = factory.get_nwc_adapter()

    def duplicate_pay(uri: str, invoice: str) -> NwcPayResult:
        raise AssertionError("pending NWC payment must not be resent")

    monkeypatch.setattr(adapter, "pay_invoice", duplicate_pay)
    pending = client.get(f"/api/v1/payments/{created.json()['id']}", headers=_auth(token))
    assert pending.status_code == 200
    assert pending.json()["nwc_attempt_count"] == 1

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.get(Payment, created.json()["id"])
        assert payment is not None
        payment.nwc_last_lookup_at = datetime.now(UTC) - timedelta(minutes=1)
        payment.nwc_lease_until = datetime.now(UTC) + timedelta(minutes=1)
        session.add(payment)
        session.commit()
    monkeypatch.setattr(
        adapter,
        "lookup_invoice",
        lambda uri, payment_hash: (_ for _ in ()).throw(
            AssertionError("active lease must prevent wallet lookup")
        ),
    )
    leased = client.get(f"/api/v1/payments/{created.json()['id']}", headers=_auth(token))
    assert leased.status_code == 200


def test_settled_wallet_proof_is_never_resent_after_not_found(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    adapter = factory.get_nwc_adapter()
    fixed_preimage = b"\x66" * 32
    pay_calls = 0

    from blindport.services import payments

    monkeypatch.setattr(payments, "_invoice_preimage", lambda payment: fixed_preimage)

    def settle_without_lnd(uri: str, invoice: str) -> NwcPayResult:
        nonlocal pay_calls
        pay_calls += 1
        return NwcPayResult(NwcPaymentState.SETTLED, preimage=fixed_preimage.hex())

    monkeypatch.setattr(adapter, "pay_invoice", settle_without_lnd)
    created = _create_nwc(client, token, subscription["id"])
    assert created.status_code == 200
    assert created.json()["nwc_state"] == "settled"
    monkeypatch.setattr(
        adapter,
        "lookup_invoice",
        lambda uri, payment_hash: NwcLookupResult(NwcLookupState.NOT_FOUND),
    )

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.get(Payment, created.json()["id"])
        assert payment is not None
        payment.nwc_last_lookup_at = datetime.now(UTC) - timedelta(minutes=1)
        payment.nwc_next_attempt_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(payment)
        session.commit()

    checked = client.get(f"/api/v1/payments/{created.json()['id']}", headers=_auth(token))

    assert checked.status_code == 200
    assert checked.json()["status"] == "pending"
    assert checked.json()["nwc_state"] == "unknown"
    assert checked.json()["nwc_error_code"] == "settlement_unconfirmed"
    assert pay_calls == 1


def test_post_send_protocol_failure_is_not_treated_as_definitive(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "pay_invoice",
        lambda uri, invoice: (_ for _ in ()).throw(
            NwcAdapterError("protocol", "wallet helper protocol failed", retryable=False)
        ),
    )

    created = _create_nwc(client, token, subscription["id"])

    assert created.status_code == 502
    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        assert payment.status.value == "pending"
        assert payment.nwc_state == "unknown"
        assert payment.nwc_error_code == "protocol"


def test_lnd_settlement_wins_over_terminal_wallet_error(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    fixed_preimage = b"\x77" * 32

    from blindport.services import payments

    monkeypatch.setattr(payments, "_invoice_preimage", lambda payment: fixed_preimage)

    def paid_then_error(uri: str, invoice: str) -> NwcPayResult:
        del uri
        del invoice
        payment_hash = __import__("hashlib").sha256(fixed_preimage).hexdigest()
        factory.get_lightning_adapter().mark_paid(payment_hash)
        raise NwcAdapterError(
            "insufficient_balance", "wallet balance is insufficient", retryable=False
        )

    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", paid_then_error)

    created = _create_nwc(client, token, subscription["id"])

    assert created.status_code == 200
    assert created.json()["status"] == "paid"


def test_recent_lookup_throttles_repeated_api_polling(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    created = _create_nwc(client, token, subscription["id"])
    adapter = factory.get_nwc_adapter()
    lookups = 0
    original_lookup = adapter.lookup_invoice

    def counted_lookup(uri: str, payment_hash: str) -> NwcLookupResult:
        nonlocal lookups
        lookups += 1
        return original_lookup(uri, payment_hash)

    monkeypatch.setattr(adapter, "lookup_invoice", counted_lookup)
    payment_url = f"/api/v1/payments/{created.json()['id']}"

    assert client.get(payment_url, headers=_auth(token)).status_code == 200
    assert client.get(payment_url, headers=_auth(token)).status_code == 200

    assert lookups == 1


def test_recent_unknown_payment_does_not_starve_later_reconciliation_batch(app_client) -> None:
    client, _ = app_client
    first_token, first_subscription = _wallet_subscription(client)
    second_token, second_subscription = _wallet_subscription(client)
    first = _create_nwc(client, first_token, first_subscription["id"]).json()
    second = _create_nwc(client, second_token, second_subscription["id"]).json()

    from blindport.core.models import Payment
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    assert reconcile_pending_payments_once(batch_size=1).scanned == 1
    assert reconcile_pending_payments_once(batch_size=1).scanned == 1

    with Session(engine) as session:
        first_stored = session.get(Payment, first["id"])
        second_stored = session.get(Payment, second["id"])
        assert first_stored is not None and first_stored.nwc_last_lookup_at is not None
        assert second_stored is not None and second_stored.nwc_last_lookup_at is not None


def test_stale_worker_cannot_clear_new_lease_owner(app_client) -> None:
    client, _ = app_client
    token, subscription = _wallet_subscription(client)
    created = _create_nwc(client, token, subscription["id"])

    from blindport.core.models import Payment
    from blindport.db import engine
    from blindport.services.payments import _claim_nwc_lease, _save_nwc_observation

    with Session(engine) as first_session:
        first_payment = first_session.get(Payment, created.json()["id"])
        assert first_payment is not None
        first_payment.nwc_lease_until = datetime.now(UTC) - timedelta(seconds=1)
        first_session.add(first_payment)
        first_session.commit()
        first_claim = _claim_nwc_lease(first_session, first_payment)
        assert first_claim is not None and first_claim.nwc_lease_token is not None
        first_token = first_claim.nwc_lease_token

        with Session(engine) as second_session:
            second_payment = second_session.get(Payment, created.json()["id"])
            assert second_payment is not None
            second_payment.nwc_lease_until = datetime.now(UTC) - timedelta(seconds=1)
            second_session.add(second_payment)
            second_session.commit()
            second_claim = _claim_nwc_lease(second_session, second_payment)
            assert second_claim is not None and second_claim.nwc_lease_token is not None
            second_token = second_claim.nwc_lease_token

        observed = _save_nwc_observation(first_session, first_claim, "unknown")

    assert second_token != first_token
    assert observed.nwc_lease_token == second_token


def test_lnd_settlement_is_checked_before_nwc_lookup(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    payment = _create_nwc(client, token, subscription["id"]).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "lookup_invoice",
        lambda uri, payment_hash: (_ for _ in ()).throw(
            AssertionError("settled LND invoice must bypass NWC")
        ),
    )

    checked = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))

    assert checked.json()["status"] == "paid"


def test_terminal_wallet_policy_failure_disables_auto_renew(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "pay_invoice",
        lambda uri, invoice: (_ for _ in ()).throw(
            NwcAdapterError(
                "insufficient_balance", "wallet balance is insufficient", retryable=False
            )
        ),
    )

    renewal = _create_nwc(client, token, subscription["id"])

    assert renewal.status_code == 200
    assert renewal.json()["status"] == "failed"
    assert renewal.json()["nwc_error_code"] == "insufficient_balance"
    current = client.get("/api/v1/me", headers=_auth(token)).json()
    assert current["subscriptions"][0]["auto_renew"] is False


def test_due_auto_renew_uses_shared_nwc_payment_path(app_client) -> None:
    client, factory = app_client
    token, subscription = _wallet_subscription(client)
    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )

    from blindport.core.models import Payment, PaymentMethod, Subscription
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) + timedelta(minutes=1)
        session.add(stored)
        session.commit()

    summary = reconcile_pending_payments_once()

    assert summary.auto_renewed == 1
    with Session(engine) as session:
        renewal = session.exec(select(Payment).where(Payment.method == PaymentMethod.NWC)).one()
        assert renewal.nwc_attempt_count == 1
        assert renewal.nwc_state == "pending"


def test_custom_domain_auto_renew_requires_fresh_cname(app_client, monkeypatch) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://domain-renewal"},
        headers=_auth(token),
    )
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "renewal.example"},
        headers=_auth(token),
    ).json()

    from blindport.core.models import Payment, Subscription, SubscriptionStatus
    from blindport.db import engine
    from blindport.services import payment_reconciliation
    from blindport.services.domain_verification import DomainVerificationResult

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        stored.status = SubscriptionStatus.ACTIVE
        stored.domain_verified_at = datetime.now(UTC)
        stored.current_period_end = datetime.now(UTC) + timedelta(minutes=1)
        stored.auto_renew = True
        session.add(stored)
        session.commit()

    checked = 0

    def mismatch(*args, **kwargs):
        nonlocal checked
        checked += 1
        return DomainVerificationResult(False, "CNAME target did not match")

    monkeypatch.setattr(payment_reconciliation, "verify_subscription_domain", mismatch)
    summary = payment_reconciliation.reconcile_pending_payments_once()

    assert checked == 1
    assert summary.auto_renewed == 0
    with Session(engine) as session:
        assert session.exec(select(Payment)).all() == []
