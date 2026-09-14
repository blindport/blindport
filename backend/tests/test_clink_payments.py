"""CLINK payment ordering, fallback, and ambiguity handling."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select
from subscription_helpers import subscription_by_public_id

from blindport.adapters.base import (
    ClinkAdapterError,
    ClinkPaymentState,
    ClinkPayResult,
)
from blindport.core.models import Payment, PaymentMethod, Subscription, User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _connected_subscription(client, *, with_nwc: bool = False) -> tuple[str, dict]:
    token = client.post("/api/v1/signup").json()["token"]
    connected = client.post(
        "/api/v1/me/clink",
        json={"ndebit": "ndebit1subscription-test"},
        headers=_auth(token),
    )
    assert connected.status_code == 200, connected.text
    if with_nwc:
        nwc = client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://clink-fallback"},
            headers=_auth(token),
        )
        assert nwc.status_code == 200, nwc.text
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    return token, subscription


def _create_clink(client, token: str, subscription_id: str):
    return client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription_id, "method": "clink"},
        headers=_auth(token),
    )


def test_clink_success_uses_lnd_and_verifies_preimage(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)
    fixed_preimage = b"\x64" * 32

    from blindport.services import payments

    monkeypatch.setattr(payments, "_invoice_preimage", lambda payment: fixed_preimage)
    nwc_calls = 0

    def reject_unexpected_nwc(uri: str, invoice: str):
        nonlocal nwc_calls
        nwc_calls += 1
        raise AssertionError("NWC must not run after CLINK success")

    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", reject_unexpected_nwc)

    def settle(ndebit: str, invoice: str, amount_sats: int, description: str) -> ClinkPayResult:
        del ndebit, invoice, amount_sats, description
        payment_hash = hashlib.sha256(fixed_preimage).hexdigest()
        factory.get_lightning_adapter().mark_paid(payment_hash)
        return ClinkPayResult(ClinkPaymentState.SETTLED, fixed_preimage.hex())

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", settle)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "paid"
    assert response.json()["clink_state"] == "settled"
    assert response.json()["clink_nwc_fallback"] is False
    assert response.json()["nwc_attempt_count"] == 0
    assert nwc_calls == 0


def test_explicit_clink_rejection_falls_back_to_nwc(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)
    nwc = factory.get_nwc_adapter()
    nwc.auto_settle = True

    def deny(ndebit: str, invoice: str, amount_sats: int, description: str) -> ClinkPayResult:
        del ndebit, invoice, amount_sats, description
        raise ClinkAdapterError(
            "denied",
            "payment request was denied",
            retryable=False,
            wallet_rejection=True,
        )

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", deny)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "paid"
    assert response.json()["clink_state"] == "failed"
    assert response.json()["clink_error_code"] == "denied"
    assert response.json()["clink_nwc_fallback"] is True
    assert response.json()["clink_attempt_count"] == 1
    assert response.json()["nwc_attempt_count"] == 1


def test_ambiguous_clink_timeout_never_falls_back_or_resends(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)
    clink_calls = 0
    nwc_calls = 0

    def timeout(ndebit: str, invoice: str, amount_sats: int, description: str) -> ClinkPayResult:
        nonlocal clink_calls
        del ndebit, invoice, amount_sats, description
        clink_calls += 1
        raise ClinkAdapterError("timeout", "payment request timed out", retryable=True)

    def unexpected_nwc(uri: str, invoice: str):
        nonlocal nwc_calls
        del uri, invoice
        nwc_calls += 1
        raise AssertionError("ambiguous CLINK payment must not fall back")

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", timeout)
    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", unexpected_nwc)

    created = _create_clink(client, token, subscription["id"])
    assert created.status_code == 502

    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        payment_id = payment.id
        assert payment.clink_state == "unknown"
        assert payment.clink_attempt_count == 1
        assert payment.clink_nwc_fallback is False
        assert payment.nwc_attempt_count == 0

    checked = client.get(f"/api/v1/payments/{payment_id}", headers=_auth(token))

    assert checked.status_code == 200, checked.text
    assert checked.json()["status"] == "pending"
    assert clink_calls == 1
    assert nwc_calls == 0


def test_malformed_clink_success_response_does_not_fall_back(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)

    def malformed(ndebit: str, invoice: str, amount_sats: int, description: str) -> ClinkPayResult:
        del ndebit, invoice, amount_sats, description
        raise ClinkAdapterError(
            "invalid_wallet_response",
            "wallet returned an invalid response",
            retryable=False,
        )

    def unexpected_nwc(uri: str, invoice: str):
        del uri, invoice
        raise AssertionError("an ambiguous CLINK response must not fall back")

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", malformed)
    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", unexpected_nwc)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 502
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        assert payment.clink_state == "unknown"
        assert payment.clink_nwc_fallback is False
        assert payment.nwc_attempt_count == 0


def test_local_clink_failure_does_not_authorize_nwc_fallback(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)

    def invalid_request(
        ndebit: str, invoice: str, amount_sats: int, description: str
    ) -> ClinkPayResult:
        del ndebit, invoice, amount_sats, description
        raise ClinkAdapterError("invalid_request", "invalid request", retryable=False)

    def unexpected_nwc(uri: str, invoice: str):
        del uri, invoice
        raise AssertionError("a local CLINK failure must not fall back")

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", invalid_request)
    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", unexpected_nwc)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 502
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        assert payment.clink_state == "unknown"
        assert payment.clink_nwc_fallback is False
        assert payment.nwc_attempt_count == 0


def test_missing_clink_credential_does_not_authorize_nwc_fallback(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)

    def unavailable(*args, **kwargs):
        del args, kwargs
        raise ValueError("credential unavailable")

    def unexpected_nwc(uri: str, invoice: str):
        del uri, invoice
        raise AssertionError("a local credential failure must not fall back")

    monkeypatch.setattr("blindport.services.payments.decrypt_clink_credential", unavailable)
    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", unexpected_nwc)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 200
    assert response.json()["status"] == "failed"
    assert response.json()["clink_error_code"] == "credential_unavailable"
    assert response.json()["clink_nwc_fallback"] is False
    assert response.json()["nwc_attempt_count"] == 0


def test_clink_rejection_without_nwc_fails_and_disables_auto_renew(app_client, monkeypatch) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client)
    enabled = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )
    assert enabled.status_code == 200

    def deny(ndebit: str, invoice: str, amount_sats: int, description: str) -> ClinkPayResult:
        del ndebit, invoice, amount_sats, description
        raise ClinkAdapterError(
            "invalid_amount",
            "amount rejected",
            retryable=False,
            wallet_rejection=True,
        )

    monkeypatch.setattr(factory.get_clink_adapter(), "pay_invoice", deny)

    response = _create_clink(client, token, subscription["id"])

    assert response.status_code == 200, response.text
    assert response.json()["status"] == "failed"
    assert response.json()["clink_nwc_fallback"] is False
    from blindport.db import engine

    with Session(engine) as session:
        refreshed = session.exec(select(Subscription)).one()
        assert refreshed.auto_renew is False


def test_clink_pointer_is_encrypted_and_locked_during_open_payment(app_client) -> None:
    client, _ = app_client
    token, subscription = _connected_subscription(client)
    pointer = "ndebit1subscription-test"
    created = _create_clink(client, token, subscription["id"])
    assert created.status_code == 200
    assert created.json()["status"] == "pending"

    status = client.get("/api/v1/me/clink", headers=_auth(token))
    rotated = client.post(
        "/api/v1/me/clink",
        json={"ndebit": "ndebit1replacement"},
        headers=_auth(token),
    )

    assert status.status_code == 200
    assert status.json()["has_clink"] is True
    assert pointer not in status.text
    assert status.headers["Cache-Control"] == "no-store"
    assert rotated.status_code == 409
    assert pointer not in rotated.text

    from blindport.db import engine

    with Session(engine) as session:
        row = session.exec(select(Payment)).one()
        user = session.exec(select(User).where(User.is_admin.is_(False))).one()  # type: ignore[union-attr]
        assert row.clink_credential_generation == user.clink_generation
        assert pointer not in (user.clink_ciphertext or "")


def test_auto_renew_prefers_clink_when_both_wallets_are_connected(app_client) -> None:
    client, factory = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)
    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    enabled = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )
    assert enabled.status_code == 200

    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    with Session(engine) as session:
        stored = subscription_by_public_id(session, subscription["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) + timedelta(minutes=1)
        session.add(stored)
        session.commit()

    summary = reconcile_pending_payments_once()

    assert summary.auto_renewed == 1
    with Session(engine) as session:
        renewal = session.exec(select(Payment).where(Payment.method == PaymentMethod.CLINK)).one()
        assert renewal.clink_attempt_count == 1
        assert renewal.clink_state == "pending"
        assert renewal.nwc_attempt_count == 0


def test_removing_one_wallet_preserves_auto_renew_until_last_wallet_is_removed(
    app_client,
) -> None:
    client, _ = app_client
    token, subscription = _connected_subscription(client, with_nwc=True)
    assert (
        client.post(
            f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
            headers=_auth(token),
        ).status_code
        == 200
    )

    assert client.delete("/api/v1/me/clink", headers=_auth(token)).status_code == 200

    from blindport.db import engine

    with Session(engine) as session:
        assert session.exec(select(Subscription)).one().auto_renew is True

    assert client.delete("/api/v1/me/nwc", headers=_auth(token)).status_code == 200
    with Session(engine) as session:
        assert session.exec(select(Subscription)).one().auto_renew is False
