"""Enabled payment method enforcement at public adapter boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _subscription(client, token: str) -> dict:
    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    "legacy_status",
    [
        "pending",
        "processing",
        "paid",
        "failed",
        "expired",
    ],
)
def test_legacy_cashu_rows_are_read_only_without_provider_settlement(
    app_client, monkeypatch, legacy_status: str
) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)

    from blindport.core.models import Payment, PaymentMethod, PaymentStatus, Subscription
    from blindport.db import engine
    from blindport.services import payments

    with Session(engine) as session:
        stored_subscription = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(subscription["id"]))
        ).one()
        legacy_payment = Payment(
            subscription_id=stored_subscription.id or 0,
            method=PaymentMethod.CASHU,
            status=PaymentStatus(legacy_status),
            amount_sats=1000,
            cashu_token="legacy-token",
        )
        session.add(legacy_payment)
        session.commit()
        payment_id = legacy_payment.id
        assert payment_id is not None

    def unexpected_adapter():
        raise AssertionError("legacy rows must not reach a payment provider")

    monkeypatch.setattr(payments, "get_lightning_adapter", unexpected_adapter)
    response = client.get(f"/api/v1/payments/{payment_id}", headers=_auth(token))
    listed = client.get("/api/v1/payments", headers=_auth(token))

    assert response.status_code == 200
    assert response.json()["method"] == "cashu"
    assert response.json()["status"] == legacy_status
    assert "cashu_token" not in response.json()
    assert listed.status_code == 200
    expected_open_ids = (
        [payment_id]
        if legacy_status in {PaymentStatus.PENDING.value, PaymentStatus.PROCESSING.value}
        else []
    )
    assert [payment["id"] for payment in listed.json()] == expected_open_ids
    with Session(engine) as session:
        persisted = session.get(Payment, payment_id)
        assert persisted is not None
        assert persisted.status.value == legacy_status
        assert persisted.cashu_token == "legacy-token"


def test_cashu_creation_and_removed_routes_are_rejected(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)

    create = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "cashu"},
        headers=_auth(token),
    )

    assert create.status_code == 422
    method_schema = client.get("/openapi.json").json()["components"]["schemas"][
        "CreatePaymentRequest"
    ]["properties"]["method"]
    assert method_schema["enum"] == ["lightning", "nwc", "clink", "stablecoin_swap"]
    for route in (
        "/api/v1/payments/cashu-submit",
        "/api/v1/payments/cashu-quote",
        "/api/v1/payments/cashu-mint-and-redeem",
    ):
        assert client.post(route, json={}, headers=_auth(token)).status_code == 405


def test_disabled_nwc_setup_creation_poll_and_auto_renew_skip_adapters(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    setup = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://enabled"},
        headers=_auth(token),
    )
    assert setup.status_code == 200
    subscription = _subscription(client, token)
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "nwc"},
        headers=_auth(token),
    ).json()

    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "PAYMENT_ENABLED_METHODS", "lightning")

    def unexpected_adapter(*args, **kwargs):
        raise AssertionError("disabled NWC must not reach an adapter")

    monkeypatch.setattr(factory.get_nwc_adapter(), "lookup_invoice", unexpected_adapter)
    monkeypatch.setattr(factory.get_lightning_adapter(), "create_invoice", unexpected_adapter)

    setup_disabled = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://disabled"},
        headers=_auth(token),
    )
    create_disabled = client.post(
        "/api/v1/payments",
        json={"subscription_id": _subscription(client, token)["id"], "method": "nwc"},
        headers=_auth(token),
    )
    poll_disabled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    renew_disabled = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )

    for response in (setup_disabled, create_disabled, poll_disabled, renew_disabled):
        assert response.status_code == 400
        assert response.json()["detail"] == "payment method nwc is disabled"


def test_stablecoin_kill_switch_blocks_creation_but_reconciles_issued_invoice(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]

    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    payment = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": _subscription(client, token)["id"],
            "method": "stablecoin_swap",
        },
        headers=_auth(token),
    ).json()
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", False)

    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    create = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": _subscription(client, token)["id"],
            "method": "stablecoin_swap",
        },
        headers=_auth(token),
    )
    poll = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))

    assert create.status_code == 400
    assert create.json()["detail"] == "payment method stablecoin_swap is disabled"
    assert poll.status_code == 200
    assert poll.json()["status"] == "paid"


def test_disabled_stablecoin_reservation_does_not_block_lightning_creation(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]

    from blindport.core.models import Payment, PaymentStatus, Subscription
    from blindport.db import engine
    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    stablecoin_subscription = _subscription(client, token)
    stablecoin_payment = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": stablecoin_subscription["id"],
            "method": "stablecoin_swap",
        },
        headers=_auth(token),
    ).json()
    lightning_subscription = _subscription(client, token)

    with Session(engine) as session:
        stored_subscription = session.exec(
            select(Subscription).where(
                Subscription.public_id == UUID(stablecoin_subscription["id"])
            )
        ).one_or_none()
        assert stored_subscription is not None
        stored_subscription.reservation_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored_subscription)
        session.commit()

    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", False)
    adapter = factory.get_lightning_adapter()
    original_is_invoice_paid = adapter.is_invoice_paid

    observed_hashes: list[str] = []

    def observe_stablecoin_invoice(payment_hash: str) -> bool:
        observed_hashes.append(payment_hash)
        return original_is_invoice_paid(payment_hash)

    monkeypatch.setattr(adapter, "is_invoice_paid", observe_stablecoin_invoice)
    lightning = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": lightning_subscription["id"],
            "method": "lightning",
        },
        headers=_auth(token),
    )

    assert lightning.status_code == 200, lightning.text
    assert lightning.json()["method"] == "lightning"
    with Session(engine) as session:
        stored_payment = session.get(Payment, stablecoin_payment["id"])
        stored_subscription = session.exec(
            select(Subscription).where(
                Subscription.public_id == UUID(stablecoin_subscription["id"])
            )
        ).one_or_none()
        assert stored_payment is not None
        assert stored_payment.status == PaymentStatus.PENDING
        assert stored_subscription is not None
        assert stored_subscription.reservation_payment_id == stored_payment.id
    assert stablecoin_payment["payment_hash"] in observed_hashes
