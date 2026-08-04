"""Enabled payment method enforcement at public adapter boundaries."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

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


def test_disabled_cashu_operations_never_call_adapter(app_client, monkeypatch) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _subscription(client, token)
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "cashu"},
        headers=_auth(token),
    ).json()

    from blindport.api import v1
    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "PAYMENT_ENABLED_METHODS", "lightning")

    def unexpected_adapter():
        raise AssertionError("disabled Cashu must not reach its adapter")

    monkeypatch.setattr(payments, "get_cashu_adapter", unexpected_adapter)
    monkeypatch.setattr(v1, "get_cashu_adapter", unexpected_adapter)

    create = client.post(
        "/api/v1/payments",
        json={"subscription_id": _subscription(client, token)["id"], "method": "cashu"},
        headers=_auth(token),
    )
    submit = client.post(
        "/api/v1/payments/cashu-submit",
        json={"payment_id": payment["id"], "cashu_token": "cashu-test"},
        headers=_auth(token),
    )
    quote = client.post(
        "/api/v1/payments/cashu-quote",
        json={"payment_id": payment["id"]},
        headers=_auth(token),
    )
    redeem = client.post(
        "/api/v1/payments/cashu-mint-and-redeem",
        json={"payment_id": payment["id"], "quote_id": "quote"},
        headers=_auth(token),
    )

    for response in (create, submit, quote, redeem):
        assert response.status_code == 400
        assert response.json()["detail"] == "payment method cashu is disabled"


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


def test_stablecoin_kill_switch_blocks_creation_and_polling_before_lnd(
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

    def unexpected_adapter(*args, **kwargs):
        raise AssertionError("disabled stablecoin checkout must not reach LND")

    monkeypatch.setattr(factory.get_lightning_adapter(), "is_invoice_paid", unexpected_adapter)
    create = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": _subscription(client, token)["id"],
            "method": "stablecoin_swap",
        },
        headers=_auth(token),
    )
    poll = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))

    for response in (create, poll):
        assert response.status_code == 400
        assert response.json()["detail"] == "payment method stablecoin_swap is disabled"


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

    def stablecoin_must_not_reach_lnd(payment_hash: str) -> bool:
        if payment_hash == stablecoin_payment["payment_hash"]:
            raise AssertionError("disabled stablecoin checkout must not reach LND")
        return original_is_invoice_paid(payment_hash)

    monkeypatch.setattr(adapter, "is_invoice_paid", stablecoin_must_not_reach_lnd)
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
