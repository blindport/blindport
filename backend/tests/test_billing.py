"""Fixed monthly and yearly billing contract tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session
from subscription_helpers import subscription_by_public_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _settle(client, factory, token: str, payment: dict) -> dict:
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    response = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert response.status_code == 200, response.text
    return response.json()


def _configure_wireguard(monkeypatch) -> None:
    from blindport.services import catalog, subscriptions

    for module in (catalog, subscriptions):
        monkeypatch.setattr(module.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
        monkeypatch.setattr(module.settings, "WIREGUARD_RELAY_PUBLIC_KEY", "A" * 44)
        monkeypatch.setattr(module.settings, "WIREGUARD_ENDPOINT", "relay:51820")


def test_catalog_and_ip_api_defaults_are_wireguard_yearly(app_client, monkeypatch) -> None:
    _configure_wireguard(monkeypatch)
    client, _ = app_client
    catalog = client.get("/api/v1/catalog").json()
    assert catalog["yearly_billing_enabled"] is True
    prices = {
        item["product"]: (item["monthly_price_sats"], item["yearly_price_sats"])
        for item in catalog["products"]
    }
    assert prices == {"ip": (7500, 75000), "port": (1500, 15000), "relay": (3000, 30000)}

    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    assert subscription["delivery"] == "wireguard"
    assert subscription["billing_term"] == "yearly"
    assert subscription["period_days"] == 365
    assert subscription["monthly_price_sats"] == 7500
    assert subscription["yearly_price_sats"] == 75000

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    assert (payment["billing_term"], payment["period_days"], payment["amount_sats"]) == (
        "yearly",
        365,
        75000,
    )


@pytest.mark.parametrize(
    ("request_body", "message"),
    [
        (
            {"product": "ip", "delivery": "framed"},
            "Blindport IP is available with WireGuard delivery only",
        ),
        (
            {"product": "ip", "billing_term": "monthly"},
            "WireGuard Blindport IP is available with yearly billing only",
        ),
    ],
)
def test_ip_subscription_rejects_explicit_legacy_delivery_or_term(
    app_client, request_body, message
) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post("/api/v1/subscriptions", json=request_body, headers=_auth(token))

    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == f"Value error, {message}"


def test_yearly_anonymous_order_and_omitted_payment_term_use_preference(app_client) -> None:
    client, _ = app_client
    order = client.post(
        "/api/v2/orders",
        json={"product": "port", "billing_term": "yearly"},
    )
    assert order.status_code == 201, order.text
    body = order.json()
    assert (body["billing_term"], body["period_days"]) == ("yearly", 365)
    assert (body["monthly_price_sats"], body["yearly_price_sats"]) == (1500, 15000)
    assert body["subscription"]["billing_term"] == "yearly"

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": body["subscription"]["id"], "method": "lightning"},
        headers=_auth(body["token"]),
    )
    assert payment.status_code == 200, payment.text
    assert (payment.json()["billing_term"], payment.json()["period_days"]) == ("yearly", 365)
    assert payment.json()["amount_sats"] == 15000


def test_yearly_activation_and_renewal_use_exact_payment_days(app_client, monkeypatch) -> None:
    _configure_wireguard(monkeypatch)
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "billing_term": "yearly"},
        headers=_auth(token),
    ).json()

    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    assert (initial["amount_sats"], initial["period_days"]) == (75000, 365)
    _settle(client, factory, token, initial)
    active = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    start = datetime.fromisoformat(active["current_period_start"])
    first_end = datetime.fromisoformat(active["current_period_end"])
    assert first_end - start == timedelta(days=365)
    assert active["billing_term"] == "yearly"

    yearly_renewal = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    ).json()
    _settle(client, factory, token, yearly_renewal)
    renewed = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    second_end = datetime.fromisoformat(renewed["current_period_end"])
    assert second_end - first_end == timedelta(days=365)

    monthly_renewal = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "monthly",
        },
        headers=_auth(token),
    )
    assert monthly_renewal.status_code == 400
    assert (
        monthly_renewal.json()["detail"]
        == "WireGuard Blindport IP is available with yearly billing only"
    )


def test_delayed_settlement_uses_payment_snapshots_not_current_preference_or_config(
    app_client,
    monkeypatch,
) -> None:
    _configure_wireguard(monkeypatch)
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    ).json()

    from blindport.core.models import BillingTerm
    from blindport.db import engine
    from blindport.services import subscriptions as subscriptions_service

    monkeypatch.setattr(subscriptions_service.settings, "IP_YEARLY_SATS", 1)

    with Session(engine) as session:
        stored = subscription_by_public_id(session, subscription["id"])
        assert stored is not None
        stored.billing_term = BillingTerm.MONTHLY
        session.add(stored)
        session.commit()

    settled = _settle(client, factory, token, payment)
    assert (settled["billing_term"], settled["period_days"], settled["amount_sats"]) == (
        "yearly",
        365,
        75000,
    )
    active = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    start = datetime.fromisoformat(active["current_period_start"]).astimezone(UTC)
    end = datetime.fromisoformat(active["current_period_end"]).astimezone(UTC)
    assert end - start == timedelta(days=365)
    assert active["billing_term"] == "yearly"


def test_invalid_billing_terms_are_rejected_strictly(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    for value in ("annual", "YEARLY", 365, True):
        response = client.post(
            "/api/v1/subscriptions",
            json={"product": "ip", "billing_term": value},
            headers=_auth(token),
        )
        assert response.status_code == 422


def test_yearly_issuance_gate_preserves_monthly_api_and_existing_invoice(
    app_client,
    monkeypatch,
) -> None:
    _configure_wireguard(monkeypatch)
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    yearly_payment = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    ).json()

    from blindport.services import catalog, subscriptions

    monkeypatch.setattr(catalog.settings, "BILLING_YEARLY_ENABLED", False)
    monkeypatch.setattr(subscriptions.settings, "BILLING_YEARLY_ENABLED", False)
    assert client.get("/api/v1/catalog").json()["yearly_billing_enabled"] is False

    existing = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    )
    assert existing.status_code == 200
    assert existing.json()["id"] == yearly_payment["id"]

    other_token = client.post("/api/v1/signup").json()["token"]
    blocked_subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "billing_term": "yearly"},
        headers=_auth(other_token),
    )
    assert blocked_subscription.status_code == 400
    assert blocked_subscription.json()["detail"] == "yearly billing is not enabled"

    monthly_subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=_auth(other_token),
    )
    assert monthly_subscription.status_code == 200
    blocked_payment = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": monthly_subscription.json()["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(other_token),
    )
    assert blocked_payment.status_code == 400
    assert blocked_payment.json()["detail"] == "yearly billing is not enabled"


@pytest.mark.parametrize(
    ("period_days", "amount_sats", "error"),
    [(30, 50000, "invalid period"), (365, 0, "invalid amount")],
)
def test_invalid_payment_snapshot_cannot_transition_to_paid(
    app_client,
    monkeypatch,
    period_days: int,
    amount_sats: int,
    error: str,
) -> None:
    _configure_wireguard(monkeypatch)
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "billing_term": "yearly"},
        headers=_auth(token),
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services.payments import check_and_settle_payment

    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        assert stored is not None
        stored.period_days = period_days
        stored.amount_sats = amount_sats
        session.add(stored)
        session.commit()

    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        assert stored is not None
        with pytest.raises(ValueError, match=error):
            check_and_settle_payment(session, stored)

    with Session(engine) as session:
        stored_payment = session.get(Payment, payment["id"])
        stored_subscription = subscription_by_public_id(session, subscription["id"])
        assert stored_payment is not None and stored_subscription is not None
        assert stored_payment.status == PaymentStatus.PENDING
        assert stored_subscription.current_period_end is None
