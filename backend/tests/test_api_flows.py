"""End-to-end API tests: signup -> subscription -> Lightning payment -> activation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _convert_to_historical_framed_ip(public_id: str) -> None:
    from blindport.core.models import DeliveryMode, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        subscription = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(public_id))
        ).one()
        subscription.delivery = DeliveryMode.FRAMED
        subscription.assigned_ip = "203.0.113.10"
        session.add(subscription)
        session.commit()


def test_signup_and_me(app_client) -> None:
    client, _ = app_client
    r = client.post("/api/v2/signup")
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    account_id = r.json()["account_id"]
    assert token
    assert UUID(account_id).version == 4
    assert set(r.json()) == {"token", "account_id"}

    me = client.get("/api/v2/me", headers=_auth(token))
    assert me.status_code == 200
    assert me.json()["account_id"] == account_id
    assert "user_id" not in me.json()
    assert me.json()["subscriptions"] == []


def test_v1_account_contract_retains_legacy_integer_identity(app_client) -> None:
    client, _ = app_client

    signup = client.post("/api/v1/signup")
    assert signup.status_code == 200
    assert set(signup.json()) == {"token", "user_id"}
    assert signup.json()["user_id"] >= 1

    me = client.get("/api/v1/me", headers=_auth(signup.json()["token"]))
    assert me.status_code == 200
    assert set(me.json()) == {"user_id", "is_admin", "created_at", "subscriptions"}
    assert me.json()["user_id"] == signup.json()["user_id"]


def test_client_version_is_authenticated_and_operator_configured(app_client, monkeypatch) -> None:
    from blindport.config import settings

    client, _ = app_client
    assert client.get("/api/v1/client/version").status_code == 401
    token = client.post("/api/v2/signup").json()["token"]
    monkeypatch.setattr(settings, "BLINDPORTD_VERSION", "abc1234")

    response = client.get("/api/v1/client/version", headers=_auth(token))

    assert response.status_code == 200
    assert response.json() == {"version": "abc1234"}


def test_subscription_public_ids_hide_internal_keys_and_enforce_ownership(app_client) -> None:
    client, _ = app_client
    owner = client.post("/api/v1/signup").json()["token"]
    other = client.post("/api/v1/signup").json()["token"]
    created = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(owner)
    ).json()
    public_id = UUID(created["id"])
    assert public_id.version == 4

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.exec(select(Subscription).where(Subscription.public_id == public_id)).one()
        assert stored.id is not None
        subscription_pk = stored.id
    assert created["id"] != str(subscription_pk)

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": created["id"], "method": "lightning"},
        headers=_auth(owner),
    )
    assert payment.status_code == 200
    assert payment.json()["subscription_id"] == created["id"]
    assert str(subscription_pk) not in {created["id"], payment.json()["subscription_id"]}

    cross_account = client.post(
        "/api/v1/payments",
        json={"subscription_id": created["id"], "method": "lightning"},
        headers=_auth(other),
    )
    assert cross_account.status_code == 404
    assert (
        client.post(
            f"/api/v1/subscriptions/{created['id']}/auto-renew?enable=false",
            headers=_auth(other),
        ).status_code
        == 404
    )
    assert (
        client.post(
            "/api/v1/payments",
            json={"subscription_id": "not-a-uuid", "method": "lightning"},
            headers=_auth(owner),
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/subscriptions/not-a-uuid/auto-renew?enable=false",
            headers=_auth(owner),
        ).status_code
        == 422
    )


def test_ip_lightning_flow(app_client, monkeypatch) -> None:
    from blindport.api import v1

    client, factory = app_client
    qr_payloads: list[str] = []
    render_svg = v1.qr.render_svg

    def capture_qr_payload(data: str, **kwargs: int) -> str:
        qr_payloads.append(data)
        return render_svg(data, **kwargs)

    monkeypatch.setattr(v1.qr, "render_svg", capture_qr_payload)
    token = client.post("/api/v1/signup").json()["token"]

    # Create subscription
    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    assert sub["status"] == "pending"
    assert sub["assigned_ip"] is None

    # Create lightning payment
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    assert pay["invoice"].startswith("lnbcrt")
    assert pay["lightning_uri"] == f"lightning:{pay['invoice']}"
    assert qr_payloads == [pay["invoice"].upper()]
    assert pay["qr_svg"].startswith("<svg")
    assert 'viewBox="0 0 ' in pay["qr_svg"]
    assert " width=" not in pay["qr_svg"].split(">", 1)[0]
    assert pay["status"] == "pending"

    # Poll - still pending
    p2 = client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token)).json()
    assert p2["status"] == "pending"

    # Simulate payment settlement via the mock adapter
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])

    # Poll again - should be paid + subscription activated
    p3 = client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token)).json()
    assert p3["status"] == "paid"

    me = client.get("/api/v1/me", headers=_auth(token)).json()
    assert me["subscriptions"][0]["status"] == "active"
    assert me["subscriptions"][0]["assigned_ip"].startswith("198.51.100.")
    assert me["subscriptions"][0]["assigned_port"] is None
    assert me["subscriptions"][0]["transport"] == "tcp"
    assert me["subscriptions"][0]["delivery"] == "wireguard"
    assert me["subscriptions"][0]["billing_term"] == "yearly"


def test_stablecoin_swap_charges_markup_and_settles_only_through_lnd(
    app_client, monkeypatch
) -> None:
    from blindport.services import payments

    client, factory = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MARKUP_BPS", 1000)
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_DEFAULT_ASSET", "USDC-BASE")
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "boltz")
    monkeypatch.setattr(payments.settings, "BOLTZ_WEB_URL", "https://boltz.example")
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()

    response = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    )

    assert response.status_code == 200, response.text
    payment = response.json()
    assert payment["method"] == "stablecoin_swap"
    assert payment["base_amount_sats"] == 75000
    assert payment["markup_sats"] == 7500
    assert payment["amount_sats"] == 82500
    assert (
        payment["standard_period_days"],
        payment["bonus_days"],
        payment["stablecoin_surcharge_sats"],
        payment["stablecoin_minimum_topup_sats"],
    ) == (365, 0, 7500, 0)
    assert (payment["billing_term"], payment["period_days"]) == ("yearly", 365)
    assert payment["stablecoin_asset"] == "USDC-BASE"
    assert payment["stablecoin_provider"] == "boltz"
    assert payment["lightning_uri"] is None
    assert payment["qr_svg"] is None
    checkout = urlsplit(payment["stablecoin_checkout_url"])
    assert (checkout.scheme, checkout.netloc, checkout.path) == (
        "https",
        "boltz.example",
        "/",
    )
    assert parse_qs(checkout.query) == {
        "sendAsset": ["USDC-BASE"],
        "receiveAsset": ["LN"],
        "destination": [payment["invoice"]],
    }
    expires_at = datetime.fromisoformat(payment["expires_at"])
    assert expires_at.tzinfo is not None
    assert expires_at.utcoffset() == timedelta(0)
    assert timedelta(seconds=1150) <= expires_at - datetime.now(UTC) <= timedelta(seconds=1200)

    monkeypatch.setattr(payments.settings, "BOLTZ_WEB_URL", "https://changed.example")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_DEFAULT_ASSET", "USDT0-ETH")
    pending = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).json()
    assert pending["status"] == "pending"
    assert pending["stablecoin_provider"] == "boltz"
    assert pending["stablecoin_asset"] == "USDC-BASE"
    assert pending["stablecoin_checkout_url"] == payment["stablecoin_checkout_url"]
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    paid = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).json()
    assert paid["status"] == "paid"
    assert paid["base_amount_sats"] == 75000
    assert paid["markup_sats"] == 7500
    assert (
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]["status"]
        == "active"
    )


def test_lightning_swap_checkout_prefills_encoded_invoice_and_snapshots_origin(
    app_client, monkeypatch
) -> None:
    from blindport.services import payments

    client, _ = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(
        payments.settings, "LIGHTNING_SWAP_WEB_URL", "https://lightning-swap.example"
    )
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()

    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()

    assert created["stablecoin_provider"] == "lightning_swap"
    assert created["stablecoin_asset"] == "USDCSOL"
    assert created["bonus_days"] == 0
    assert created["period_days"] == created["standard_period_days"] == 365
    assert created["markup_sats"] == created["stablecoin_surcharge_sats"]
    assert created["stablecoin_minimum_topup_sats"] == 0
    assert created["stablecoin_checkout_url"] != (
        f"https://lightning-swap.example/{created['invoice']}"
    )
    checkout = urlsplit(created["stablecoin_checkout_url"])
    assert (checkout.scheme, checkout.netloc, checkout.path, checkout.fragment) == (
        "https",
        "lightning-swap.example",
        "/",
        "",
    )
    assert parse_qs(checkout.query) == {"invoice": [created["invoice"]]}
    assert created["invoice"] not in checkout.path

    monkeypatch.setattr(payments.settings, "LIGHTNING_SWAP_WEB_URL", "https://changed.example")
    restored = client.get(f"/api/v1/payments/{created['id']}", headers=_auth(token)).json()
    assert restored["stablecoin_provider"] == "lightning_swap"
    assert restored["stablecoin_checkout_url"] == created["stablecoin_checkout_url"]
    conflict = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    )
    assert conflict.status_code == 200
    assert conflict.json()["id"] == created["id"]
    assert conflict.json()["stablecoin_provider"] == "lightning_swap"
    assert conflict.json()["stablecoin_checkout_url"] == created["stablecoin_checkout_url"]


def test_lightning_swap_checkout_percent_encodes_reserved_invoice_characters() -> None:
    from blindport.core.models import Payment, PaymentMethod
    from blindport.services.payments import stablecoin_checkout_url

    invoice = "lnbc1test+reserved?value=one&next=two"
    payment = Payment(
        subscription_id=1,
        method=PaymentMethod.STABLECOIN_SWAP,
        amount_sats=5000,
        stablecoin_provider="lightning_swap",
        stablecoin_checkout_origin="https://lightning-swap.example",
        invoice=invoice,
    )

    checkout_url = stablecoin_checkout_url(payment)

    assert checkout_url is not None
    checkout = urlsplit(checkout_url)
    assert parse_qs(checkout.query) == {"invoice": [invoice]}
    assert "+reserved?value=one&next=two" not in checkout.query


def test_lightning_swap_manual_checkout_uses_conservative_local_floor(
    app_client, monkeypatch
) -> None:
    from blindport.services import payments

    client, _ = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MIN_INVOICE_SATS", 5000)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=_auth(token),
    ).json()

    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()

    assert created["base_amount_sats"] == 1500
    assert created["markup_sats"] == 3500
    assert created["amount_sats"] == 5000
    assert created["stablecoin_surcharge_sats"] == 150
    assert created["stablecoin_minimum_topup_sats"] == 3350
    assert (created["standard_period_days"], created["bonus_days"], created["period_days"]) == (
        30,
        61,
        91,
    )
    assert created["stablecoin_asset"] == "USDCSOL"


def test_lightning_swap_floor_topup_grants_bonus_days_and_settles_idempotently(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import Payment, Subscription
    from blindport.db import engine
    from blindport.services import payments

    client, factory = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MARKUP_BPS", 1000)
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MIN_INVOICE_SATS", 5000)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()

    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()
    repeated = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()
    assert repeated["id"] == created["id"]
    assert created["period_days"] == 91

    factory.get_lightning_adapter().mark_paid(created["payment_hash"])
    settled = client.get(f"/api/v1/payments/{created['id']}", headers=_auth(token)).json()
    assert (settled["status"], settled["period_days"], settled["bonus_days"]) == ("paid", 91, 61)

    with Session(engine) as session:
        payment = session.get(Payment, created["id"])
        stored_subscription = (
            session.get(Subscription, payment.subscription_id) if payment else None
        )
        assert payment is not None and stored_subscription is not None
        assert stored_subscription.current_period_start is not None
        assert stored_subscription.current_period_end is not None
        assert (
            stored_subscription.current_period_end - stored_subscription.current_period_start
            == timedelta(days=91)
        )


def test_legacy_stablecoin_snapshot_with_zero_surcharge_settles_standard_period(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import Payment
    from blindport.db import engine
    from blindport.services import payments

    client, factory = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MIN_INVOICE_SATS", 5000)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()

    with Session(engine) as session:
        payment = session.get(Payment, created["id"])
        assert payment is not None
        payment.stablecoin_surcharge_sats = 0
        payment.period_days = 30
        session.add(payment)
        session.commit()

    factory.get_lightning_adapter().mark_paid(created["payment_hash"])
    settled = client.get(f"/api/v1/payments/{created['id']}", headers=_auth(token)).json()
    assert (settled["status"], settled["period_days"]) == ("paid", 30)


def test_tampered_lightning_swap_bonus_snapshot_cannot_settle(app_client, monkeypatch) -> None:
    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services import payments

    client, factory = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MARKUP_BPS", 1000)
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MIN_INVOICE_SATS", 5000)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()

    with Session(engine) as session:
        payment = session.get(Payment, created["id"])
        assert payment is not None
        payment.period_days = 90
        session.add(payment)
        session.commit()

    factory.get_lightning_adapter().mark_paid(created["payment_hash"])
    with Session(engine) as session:
        payment = session.get(Payment, created["id"])
        assert payment is not None
        with pytest.raises(ValueError, match="invalid period"):
            payments.check_and_settle_payment(session, payment)

    with Session(engine) as session:
        payment = session.get(Payment, created["id"])
        assert payment is not None
        assert payment.status == PaymentStatus.PENDING


def test_stablecoin_credit_rounds_up_for_annual_and_boundary_amounts(app_client) -> None:
    del app_client
    from blindport.services.payments import stablecoin_credited_days

    assert stablecoin_credited_days(5000, 1500, 150, 365) == 1107
    assert stablecoin_credited_days(1651, 1500, 150, 30) == 31


def test_historical_prepared_lightning_swap_columns_do_not_suppress_manual_checkout(
    app_client, monkeypatch
) -> None:
    from blindport.db import engine
    from blindport.services import payments

    client, _ = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    ).json()

    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE payment SET stablecoin_api_order_enabled = true, "
                "stablecoin_order_id = :order_id, stablecoin_deposit_amount = :amount, "
                "stablecoin_deposit_address = :address, stablecoin_deposit_network = :network, "
                "stablecoin_required_confirmations = :confirmations, "
                "stablecoin_order_expires_at = :expires_at WHERE id = :payment_id"
            ),
            {
                "order_id": "PREPAREDORDER12345678901234567890",
                "amount": "5.2500",
                "address": "prepared-deposit-address",
                "network": "SOL",
                "confirmations": 1,
                "expires_at": datetime.now(UTC) + timedelta(minutes=10),
                "payment_id": created["id"],
            },
        )

    response = client.get(f"/api/v1/payments/{created['id']}", headers=_auth(token))

    assert response.status_code == 200
    restored = response.json()
    assert parse_qs(urlsplit(restored["stablecoin_checkout_url"]).query) == {
        "invoice": [created["invoice"]]
    }
    assert "stablecoin_deposit_address" not in restored


def test_payment_responses_are_private_and_conflicts_preserve_header(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert created.headers["Cache-Control"] == "no-store"
    payment = created.json()
    fetched = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    listed = client.get("/api/v1/payments", headers=_auth(token))
    conflict = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "nwc"},
        headers=_auth(token),
    )
    assert fetched.headers["Cache-Control"] == "no-store"
    assert listed.headers["Cache-Control"] == "no-store"
    assert conflict.status_code == 409
    assert conflict.headers["Cache-Control"] == "no-store"


def test_stablecoin_markup_rounds_up_without_floating_point(app_client, monkeypatch) -> None:
    del app_client
    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MARKUP_BPS", 1000)

    assert payments.stablecoin_markup_sats(1) == 1
    assert payments.stablecoin_markup_sats(10) == 1
    assert payments.stablecoin_markup_sats(11) == 2


def test_port_creation_payment_activation_config_and_resolve(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    assert sub["status"] == "pending"
    assert sub["assigned_ip"] is None
    assert sub["assigned_port"] is None
    assert sub["transport"] == "tcp"

    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert pay.status_code == 200, pay.text
    reserved = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    assert reserved["status"] == "pending"
    assert reserved["assigned_ip"] == "203.0.113.20"
    assert reserved["assigned_port"] == 10000

    payment = pay.json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).json()
    assert settled["status"] == "paid"

    config = client.get("/api/v1/client/config", headers=_auth(token)).json()
    assert config == [
        {
            "relay_endpoint": "relay:5443",
            "relay_endpoints": ["relay:5443"],
            "assigned_ip": "203.0.113.20",
            "assigned_port": 10000,
            "transport": "tcp",
            "domain": None,
            "product": "port",
            "subscription_id": sub["id"],
        }
    ]
    resolved = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert resolved["port_leases"] == [
        {"assigned_ip": "203.0.113.20", "assigned_port": 10000, "transport": "tcp"}
    ]
    assert resolved["ip_ips"] == []


def test_udp_port_activation_uses_transport_specific_socket(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "transport": "udp"},
        headers=_auth(token),
    )
    assert sub.status_code == 200, sub.text
    assert sub.json()["transport"] == "udp"

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub.json()["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    reserved = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    assert (reserved["assigned_ip"], reserved["assigned_port"], reserved["transport"]) == (
        "203.0.113.20",
        10000,
        "udp",
    )

    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    config = client.get("/api/v1/client/config", headers=_auth(token)).json()
    assert config[0]["transport"] == "udp"
    resolved = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert resolved["port_leases"] == [
        {"assigned_ip": "203.0.113.20", "assigned_port": 10000, "transport": "udp"}
    ]


@pytest.mark.parametrize("product", ["ip", "relay"])
def test_udp_transport_is_rejected_for_non_port_products(app_client, product: str) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    body = {"product": product, "transport": "udp"}
    if product == "relay":
        body["domain"] = "udp-invalid.relay.test"

    response = client.post("/api/v1/subscriptions", json=body, headers=_auth(token))

    assert response.status_code == 422
    assert "UDP transport is supported only for Blindport Port subscriptions" in response.text


def test_provisioning_endpoints_are_product_specific(app_client, monkeypatch) -> None:
    from blindport.api import v1 as v1_mod

    client, factory = app_client
    monkeypatch.setattr(v1_mod.settings, "RELAY_CONTROL_URL", "primary.example:5443")
    monkeypatch.setattr(
        v1_mod.settings,
        "RELAY_CONTROL_URLS",
        "edge-a.example:5443,edge-b.example:5443",
    )
    token = client.post("/api/v1/signup").json()["token"]

    requests = [
        {"product": "ip"},
        {"product": "port"},
        {"product": "relay", "domain": "ha.relay.test"},
    ]
    for request in requests:
        sub = client.post("/api/v1/subscriptions", json=request, headers=_auth(token)).json()
        payment = client.post(
            "/api/v1/payments",
            json={"subscription_id": sub["id"], "method": "lightning"},
            headers=_auth(token),
        ).json()
        factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
        settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
        assert settled.json()["status"] == "paid"

    config = client.get("/api/v1/client/config", headers=_auth(token)).json()
    by_product = {row["product"]: row for row in config}
    assert set(by_product) == {"port", "relay"}
    assert by_product["port"]["relay_endpoint"] == "primary.example:5443"
    assert by_product["port"]["relay_endpoints"] == ["primary.example:5443"]
    assert by_product["relay"]["relay_endpoint"] == "edge-a.example:5443"
    assert by_product["relay"]["relay_endpoints"] == [
        "edge-a.example:5443",
        "edge-b.example:5443",
    ]


def test_port_provisioning_and_authorization_expand_provider_edges(app_client, monkeypatch) -> None:
    from blindport.services import relay_routing

    client, factory = app_client
    monkeypatch.setattr(relay_routing.settings, "RELAY_CONTROL_URL", "primary.example:5443")
    monkeypatch.setattr(
        relay_routing.settings,
        "RELAY_CONTROL_URLS",
        "primary.example:5443,secondary.example:5443",
    )
    monkeypatch.setattr(relay_routing.settings, "PORT_HOSTNAME_SUFFIX", "ports.example")
    monkeypatch.setattr(
        relay_routing.settings,
        "PORT_HA_EDGES",
        '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"},'
        '{"endpoint":"secondary.example:5443","ip":"203.0.113.21"}]',
    )
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))

    account = client.get("/api/v1/me", headers=_auth(token)).json()
    active = account["subscriptions"][0]
    assert active["port_hostname"] == f"{sub['id']}.ports.example"
    assert active["port_ips"] == ["203.0.113.20", "203.0.113.21"]

    legacy_config = client.get("/api/v1/client/config", headers=_auth(token)).json()[0]
    assert legacy_config["relay_endpoint"] == "primary.example:5443"
    assert legacy_config["relay_endpoints"] == ["primary.example:5443"]
    assert "relay_assignments" not in legacy_config

    config = client.get(
        "/api/v1/client/config",
        headers={**_auth(token), "Blindport-Agent-Capabilities": "relay-assignments-v1"},
    ).json()[0]
    assert config["relay_endpoints"] == ["primary.example:5443"]
    assert config["relay_assignments"] == [
        {"relay_endpoint": "primary.example:5443", "assigned_ip": "203.0.113.20"},
        {"relay_endpoint": "secondary.example:5443", "assigned_ip": "203.0.113.21"},
    ]
    resolved = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert resolved["port_leases"] == [
        {"assigned_ip": "203.0.113.20", "assigned_port": 10000, "transport": "tcp"},
        {"assigned_ip": "203.0.113.21", "assigned_port": 10000, "transport": "tcp"},
    ]
    dashboard = client.get("/dashboard", cookies={"blindport_token": token})
    assert dashboard.status_code == 200
    assert f"{sub['id']}.ports.example:10000" in dashboard.text
    assert "203.0.113.20:10000" in dashboard.text
    assert "203.0.113.21:10000" in dashboard.text


def test_historical_framed_ip_provisioning_uses_inventory_owner_edge(
    app_client, monkeypatch
) -> None:
    from blindport.services import relay_routing

    client, factory = app_client
    monkeypatch.setattr(
        relay_routing.settings,
        "FRAMED_IP_ENDPOINTS",
        '{"203.0.113.10":"secondary.example:5443","203.0.113.11":"secondary.example:5443"}',
    )
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post("/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    _convert_to_historical_framed_ip(sub["id"])

    legacy_config = client.get("/api/v1/client/config", headers=_auth(token)).json()[0]
    assert legacy_config["relay_endpoint"] == "secondary.example:5443"
    assert legacy_config["relay_endpoints"] == ["secondary.example:5443"]
    assert "relay_assignments" not in legacy_config

    config = client.get(
        "/api/v1/client/config",
        headers={**_auth(token), "Blindport-Agent-Capabilities": "relay-assignments-v1"},
    ).json()[0]
    assert config["relay_endpoint"] == "secondary.example:5443"
    assert config["relay_assignments"] == [
        {"relay_endpoint": "secondary.example:5443", "assigned_ip": "203.0.113.10"}
    ]


def test_port_capacity_is_rejected_before_invoice_creation(app_client, monkeypatch) -> None:
    client, factory = app_client
    adapter = factory.get_lightning_adapter()
    original = adapter.create_or_lookup_invoice
    invoice_calls = 0

    def counting_create_invoice(
        amount_sats: int,
        memo: str,
        payment_preimage: bytes,
        expiry_seconds: int | None = None,
    ):
        nonlocal invoice_calls
        invoice_calls += 1
        return original(amount_sats, memo, payment_preimage, expiry_seconds)

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", counting_create_invoice)
    for expected_port in (10000, 10001):
        token = client.post("/api/v1/signup").json()["token"]
        sub = client.post(
            "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
        ).json()
        response = client.post(
            "/api/v1/payments",
            json={"subscription_id": sub["id"], "method": "lightning"},
            headers=_auth(token),
        )
        assert response.status_code == 200
        stored = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
        assert stored["assigned_port"] == expected_port

    token = client.post("/api/v1/signup").json()["token"]
    exhausted = client.post("/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token))
    assert exhausted.status_code == 409
    assert exhausted.json()["detail"] == "no TCP Blindport Port capacity"
    assert invoice_calls == 2


def test_subscription_rejects_second_live_payment(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    first = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert first.status_code == 200
    second = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "nwc"},
        headers=_auth(token),
    )
    assert second.status_code == 409
    conflict = second.json()
    assert conflict["detail"] == "a lightning payment is already pending for this subscription"
    assert conflict["existing_payment"]["id"] == first.json()["id"]
    assert conflict["existing_payment"]["method"] == "lightning"
    existing_expiry = datetime.fromisoformat(conflict["existing_payment"]["expires_at"])
    assert existing_expiry.tzinfo is not None
    assert existing_expiry.utcoffset() == timedelta(0)


def test_open_payment_listing_recovers_invoice_after_refresh(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    response = client.get("/api/v1/payments", headers=_auth(token))

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == [payment["id"]]
    assert response.json()[0]["invoice"] == payment["invoice"]
    other = client.post("/api/v1/signup").json()["token"]
    assert client.get("/api/v1/payments", headers=_auth(other)).json() == []


def test_pending_subscription_can_be_cancelled_only_without_open_payment(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    cancellable = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()

    cancelled = client.delete(f"/api/v1/subscriptions/{cancellable['id']}", headers=_auth(token))

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert cancelled.json()["assigned_ip"] is None
    rejected_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": cancellable["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert rejected_payment.status_code == 400
    assert rejected_payment.json()["detail"] == (
        "cancelled subscription cannot be paid; create a new subscription"
    )
    with_payment = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    client.post(
        "/api/v1/payments",
        json={"subscription_id": with_payment["id"], "method": "lightning"},
        headers=_auth(token),
    )
    conflict = client.delete(f"/api/v1/subscriptions/{with_payment['id']}", headers=_auth(token))
    assert conflict.status_code == 409
    assert conflict.json()["detail"] == (
        "a payment is still pending; complete it or wait for it to expire"
    )


def test_expired_unpaid_reservation_is_released_and_reused(app_client) -> None:
    client, _ = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    first_sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(first_token)
    ).json()
    first_pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": first_sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    ).json()

    from blindport.core.models import Payment, Subscription
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.get(Payment, first_pay["id"])
        subscription = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(first_sub["id"]))
        ).one()
        assert payment is not None and subscription is not None
        payment.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        subscription.reservation_expires_at = payment.expires_at
        session.add(payment)
        session.add(subscription)
        session.commit()

    expired = client.get(f"/api/v1/payments/{first_pay['id']}", headers=_auth(first_token)).json()
    assert expired["status"] == "expired"
    released = client.get("/api/v1/me", headers=_auth(first_token)).json()["subscriptions"][0]
    assert released["assigned_ip"] is None
    assert released["assigned_port"] is None

    second_token = client.post("/api/v1/signup").json()["token"]
    second_sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(second_token)
    ).json()
    client.post(
        "/api/v1/payments",
        json={"subscription_id": second_sub["id"], "method": "lightning"},
        headers=_auth(second_token),
    )
    reused = client.get("/api/v1/me", headers=_auth(second_token)).json()["subscriptions"][0]
    assert (reused["assigned_ip"], reused["assigned_port"]) == ("203.0.113.20", 10000)


def test_payment_creation_failure_retains_outbox_and_retry_recovers(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()

    adapter = factory.get_lightning_adapter()
    original = adapter.create_or_lookup_invoice

    def fail_invoice(
        amount_sats: int,
        memo: str,
        payment_preimage: bytes,
        expiry_seconds: int | None = None,
    ):
        raise RuntimeError("invoice backend unavailable")

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", fail_invoice)
    failed = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert failed.status_code == 502
    assert failed.json()["detail"] == "Lightning invoice provider is unavailable"
    stored = client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]
    assert stored["assigned_ip"] == "203.0.113.20"
    assert stored["assigned_port"] == 10000

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        staged = session.exec(select(Payment)).one()
        assert staged.invoice is None
        assert staged.invoice_idempotency_key is not None
        payment_id = staged.id

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", original)
    recovered = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert recovered.status_code == 200
    assert recovered.json()["id"] == payment_id
    assert recovered.json()["invoice"]


def test_expired_port_is_unauthorized_quarantined_then_reallocated(app_client) -> None:
    client, factory = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(first_token)
    ).json()
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    ).json()
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])
    client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(first_token))

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(sub["id"]))
        ).one()
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    old_resolve = client.post(
        "/internal/v1/resolve",
        json={"token": first_token},
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert old_resolve["port_leases"] == []

    retry_during_quarantine = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    assert retry_during_quarantine.status_code == 409
    assert "assignment is quarantined; retry after" in retry_during_quarantine.json()["detail"]

    second_token = client.post("/api/v1/signup").json()["token"]
    second_sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(second_token)
    ).json()
    client.post(
        "/api/v1/payments",
        json={"subscription_id": second_sub["id"], "method": "lightning"},
        headers=_auth(second_token),
    )
    replacement = client.get("/api/v1/me", headers=_auth(second_token)).json()["subscriptions"][0]
    assert (replacement["assigned_ip"], replacement["assigned_port"]) == (
        "203.0.113.20",
        10001,
    )

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(sub["id"]))
        ).one()
        assert stored is not None
        stored.resource_quarantined_until = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    released_retry = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    assert released_retry.status_code == 200, released_retry.text
    current = client.get("/api/v1/me", headers=_auth(first_token)).json()["subscriptions"][0]
    assert (current["assigned_ip"], current["assigned_port"]) == (
        "203.0.113.20",
        10000,
    )


def test_subscription_resource_uniqueness_constraints(app_client) -> None:
    client, _ = app_client
    client.post("/api/v1/signup")

    from blindport.core.models import (
        Payment,
        PaymentMethod,
        PaymentStatus,
        ProductType,
        Subscription,
        Transport,
    )
    from blindport.db import engine

    indexes = inspect(engine).get_indexes("subscription")
    constraints = inspect(engine).get_unique_constraints("subscription")
    assert any(index["name"] == "uq_subscription_dedicated_ip" for index in indexes)
    payment_indexes = inspect(engine).get_indexes("payment")
    assert any(index["name"] == "uq_payment_open_subscription" for index in payment_indexes)
    assert any(
        constraint["column_names"] == ["assigned_ip", "assigned_port", "transport"]
        for constraint in constraints
    )

    with Session(engine) as session:
        first = Subscription(
            user_id=1,
            product=ProductType.PORT,
            assigned_ip="203.0.113.20",
            assigned_port=10000,
            monthly_price_sats=1,
        )
        duplicate = Subscription(
            user_id=1,
            product=ProductType.PORT,
            assigned_ip="203.0.113.20",
            assigned_port=10000,
            monthly_price_sats=1,
        )
        session.add(first)
        session.commit()
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()

    with Session(engine) as session:
        udp = Subscription(
            user_id=1,
            product=ProductType.PORT,
            assigned_ip="203.0.113.20",
            assigned_port=10000,
            transport=Transport.UDP,
            monthly_price_sats=1,
        )
        session.add(udp)
        session.commit()

    with Session(engine) as session:
        first = Payment(
            subscription_id=1,
            method=PaymentMethod.LIGHTNING,
            amount_sats=1,
        )
        duplicate = Payment(
            subscription_id=1,
            method=PaymentMethod.NWC,
            amount_sats=1,
        )
        session.add(first)
        session.commit()
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()

    with Session(engine) as session:
        processing = Payment(
            subscription_id=2,
            method=PaymentMethod.NWC,
            status=PaymentStatus.PROCESSING,
            amount_sats=1,
        )
        duplicate = Payment(
            subscription_id=2,
            method=PaymentMethod.LIGHTNING,
            amount_sats=1,
        )
        session.add(processing)
        session.commit()
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()

    with Session(engine) as session:
        first = Subscription(
            user_id=1,
            product=ProductType.IP,
            assigned_ip="203.0.113.10",
            monthly_price_sats=1,
        )
        duplicate = Subscription(
            user_id=1,
            product=ProductType.IP,
            assigned_ip="203.0.113.10",
            monthly_price_sats=1,
        )
        session.add(first)
        session.commit()
        session.add(duplicate)
        with pytest.raises(IntegrityError):
            session.commit()


def test_relay_canonicalizes_idna_and_rejects_cross_user_duplicate(app_client) -> None:
    client, _ = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    second_token = client.post("/api/v1/signup").json()["token"]

    created = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "BÜCHER.Example."},
        headers=_auth(first_token),
    )
    assert created.status_code == 200, created.text
    assert created.json()["domain"] == "xn--bcher-kva.example"

    duplicate = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "xn--bcher-kva.example"},
        headers=_auth(second_token),
    )
    assert duplicate.status_code == 400
    assert duplicate.json()["detail"] == "domain already has a subscription"

    from blindport.db import engine

    constraints = inspect(engine).get_unique_constraints("subscription")
    assert any(constraint["column_names"] == ["domain"] for constraint in constraints)


@pytest.mark.parametrize(
    "domain",
    [
        "127.0.0.1",
        "2001:db8::1",
        "-bad.example",
        "bad_.example",
        "example.com..",
        f"{'a' * 64}.example",
        ".".join(["a" * 63] * 4),
        "xn--.example",
    ],
)
def test_relay_rejects_invalid_hostnames(app_client, domain: str) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": domain},
        headers=_auth(token),
    )
    assert response.status_code == 400


def test_nwc_flow(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]

    # Set NWC URI
    r = client.post(
        "/api/v1/me/nwc", json={"nwc_uri": "nostr+walletconnect://abc"}, headers=_auth(token)
    )
    assert r.status_code == 200

    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()

    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "nwc"},
        headers=_auth(token),
    ).json()
    assert pay["nwc_state"] == "pending"
    assert pay["nwc_attempt_count"] == 1
    assert pay["status"] == "pending"

    factory.get_nwc_adapter().mark_settled(pay["payment_hash"])
    p2 = client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token)).json()
    assert p2["status"] == "paid"


def test_client_config_endpoint(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])
    # Settle.
    client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token))
    _convert_to_historical_framed_ip(sub["id"])

    cfg = client.get("/api/v1/client/config", headers=_auth(token)).json()
    assert len(cfg) == 1
    assert cfg[0]["product"] == "ip"
    assert cfg[0]["assigned_ip"]


def test_expired_subscription_is_removed_from_client_config(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    ).json()
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])
    client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token))
    _convert_to_historical_framed_ip(sub["id"])

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(sub["id"]))
        ).one()
        assert stored is not None
        assigned_ip = stored.assigned_ip
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    cfg = client.get("/api/v1/client/config", headers=_auth(token))
    assert cfg.status_code == 200
    assert cfg.json() == []
    listed = client.get("/api/v1/subscriptions", headers=_auth(token)).json()
    assert listed[0]["status"] == "expired"
    assert assigned_ip is not None
    assert listed[0]["assigned_ip"] == assigned_ip


def test_internal_resolve(app_client) -> None:
    client, factory = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    sub = client.post("/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)).json()
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])
    client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token))
    _convert_to_historical_framed_ip(sub["id"])

    # Internal endpoint requires the relay secret. Default SECRET_KEY in tests
    # is "test-secret".
    legacy = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert legacy.status_code == 200, legacy.text
    assert "account_id" not in legacy.json()

    r = client.post(
        "/internal/v2/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ip_ips"]
    assert data["user_id"] >= 1
    assert data["account_id"] == signup["account_id"]


def test_internal_resolve_expires_elapsed_subscription(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "expired.relay.test"},
        headers=_auth(token),
    ).json()
    pay = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(pay["payment_hash"])
    client.get(f"/api/v1/payments/{pay['id']}", headers=_auth(token))

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(sub["id"]))
        ).one()
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    resolved = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert resolved.status_code == 200
    assert resolved.json()["relay_domains"] == []
    assert (
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]["status"]
        == "expired"
    )


def test_internal_resolve_requires_secret(app_client) -> None:
    client, _ = app_client
    r = client.post("/internal/v1/resolve", json={"token": "x"})
    assert r.status_code == 401


def test_landing_page_renders(app_client) -> None:
    client, _ = app_client
    r = client.get("/")
    assert r.status_code == 200
    assert "Blindport" in r.text
