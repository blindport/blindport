"""Atomic pricing-first anonymous ordering and public account identity tests."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlmodel import Session, select
from subscription_helpers import subscription_by_public_id

from blindport.core import tokens
from blindport.core.models import Payment, Subscription, User


def _non_admin_users(session: Session) -> list[User]:
    return list(session.exec(select(User).where(User.is_admin.is_(False))).all())  # type: ignore[union-attr]


def _configure_wireguard(monkeypatch) -> None:
    from blindport.services import catalog, subscriptions

    for module in (catalog, subscriptions):
        monkeypatch.setattr(module.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
        monkeypatch.setattr(module.settings, "WIREGUARD_RELAY_PUBLIC_KEY", "A" * 44)
        monkeypatch.setattr(module.settings, "WIREGUARD_ENDPOINT", "relay:51820")


@pytest.mark.parametrize(
    ("request_body", "expected_product", "expected_transport"),
    [
        ({"product": "ip"}, "ip", "tcp"),
        ({"product": "port"}, "port", "tcp"),
        ({"product": "port", "transport": "udp"}, "port", "udp"),
        (
            {"product": "relay", "domain": "ordered.relay.test"},
            "relay",
            "tcp",
        ),
    ],
)
def test_anonymous_order_variants_are_atomic_and_unbilled(
    app_client,
    monkeypatch,
    request_body: dict[str, str],
    expected_product: str,
    expected_transport: str,
) -> None:
    _configure_wireguard(monkeypatch)
    client, _ = app_client

    response = client.post("/api/v2/orders", json=request_body)

    assert response.status_code == 201, response.text
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    account_id = UUID(body["account_id"])
    assert account_id.version == 4
    assert "user_id" not in body
    assert body["subscription"]["product"] == expected_product
    assert body["subscription"]["transport"] == expected_transport
    assert body["subscription"]["status"] == "pending"
    assert body["monthly_price_sats"] == body["subscription"]["monthly_price_sats"]
    assert body["yearly_price_sats"] == body["subscription"]["yearly_price_sats"]
    expected_term = ("yearly", 365) if expected_product == "ip" else ("monthly", 30)
    assert (body["billing_term"], body["period_days"]) == expected_term
    if expected_product == "ip":
        assert body["subscription"]["delivery"] == "wireguard"

    from blindport.db import engine

    with Session(engine) as session:
        users = _non_admin_users(session)
        assert len(users) == 1
        user = users[0]
        subscription = subscription_by_public_id(session, body["subscription"]["id"])
        assert user.public_id == account_id
        assert user.display_token is None
        assert user.hashed_token == tokens.hash_token(tokens.crockford.normalize(body["token"]))
        assert body["token"] not in vars(user).values()
        assert subscription is not None and subscription.user_id == user.id
        assert session.exec(select(Payment)).all() == []

    me = client.get(
        "/api/v2/me",
        headers={"Authorization": f"Bearer {body['token']}"},
    )
    assert me.status_code == 200
    assert me.json()["account_id"] == body["account_id"]
    assert "user_id" not in me.json()


def test_anonymous_order_uses_authoritative_catalog_price(app_client, monkeypatch) -> None:
    from blindport.services import catalog, subscriptions

    client, _ = app_client
    monkeypatch.setattr(catalog.settings, "PORT_MONTHLY_SATS", 4321)
    monkeypatch.setattr(catalog.settings, "PORT_YEARLY_SATS", 43210)
    monkeypatch.setattr(subscriptions.settings, "PORT_MONTHLY_SATS", 4321)
    monkeypatch.setattr(subscriptions.settings, "PORT_YEARLY_SATS", 43210)

    rejected = client.post(
        "/api/v2/orders",
        json={"product": "port", "monthly_price_sats": 1},
    )
    response = client.post("/api/v2/orders", json={"product": "port"})

    assert rejected.status_code == 422
    assert response.status_code == 201
    assert response.json()["monthly_price_sats"] == 4321
    assert response.json()["subscription"]["monthly_price_sats"] == 4321
    assert response.json()["yearly_price_sats"] == 43210
    assert response.json()["subscription"]["yearly_price_sats"] == 43210


@pytest.mark.parametrize("unexpected_field", ["location", "monthly_price_sats"])
def test_anonymous_order_rejects_fields_outside_its_contract(
    app_client, unexpected_field: str
) -> None:
    client, _ = app_client

    response = client.post(
        "/api/v2/orders",
        json={"product": "port", unexpected_field: "ignored"},
    )

    assert response.status_code == 422
    assert any(error["loc"][-1] == unexpected_field for error in response.json()["detail"])


@pytest.mark.parametrize(
    "request_body",
    [
        {"product": "relay"},
        {"product": "ip", "transport": "udp"},
        {"product": "port", "delivery": "wireguard"},
    ],
)
def test_anonymous_order_validation_errors_create_nothing(app_client, request_body) -> None:
    client, _ = app_client

    response = client.post("/api/v2/orders", json=request_body)

    assert response.status_code in {400, 422}
    from blindport.db import engine

    with Session(engine) as session:
        assert _non_admin_users(session) == []
        assert session.exec(select(Subscription)).all() == []
        assert session.exec(select(Payment)).all() == []


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
def test_anonymous_ip_order_rejects_explicit_legacy_options(
    app_client, request_body, message
) -> None:
    client, _ = app_client

    response = client.post("/api/v2/orders", json=request_body)

    assert response.status_code == 422
    assert response.json()["detail"][0]["msg"] == f"Value error, {message}"


def test_anonymous_order_unavailable_product_rolls_back_account(app_client, monkeypatch) -> None:
    from blindport.services import catalog

    _configure_wireguard(monkeypatch)
    client, _ = app_client
    monkeypatch.setattr(catalog.settings, "IP_SALES_PAUSED", True)

    response = client.post("/api/v2/orders", json={"product": "ip"})

    assert response.status_code == 409
    from blindport.db import engine

    with Session(engine) as session:
        assert _non_admin_users(session) == []
        assert session.exec(select(Subscription)).all() == []


def test_anonymous_order_service_failure_rolls_back_flushed_account(
    app_client, monkeypatch
) -> None:
    from blindport.api import v2

    client, _ = app_client

    def fail_subscription(*args, **kwargs):
        del args, kwargs
        raise ValueError("injected order failure")

    monkeypatch.setattr(v2.subs_svc, "create_subscription", fail_subscription)

    response = client.post("/api/v2/orders", json={"product": "ip"})

    assert response.status_code == 400
    assert response.json()["detail"] == "injected order failure"
    from blindport.db import engine

    with Session(engine) as session:
        assert _non_admin_users(session) == []
        assert session.exec(select(Subscription)).all() == []


def test_anonymous_order_shares_signup_rate_limit_and_returns_no_store(
    app_client, monkeypatch
) -> None:
    from blindport.services import rate_limits

    _configure_wireguard(monkeypatch)
    client, _ = app_client
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_SIGNUP_REQUESTS", 1)

    first = client.post("/api/v2/orders", json={"product": "ip"})
    limited = client.post("/api/v2/orders", json={"product": "port"})

    assert first.status_code == 201
    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "no-store"
    assert int(limited.headers["Retry-After"]) >= 1
    from blindport.db import engine

    with Session(engine) as session:
        assert len(_non_admin_users(session)) == 1
        assert len(session.exec(select(Subscription)).all()) == 1


def test_signup_consumes_anonymous_order_quota(app_client, monkeypatch) -> None:
    from blindport.services import rate_limits

    client, _ = app_client
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_SIGNUP_REQUESTS", 1)

    signup = client.post("/api/v1/signup")
    order = client.post("/api/v2/orders", json={"product": "ip"})

    assert signup.status_code == 200
    assert order.status_code == 429


def test_public_account_ids_are_unique_and_admin_paths_accept_rollout_ids(app_client) -> None:
    client, _ = app_client
    first = client.post("/api/v2/signup").json()
    second = client.post("/api/v2/signup").json()
    first_id = UUID(first["account_id"])
    second_id = UUID(second["account_id"])
    assert first_id.version == second_id.version == 4
    assert first_id != second_id
    assert set(first) == {"token", "account_id"}

    admin = {"Authorization": "Bearer TESTADMIN0000"}
    from blindport.db import engine

    with Session(engine) as session:
        first_user = session.exec(select(User).where(User.public_id == first_id)).one()
    integer_lookup = client.post(
        f"/api/v1/admin/users/{first_user.id}/suspend",
        headers=admin,
    )
    missing_lookup = client.post(f"/api/v2/admin/users/{uuid4()}/suspend", headers=admin)
    suspended = client.post(
        f"/api/v2/admin/users/{first['account_id']}/suspend",
        headers=admin,
    )

    assert integer_lookup.status_code == 200
    assert integer_lookup.json() == {"user_id": first_user.id, "is_suspended": True}
    assert missing_lookup.status_code == 404
    assert suspended.status_code == 200
    assert suspended.json() == {"account_id": first["account_id"], "is_suspended": True}
