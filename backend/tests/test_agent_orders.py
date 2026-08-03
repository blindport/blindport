"""Idempotent authenticated agent order API coverage."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session, select

from blindport.adapters.base import NwcAdapterError
from blindport.core.models import AgentOrder, Payment, Subscription, User


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signup(client) -> tuple[str, dict[str, str]]:
    token = client.post("/api/v1/signup").json()["token"]
    return token, _auth(token)


def _put(client, headers, key: str = "primary", **body):
    return client.put(
        f"/api/v1/client/orders/{key}",
        json={"product": "ip", **body},
        headers=headers,
    )


def _configure_wallet(client, headers, suffix: str = "agent-order") -> None:
    response = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": f"nostr+walletconnect://{suffix}"},
        headers=headers,
    )
    assert response.status_code == 200, response.text


def test_order_creation_replay_and_immutable_conflict(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)

    created = _put(client, headers, key="web_1", transport="tcp")
    replayed = _put(client, headers, key="web_1")
    conflict = _put(client, headers, key="web_1", billing_term="yearly")

    assert created.status_code == replayed.status_code == 200
    assert created.json()["state"] == "awaiting_payment"
    assert replayed.json()["subscription"]["id"] == created.json()["subscription"]["id"]
    assert conflict.status_code == 409
    from blindport.db import engine

    with Session(engine) as session:
        assert len(session.exec(select(AgentOrder)).all()) == 1
        assert len(session.exec(select(Subscription)).all()) == 1
        assert session.exec(select(Payment)).all() == []


def test_order_without_wallet_or_with_nwc_disabled_awaits_payment(app_client, monkeypatch) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    without_wallet = _put(client, headers, key="without-wallet")
    _configure_wallet(client, headers, "disabled-order")
    from blindport.services import agent_orders, payments

    monkeypatch.setattr(agent_orders.settings, "PAYMENT_ENABLED_METHODS", "lightning,cashu")
    monkeypatch.setattr(payments.settings, "PAYMENT_ENABLED_METHODS", "lightning,cashu")
    disabled = _put(client, headers, key="disabled-nwc", product="port")

    assert without_wallet.json()["state"] == "awaiting_payment"
    assert disabled.status_code == 200
    assert disabled.json()["state"] == "awaiting_payment"
    assert disabled.json()["payment"] is None


def test_managed_relay_creates_one_linked_nwc_payment(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "managed-relay")

    created = _put(
        client,
        headers,
        key="managed",
        product="relay",
        domain="Managed.RELAY.TEST.",
    )
    replayed = _put(
        client,
        headers,
        key="managed",
        product="relay",
        domain="managed.relay.test",
    )

    assert created.status_code == replayed.status_code == 200
    assert created.json()["state"] == replayed.json()["state"] == "payment_pending"
    assert created.json()["subscription"]["domain"] == "managed.relay.test"
    assert created.json()["payment"]["id"] == replayed.json()["payment"]["id"]
    from blindport.db import engine

    with Session(engine) as session:
        order = session.exec(select(AgentOrder)).one()
        payment = session.exec(select(Payment)).one()
        assert payment.agent_order_id == order.id
        assert payment.nwc_attempt_count == 1


def test_concurrent_identical_sqlite_puts_return_one_order_subscription_and_payment(
    app_client,
) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "sqlite-concurrent")
    barrier = threading.Barrier(2)

    def put() -> dict:
        barrier.wait(timeout=5)
        response = _put(client, headers, key="concurrent")
        assert response.status_code == 200, response.text
        return response.json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: put(), range(2)))

    assert results[0]["subscription"]["id"] == results[1]["subscription"]["id"]
    assert results[0]["payment"]["id"] == results[1]["payment"]["id"]
    from blindport.db import engine

    with Session(engine) as session:
        assert len(session.exec(select(AgentOrder)).all()) == 1
        assert len(session.exec(select(Subscription)).all()) == 1
        assert len(session.exec(select(Payment)).all()) == 1


def test_active_order_replay_never_renews(app_client, monkeypatch) -> None:
    client, factory = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "active-replay")
    adapter = factory.get_nwc_adapter()
    adapter.auto_settle = True
    pay_calls = 0
    original_pay = adapter.pay_invoice

    def counted_pay(uri: str, invoice: str):
        nonlocal pay_calls
        pay_calls += 1
        return original_pay(uri, invoice)

    monkeypatch.setattr(adapter, "pay_invoice", counted_pay)
    created = _put(client, headers, key="active")
    assert created.status_code == 200, created.text
    assert created.json()["state"] == "active"
    period_end = created.json()["subscription"]["current_period_end"]

    replayed = _put(client, headers, key="active")

    assert replayed.json()["state"] == "active"
    assert replayed.json()["subscription"]["current_period_end"] == period_end
    assert pay_calls == 1


def test_terminal_initial_payment_replay_requires_attention(app_client, monkeypatch) -> None:
    client, factory = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "terminal-order")
    pay_calls = 0

    def reject(uri: str, invoice: str):
        nonlocal pay_calls
        pay_calls += 1
        raise NwcAdapterError(
            "insufficient_balance",
            "wallet balance is insufficient",
            retryable=False,
        )

    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", reject)
    created = _put(client, headers, key="terminal")
    replayed = _put(client, headers, key="terminal")

    assert created.json()["state"] == replayed.json()["state"] == "attention_required"
    assert created.json()["payment"]["status"] == "failed"
    assert replayed.json()["payment"]["id"] == created.json()["payment"]["id"]
    assert pay_calls == 1


def test_ambiguous_provider_error_returns_persisted_payment_pending(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "ambiguous-order")
    pay_calls = 0

    def timeout(uri: str, invoice: str):
        nonlocal pay_calls
        pay_calls += 1
        from blindport.db import engine

        with Session(engine) as session:
            persisted = session.exec(select(Payment)).one()
            assert persisted.agent_order_id is not None
        raise NwcAdapterError("timeout", "wallet operation timed out", retryable=True)

    monkeypatch.setattr(factory.get_nwc_adapter(), "pay_invoice", timeout)
    created = _put(client, headers, key="ambiguous")
    replayed = _put(client, headers, key="ambiguous")

    assert created.status_code == replayed.status_code == 200
    assert created.json()["state"] == replayed.json()["state"] == "payment_pending"
    assert created.json()["payment"]["id"] == replayed.json()["payment"]["id"]
    assert pay_calls == 1


def test_unverified_customer_relay_awaits_domain_without_payment(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    _configure_wallet(client, headers, "customer-domain")

    response = _put(
        client,
        headers,
        key="customer-domain",
        product="relay",
        domain="Customer.Example.",
    )

    assert response.status_code == 200, response.text
    assert response.json()["state"] == "awaiting_domain"
    assert response.json()["payment"] is None
    assert response.json()["subscription"]["domain"] == "customer.example"
    from blindport.db import engine

    with Session(engine) as session:
        assert session.exec(select(Payment)).all() == []


@pytest.mark.parametrize(
    ("key", "body"),
    [
        ("UPPER", {"product": "ip"}),
        ("valid", {"product": "ip", "delivery": "wireguard"}),
        ("valid", {"product": "relay"}),
        ("valid", {"product": "ip", "unexpected": True}),
        ("valid", {"product": "ip", "domain": "unused.example"}),
    ],
)
def test_order_auth_and_validation(app_client, key, body) -> None:
    client, _ = app_client
    unauthenticated = client.put(f"/api/v1/client/orders/{key}", json=body)
    _, headers = _signup(client)
    invalid = client.put(f"/api/v1/client/orders/{key}", json=body, headers=headers)

    assert unauthenticated.status_code == 401
    assert invalid.status_code == 422


def test_order_key_length_boundary(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)

    accepted = _put(client, headers, key="a" * 63)
    rejected = _put(client, headers, key="a" * 64)

    assert accepted.status_code == 200
    assert rejected.status_code == 422


def test_order_creation_uses_account_payment_rate_limit(app_client, monkeypatch) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    from blindport.services import rate_limits

    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_PAYMENT_CREATE_REQUESTS", 1)

    assert _put(client, headers, key="limited").status_code == 200
    limited = _put(client, headers, key="limited")

    assert limited.status_code == 429
    assert limited.headers["Retry-After"]
    assert limited.json()["detail"] == "request rate limit exceeded"


def test_frequent_client_polling_does_not_rewrite_last_seen(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)

    assert client.get("/api/v1/client/config", headers=headers).status_code == 200
    from blindport.db import engine

    with Session(engine) as session:
        first_seen = session.exec(
            select(User.last_seen_at).where(User.is_admin == False)  # noqa: E712
        ).one()
    assert first_seen is not None

    assert client.get("/api/v1/client/config", headers=headers).status_code == 200
    with Session(engine) as session:
        current_seen = session.exec(
            select(User.last_seen_at).where(User.is_admin == False)  # noqa: E712
        ).one()
        assert current_seen == first_seen


def test_concurrent_last_seen_refresh_has_one_database_winner(app_client) -> None:
    client, _ = app_client
    _, headers = _signup(client)
    assert client.get("/api/v1/client/config", headers=headers).status_code == 200
    from blindport.core.auth import _touch_last_seen
    from blindport.db import engine

    stale = datetime.now(UTC) - timedelta(minutes=10)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.is_admin == False)).one()  # noqa: E712
        user.last_seen_at = stale
        session.add(user)
        session.commit()
        user_id = user.id
    barrier = threading.Barrier(2)

    def touch() -> bool:
        with Session(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            barrier.wait(timeout=5)
            return _touch_last_seen(session, user, datetime.now(UTC))

    with ThreadPoolExecutor(max_workers=2) as executor:
        winners = list(executor.map(lambda _: touch(), range(2)))

    assert winners.count(True) == 1
