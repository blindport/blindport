"""Subscription referral attribution regressions."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlmodel import Session, select

from blindport.core.models import AgentOrder, Subscription, SubscriptionStatus


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _subscription_referral(session: Session, public_id: str) -> str | None:
    subscription = session.exec(
        select(Subscription).where(Subscription.public_id == UUID(public_id))
    ).one()
    return subscription.referral_address


def test_anonymous_order_canonicalizes_referral_without_network_io(app_client, monkeypatch) -> None:
    client, _ = app_client

    def fail_network(*args, **kwargs):
        raise AssertionError("referral attribution must not resolve Lightning Address domains")

    monkeypatch.setattr(socket, "getaddrinfo", fail_network)
    response = client.post(
        "/api/v2/orders",
        json={"product": "port", "referral_address": "Alice@Wallet.Co"},
    )

    assert response.status_code == 201, response.text
    from blindport.db import engine

    with Session(engine) as session:
        assert (
            _subscription_referral(session, response.json()["subscription"]["id"])
            == "alice@wallet.co"
        )


def test_referral_commission_injection_is_rejected_before_subscription_creation(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    requests = (
        (
            "/api/v2/orders",
            {"product": "port", "referral_commission_bps": 10_000},
            None,
        ),
        (
            "/api/v1/subscriptions",
            {"product": "port", "referral_commission_bps": 10_000},
            _auth(token),
        ),
        (
            "/api/v1/client/orders/referral-rate",
            {"product": "port", "referral_commission_bps": 10_000},
            _auth(token),
        ),
    )

    for path, body, headers in requests:
        response = (
            client.put(path, json=body, headers=headers)
            if "client/orders" in path
            else client.post(
                path,
                json=body,
                headers=headers,
            )
        )
        assert response.status_code == 422, response.text

    from blindport.db import engine

    with Session(engine) as session:
        assert session.exec(select(Subscription)).all() == []


def test_signed_in_order_does_not_override_existing_subscription_attribution(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    headers = _auth(token)
    without_referral = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=headers,
    )
    attributed = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "referral_address": "alice@wallet.co"},
        headers=headers,
    )

    assert without_referral.status_code == attributed.status_code == 200
    from blindport.db import engine

    with Session(engine) as session:
        assert _subscription_referral(session, without_referral.json()["id"]) is None
        assert _subscription_referral(session, attributed.json()["id"]) == "alice@wallet.co"


def test_agent_order_replay_requires_matching_referral_attribution(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    headers = _auth(token)
    body = {"product": "port", "referral_address": "Alice@Wallet.Co"}

    created = client.put("/api/v1/client/orders/referral", json=body, headers=headers)
    replayed = client.put(
        "/api/v1/client/orders/referral",
        json={"product": "port", "referral_address": "alice@wallet.co"},
        headers=headers,
    )
    conflict = client.put(
        "/api/v1/client/orders/referral",
        json={"product": "port", "referral_address": "bob@wallet.co"},
        headers=headers,
    )

    assert created.status_code == replayed.status_code == 200
    assert replayed.json()["subscription"]["id"] == created.json()["subscription"]["id"]
    assert conflict.status_code == 409
    from blindport.db import engine

    with Session(engine) as session:
        order = session.exec(select(AgentOrder)).one()
        subscription = session.get(Subscription, order.subscription_id)
        assert subscription is not None
        assert subscription.referral_address == "alice@wallet.co"


def test_wildcard_upgrade_copies_source_referral_attribution(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    headers = _auth(token)
    source = client.post(
        "/api/v1/subscriptions",
        json={
            "product": "relay",
            "domain": "app.example.test",
            "referral_address": "alice@wallet.co",
        },
        headers=headers,
    )
    assert source.status_code == 200, source.text
    from blindport.db import engine

    with Session(engine) as session:
        persisted = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source.json()["id"]))
        ).one()
        persisted.status = SubscriptionStatus.ACTIVE
        persisted.domain_verified_at = datetime.now(UTC)
        persisted.current_period_start = datetime.now(UTC) - timedelta(days=1)
        persisted.current_period_end = datetime.now(UTC) + timedelta(days=29)
        session.add(persisted)
        session.commit()

    upgrade = client.post(
        f"/api/v1/subscriptions/{source.json()['id']}/wildcard-upgrade",
        json={"billing_term": "monthly"},
        headers=headers,
    )

    assert upgrade.status_code == 200, upgrade.text
    with Session(engine) as session:
        assert _subscription_referral(session, source.json()["id"]) == "alice@wallet.co"
        assert _subscription_referral(session, upgrade.json()["id"]) == "alice@wallet.co"
