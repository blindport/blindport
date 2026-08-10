"""Relay wildcard hostname scope API and lifecycle coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import dns.name
from sqlmodel import Session
from subscription_helpers import subscription_by_public_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signup(client) -> str:
    return client.post("/api/v1/signup").json()["token"]


def _create_relay(client, token: str, domain: str, scope: str = "exact"):
    return client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": domain, "relay_hostname_scope": scope},
        headers=_auth(token),
    )


class _TxtRecord:
    def __init__(self, value: str) -> None:
        self.strings = (value.encode("ascii"),)


class _CnameRecord:
    def __init__(self, target: str) -> None:
        self.target = dns.name.from_text(target)


class _Resolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, str, bool, float]] = []

    def resolve(self, name: str, rdtype: str, *, search: bool, lifetime: float):
        self.calls.append((name, rdtype, search, lifetime))
        return self.answers[(name, rdtype)]


def _set_resolver_verifier(client, resolver: _Resolver) -> None:
    from blindport.api import v1
    from blindport.services.domain_verification import DnsPythonDomainVerifier

    verifier = DnsPythonDomainVerifier(resolver=resolver, lifetime=0.5)
    client.app.dependency_overrides[v1._domain_verifier_dependency] = lambda: lambda: verifier


def _wildcard_answers(subscription: dict) -> dict[tuple[str, str], object]:
    from blindport.services.subscriptions import wildcard_probe_name

    token = subscription["domain_challenge_value"].removeprefix("blindport-verification=")
    return {
        (subscription["domain_challenge_name"], "TXT"): [
            _TxtRecord(subscription["domain_challenge_value"])
        ],
        (wildcard_probe_name(subscription["domain"], token), "CNAME"): [
            _CnameRecord(subscription["record_target"] + ".")
        ],
    }


def test_wildcard_probe_name_is_stable_ascii_and_within_dns_limit() -> None:
    from blindport.services.subscriptions import wildcard_probe_name

    domain = ".".join(("a" * 63, "a" * 63, "a" * 63, "a" * 40))
    name = wildcard_probe_name(domain, "stored-verification-token")

    assert name == wildcard_probe_name(domain, "stored-verification-token")
    assert len(name) == 253
    assert name.split(".", 1)[0].startswith("bpv-")
    assert name.isascii()


def test_catalog_exposes_relay_scope_prices_and_contract(app_client) -> None:
    client, _ = app_client

    relay = next(
        item
        for item in client.get("/api/v1/catalog").json()["products"]
        if item["product"] == "relay"
    )

    assert relay["monthly_price_sats"] == 3000
    assert relay["relay_scopes"] == {
        "exact": {
            "monthly_price_sats": 3000,
            "yearly_price_sats": 30000,
            "available": True,
            "tls_passthrough_only": False,
        },
        "wildcard": {
            "monthly_price_sats": 7500,
            "yearly_price_sats": 75000,
            "available": True,
            "tls_passthrough_only": True,
        },
    }


def test_admin_resource_label_marks_wildcard_scope() -> None:
    from blindport.core.models import ProductType, RelayHostnameScope, Subscription
    from blindport.services.admin_dashboard import _assigned_resource

    subscription = Subscription(
        user_id=1,
        product=ProductType.RELAY,
        domain="admin.example",
        relay_hostname_scope=RelayHostnameScope.WILDCARD,
        monthly_price_sats=7500,
    )

    assert _assigned_resource(subscription) == "*.admin.example"


def test_anonymous_wildcard_order_snapshots_wildcard_price(app_client, monkeypatch) -> None:
    client, _ = app_client

    created = client.post(
        "/api/v2/orders",
        json={
            "product": "relay",
            "domain": "Wild.Example.",
            "relay_hostname_scope": "wildcard",
        },
    )

    assert created.status_code == 201, created.text
    body = created.json()
    subscription = body["subscription"]
    assert (body["monthly_price_sats"], body["yearly_price_sats"]) == (7500, 75000)
    assert (subscription["monthly_price_sats"], subscription["yearly_price_sats"]) == (7500, 75000)
    assert subscription["relay_hostname_scope"] == "wildcard"
    assert subscription["tls_passthrough_only"] is True
    assert subscription["domain_is_managed"] is False
    assert subscription["domain_challenge_name"] == "_blindport-challenge.wild.example"
    assert subscription["record_type"] == "CNAME"
    assert subscription["record_name"] == "*.wild.example"
    assert subscription["record_target"] in {"relay1.test", "relay2.test"}

    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "RELAY_WILDCARD_MONTHLY_SATS", 1)
    resolver = _Resolver(_wildcard_answers(subscription))
    _set_resolver_verifier(client, resolver)
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(body["token"]),
    )
    assert payment.status_code == 200, payment.text
    assert payment.json()["amount_sats"] == 7500


def test_wildcard_requires_relay_customer_base_and_no_star(app_client) -> None:
    client, _ = app_client
    token = _signup(client)

    managed = _create_relay(client, token, "wild.relay.test", "wildcard")
    marked = _create_relay(client, token, "*.wild.example", "wildcard")
    non_relay = client.post(
        "/api/v2/orders",
        json={"product": "ip", "relay_hostname_scope": "wildcard"},
    )

    assert managed.status_code == 400
    assert "customer-owned" in managed.json()["detail"]
    assert marked.status_code == 400
    assert "invalid hostname label" in marked.json()["detail"]
    assert non_relay.status_code == 422
    assert "only for Blindport Relay" in non_relay.text


def test_wildcard_rejects_shallow_and_managed_suffix_base_domains(app_client, monkeypatch) -> None:
    client, _ = app_client
    token = _signup(client)
    from blindport.services import subscriptions

    shallow = _create_relay(client, token, "example", "wildcard")
    assert shallow.status_code == 400
    assert "at least two labels" in shallow.json()["detail"]

    monkeypatch.setattr(
        subscriptions.settings,
        "RELAY_MANAGED_SUFFIXES",
        "relay.example.com",
    )
    suffix = _create_relay(client, token, "relay.example.com", "wildcard")
    ancestor = _create_relay(client, token, "example.com", "wildcard")

    assert suffix.status_code == 400
    assert "cannot equal or contain a managed suffix" in suffix.json()["detail"]
    assert ancestor.status_code == 400
    assert "cannot equal or contain a managed suffix" in ancestor.json()["detail"]


def test_wildcard_dns_verification_and_renewal_query_stable_descendant_probe(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    created = _create_relay(client, token, "renew-wild.example", "wildcard")
    assert created.status_code == 200, created.text
    subscription = created.json()
    resolver = _Resolver(_wildcard_answers(subscription))
    _set_resolver_verifier(client, resolver)

    verified = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/verify-domain",
        headers=_auth(token),
    )
    assert verified.status_code == 200, verified.text
    assert verified.json()["verified"] is True
    assert (
        verified.json()["subscription"]["domain_challenge_value"]
        == subscription["domain_challenge_value"]
    )
    from blindport.services.subscriptions import wildcard_probe_name

    token_value = subscription["domain_challenge_value"].removeprefix("blindport-verification=")
    probe_name = wildcard_probe_name(subscription["domain"], token_value)
    assert probe_name.startswith("bpv-")
    assert probe_name.endswith(".renew-wild.example")
    assert probe_name != subscription["record_name"]
    assert len(probe_name) <= 253
    assert resolver.calls == [
        ("_blindport-challenge.renew-wild.example", "TXT", False, 0.5),
        (probe_name, "CNAME", False, 0.5),
    ]

    resolver.calls.clear()
    first_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(first_payment["payment_hash"])
    assert (
        client.get(f"/api/v1/payments/{first_payment['id']}", headers=_auth(token)).json()["status"]
        == "paid"
    )
    resolver.calls.clear()

    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal.status_code == 200, renewal.text
    assert resolver.calls == [
        ("_blindport-challenge.renew-wild.example", "TXT", False, 0.5),
        (probe_name, "CNAME", False, 0.5),
    ]


def test_wildcard_overlap_rules_and_released_claim_reuse(app_client, monkeypatch) -> None:
    client, _ = app_client
    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 10)
    owner = _signup(client)
    other = _signup(client)

    wildcard = _create_relay(client, owner, "base.example", "wildcard")
    assert wildcard.status_code == 200, wildcard.text
    assert _create_relay(client, other, "child.base.example").status_code == 400
    assert _create_relay(client, other, "nested.base.example", "wildcard").status_code == 400
    assert _create_relay(client, other, "example", "wildcard").status_code == 400
    assert _create_relay(client, other, "base.example").status_code == 400

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, wildcard.json()["id"])
        assert stored is not None
        stored.domain_claim_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    released_child = _create_relay(client, other, "child.base.example")
    assert released_child.status_code == 200, released_child.text


def test_wildcard_rejects_existing_exact_descendant_and_agent_replay_checks_scope(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 10)
    first = _signup(client)
    second = _signup(client)
    exact = _create_relay(client, first, "child.exact-base.example")
    assert exact.status_code == 200, exact.text
    blocked = _create_relay(client, second, "exact-base.example", "wildcard")
    assert blocked.status_code == 400
    assert "conflicts" in blocked.json()["detail"]

    order = client.put(
        "/api/v1/client/orders/wildcard",
        json={
            "product": "relay",
            "domain": "agent.example",
            "relay_hostname_scope": "wildcard",
        },
        headers=_auth(second),
    )
    replay = client.put(
        "/api/v1/client/orders/wildcard",
        json={
            "product": "relay",
            "domain": "agent.example",
            "relay_hostname_scope": "exact",
        },
        headers=_auth(second),
    )
    assert order.status_code == 200, order.text
    assert order.json()["subscription"]["relay_hostname_scope"] == "wildcard"
    assert order.json()["state"] == "awaiting_domain"
    assert replay.status_code == 409
