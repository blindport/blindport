"""Scope-aware Relay v3 provisioning and resolution contract tests."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _csr() -> str:
    key = Ed25519PrivateKey.generate()
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def _activate(client, factory, token: str, product: str, **extra: str) -> dict[str, object]:
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": product, **extra}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    assert client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).status_code == 200
    return subscription


def _payload(artifact: str) -> dict[str, object]:
    encoded = artifact.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def _payload_keys(artifact: str) -> list[str]:
    encoded = artifact.split(".")[1]
    raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    return list(json.loads(raw, object_pairs_hook=dict))


def test_v3_provisioning_scopes_claims_and_legacy_omits_wildcards(
    app_client, monkeypatch, tmp_path
) -> None:
    from blindport.api import v2, v3
    from blindport.core.models import RelayHostnameScope, Subscription
    from blindport.db import engine
    from blindport.services import relay_routing

    client, factory = app_client
    token = client.post("/api/v2/signup").json()["token"]
    instance_id = str(uuid4())
    key_path = tmp_path / "offline.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    for module in (v2, v3, relay_routing):
        monkeypatch.setattr(module.settings, "RELAY_CONTROL_URL", "primary.example:5443")
        monkeypatch.setattr(module.settings, "RELAY_CONTROL_URLS", "primary.example:5443")
        monkeypatch.setattr(
            module.settings,
            "PORT_HA_EDGES",
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"}]',
        )
        monkeypatch.setattr(
            module.settings,
            "RELAY_EDGES",
            '[{"id":"edge-a","endpoint":"primary.example:5443"}]',
        )
    for module in (v2, v3):
        monkeypatch.setattr(module.settings, "OFFLINE_ENTITLEMENTS_ENABLED", True)
        monkeypatch.setattr(module.settings, "OFFLINE_ENTITLEMENT_KEY_ID", "offline-a")
        monkeypatch.setattr(module.settings, "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE", str(key_path))

    assert (
        client.post(
            "/api/v2/client/certificate",
            headers=_auth(token),
            json={"instance_id": instance_id, "generation": 1, "csr_pem": _csr()},
        ).status_code
        == 200
    )
    exact = _activate(client, factory, token, "relay", domain="exact.relay.test")
    wildcard = _activate(client, factory, token, "relay", domain="wild.relay.test")
    port = _activate(client, factory, token, "port")

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(wildcard["id"]))
        ).one()
        stored.relay_hostname_scope = RelayHostnameScope.WILDCARD
        session.add(stored)
        session.commit()

    v2_response = client.get(
        f"/api/v2/client/config?instance_id={instance_id}", headers=_auth(token)
    )
    assert v2_response.status_code == 200, v2_response.text
    assert {row["subscription_id"] for row in v2_response.json()["subscriptions"]} == {
        exact["id"],
        port["id"],
    }
    assert client.get("/api/v1/client/config", headers=_auth(token)).json()
    assert wildcard["id"] not in {
        row["subscription_id"]
        for row in client.get("/api/v1/client/config", headers=_auth(token)).json()
    }

    response = client.get(f"/api/v3/client/config?instance_id={instance_id}", headers=_auth(token))
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"version", "subscriptions"}
    assert body["version"] == 3
    rows = {row["subscription_id"]: row for row in body["subscriptions"]}
    assert set(rows) == {exact["id"], wildcard["id"], port["id"]}
    assert all(
        set(row)
        == {
            "assigned_ip",
            "assigned_port",
            "transport",
            "domain",
            "product",
            "subscription_id",
            "relay_hostname_scope",
            "edges",
        }
        for row in rows.values()
    )
    assert rows[exact["id"]]["relay_hostname_scope"] == "exact"
    assert rows[wildcard["id"]]["relay_hostname_scope"] == "wildcard"
    assert rows[port["id"]]["relay_hostname_scope"] == "exact"
    assert all(
        set(edge["claim"]) == {"kind", "ip", "port", "transport", "domain", "scope"}
        and edge["claim"]["scope"] == row["relay_hostname_scope"]
        for row in rows.values()
        for edge in row["edges"]
    )
    assert _payload(rows[exact["id"]]["edges"][0]["entitlement"])["v"] == 1
    wildcard_payload = _payload(rows[wildcard["id"]]["edges"][0]["entitlement"])
    assert wildcard_payload["v"] == 2
    assert wildcard_payload["scope"] == "wildcard"
    wildcard_keys = _payload_keys(rows[wildcard["id"]]["edges"][0]["entitlement"])
    assert wildcard_keys.index("domain") < wildcard_keys.index("scope") < wildcard_keys.index("iat")


def test_v3_resolve_is_strict_and_returns_exact_subscription_attribution(app_client) -> None:
    from blindport.core.models import RelayHostnameScope, Subscription
    from blindport.db import engine

    client, factory = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    exact = _activate(client, factory, token, "relay", domain="exact.relay.test")
    wildcard = _activate(client, factory, token, "relay", domain="wild.relay.test")
    port = _activate(client, factory, token, "port")
    active_by_id = {
        subscription["id"]: subscription
        for subscription in client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"]
    }
    port = active_by_id[port["id"]]
    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(wildcard["id"]))
        ).one()
        stored.relay_hostname_scope = RelayHostnameScope.WILDCARD
        session.add(stored)
        session.commit()

    headers = {"X-Relay-Secret": "test-secret"}
    for path in ("/internal/resolve", "/internal/v1/resolve", "/internal/v2/resolve"):
        response = client.post(path, json={"token": token}, headers=headers)
        assert response.status_code == 200, response.text
    for path in ("/internal/v1/resolve", "/internal/v2/resolve"):
        assert client.post(path, json={"token": token}, headers=headers).json()[
            "relay_domains"
        ] == [exact["domain"]]

    absent = client.post("/internal/v3/resolve", json={"token": token}, headers=headers)
    assert absent.status_code == 200, absent.text
    assert "subscription_id" not in absent.json()

    exact_response = client.post(
        "/internal/v3/resolve",
        json={"token": token, "claim": {"kind": "relay", "domain": exact["domain"]}},
        headers=headers,
    )
    assert exact_response.status_code == 200, exact_response.text
    assert exact_response.json()["subscription_id"] == exact["id"]

    response = client.post(
        "/internal/v3/resolve",
        json={
            "token": token,
            "claim": {"kind": "relay", "domain": wildcard["domain"], "scope": "wildcard"},
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "account_id",
        "user_id",
        "ip_ips",
        "relay_domains",
        "relay_claims",
        "port_leases",
        "subscription_id",
    }
    assert body["account_id"] == signup["account_id"]
    assert body["relay_domains"] == [exact["domain"]]
    assert body["relay_claims"] == [
        {"domain": exact["domain"], "scope": "exact"},
        {"domain": wildcard["domain"], "scope": "wildcard"},
    ]
    assert body["subscription_id"] == wildcard["id"]
    from blindport.services import relay_routing

    relay_routing.settings.PORT_HA_EDGES = (
        '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"},'
        '{"endpoint":"secondary.example:5443","ip":"198.51.100.30"}]'
    )
    port_response = client.post(
        "/internal/v3/resolve",
        json={
            "token": token,
            "claim": {
                "kind": "port",
                "ip": "198.51.100.30",
                "port": port["assigned_port"],
                "transport": port["transport"],
            },
        },
        headers=headers,
    )
    assert port_response.status_code == 200, port_response.text
    assert port_response.json()["subscription_id"] == port["id"]
    for claim in (
        {"kind": "relay", "domain": wildcard["domain"], "scope": "wildcard", "extra": 1},
        {"kind": "relay", "domain": wildcard["domain"], "ip": "203.0.113.10"},
        {
            "kind": "port",
            "ip": "203.0.113.20",
            "port": 10000,
            "transport": "tcp",
            "scope": "wildcard",
        },
    ):
        assert (
            client.post(
                "/internal/v3/resolve", json={"token": token, "claim": claim}, headers=headers
            ).status_code
            == 422
        )


def test_v3_resolve_rejects_ambiguous_authorized_port_claim(app_client, monkeypatch) -> None:
    from blindport.core.models import ProductType, Subscription, SubscriptionStatus, User
    from blindport.db import engine
    from blindport.services import relay_routing

    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    now = datetime.now(UTC)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.public_id == UUID(signup["account_id"]))).one()
        session.add_all(
            [
                Subscription(
                    user_id=user.id,
                    product=ProductType.PORT,
                    status=SubscriptionStatus.ACTIVE,
                    assigned_ip=address,
                    assigned_port=12000,
                    monthly_price_sats=1,
                    current_period_start=now - timedelta(days=1),
                    current_period_end=now + timedelta(days=1),
                )
                for address in ("203.0.113.20", "203.0.113.21")
            ]
        )
        session.commit()
    monkeypatch.setattr(
        relay_routing,
        "port_edges",
        lambda _assigned_ip: [relay_routing.RelayEdge(endpoint="relay:5443", ip="198.51.100.99")],
    )

    response = client.post(
        "/internal/v3/resolve",
        json={
            "token": signup["token"],
            "claim": {"kind": "port", "ip": "198.51.100.99", "port": 12000, "transport": "tcp"},
        },
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "ambiguous subscription claim"
