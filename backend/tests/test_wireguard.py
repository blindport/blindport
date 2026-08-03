"""Routed Blindport IP enrollment, isolation, and relay snapshot coverage."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlmodel import Session, select

from blindport.core.wireguard import wireguard_enrollment_message

RELAY_PUBLIC_KEY = base64.b64encode(bytes(range(1, 33))).decode()


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _configure_wireguard(monkeypatch) -> None:
    from blindport.services import subscriptions, wireguard

    for module in (subscriptions, wireguard):
        monkeypatch.setattr(module.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
        monkeypatch.setattr(module.settings, "WIREGUARD_RELAY_PUBLIC_KEY", RELAY_PUBLIC_KEY)
        monkeypatch.setattr(module.settings, "WIREGUARD_ENDPOINT", "relay:51820")


def _enroll_identity(client, token: str) -> tuple[str, Ed25519PrivateKey]:
    from uuid import uuid4

    instance_id = str(uuid4())
    key = Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    response = client.post(
        "/api/v2/client/certificate",
        json={"instance_id": instance_id, "generation": 1, "csr_pem": csr},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    return instance_id, key


def _activate_routed_ip(client, factory, token: str) -> dict:
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard"},
        headers=_auth(token),
    )
    assert subscription.status_code == 200, subscription.text
    assert subscription.json()["delivery"] == "wireguard"
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription.json()["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"
    return subscription.json()


def _key_request(
    instance_id: str,
    identity_key: Ed25519PrivateKey,
    generation: int,
    key_bytes: bytes,
) -> dict:
    public_key = base64.b64encode(key_bytes).decode()
    signature = identity_key.sign(wireguard_enrollment_message(instance_id, generation, public_key))
    return {
        "instance_id": instance_id,
        "generation": generation,
        "public_key": public_key,
        "signature": base64.b64encode(signature).decode(),
    }


def test_routed_ip_isolated_from_legacy_and_enrolled_by_identity(app_client, monkeypatch) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    instance_id, identity_key = _enroll_identity(client, token)
    subscription = _activate_routed_ip(client, factory, token)

    me = client.get("/api/v1/me", headers=_auth(token)).json()
    routed = me["subscriptions"][0]
    assert routed["assigned_ip"] == "198.51.100.20"
    assert routed["delivery"] == "wireguard"
    assert client.get("/api/v1/client/config", headers=_auth(token)).json() == []
    legacy_resolution = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert legacy_resolution["ip_ips"] == []

    unenrolled = client.get("/api/v2/client/wireguard", headers=_auth(token))
    assert unenrolled.status_code == 200
    assert unenrolled.json() == {
        "instance_id": instance_id,
        "generation": 0,
        "public_key": None,
        "assigned_prefixes": ["198.51.100.20/32"],
        "relay_public_key": RELAY_PUBLIC_KEY,
        "endpoint": "relay:51820",
        "mtu": 1420,
        "persistent_keepalive_seconds": 25,
    }

    request = _key_request(instance_id, identity_key, 1, bytes(range(33, 65)))
    enrolled = client.post("/api/v2/client/wireguard/key", json=request, headers=_auth(token))
    assert enrolled.status_code == 200, enrolled.text
    assert enrolled.json()["generation"] == 1
    assert (
        client.post("/api/v2/client/wireguard/key", json=request, headers=_auth(token)).json()
        == enrolled.json()
    )

    snapshot = client.get(
        "/internal/v1/wireguard/peers",
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["managed_prefixes"] == ["198.51.100.20/32"]
    assert body["peers"] == [
        {"public_key": request["public_key"], "allowed_prefixes": ["198.51.100.20/32"]}
    ]
    assert len(body["revision"]) == 64

    from blindport.core.models import Subscription
    from blindport.db import engine

    with Session(engine) as session:
        stored = session.get(Subscription, subscription["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
    revoked = client.get(
        "/internal/v1/wireguard/peers",
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert revoked["managed_prefixes"] == ["198.51.100.20/32"]
    assert revoked["peers"] == []


def test_wireguard_key_replacement_requires_valid_identity_signature(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    instance_id, identity_key = _enroll_identity(client, token)
    _activate_routed_ip(client, factory, token)

    forged = _key_request(instance_id, Ed25519PrivateKey.generate(), 1, bytes(range(33, 65)))
    response = client.post("/api/v2/client/wireguard/key", json=forged, headers=_auth(token))
    assert response.status_code == 400
    assert response.json()["detail"] == "WireGuard key signature is invalid"

    first = _key_request(instance_id, identity_key, 1, bytes(range(33, 65)))
    assert (
        client.post("/api/v2/client/wireguard/key", json=first, headers=_auth(token)).status_code
        == 200
    )
    rotated = _key_request(instance_id, identity_key, 2, bytes(range(65, 97)))
    response = client.post("/api/v2/client/wireguard/key", json=rotated, headers=_auth(token))
    assert response.status_code == 200
    assert response.json()["generation"] == 2
    stale = client.post("/api/v2/client/wireguard/key", json=first, headers=_auth(token))
    assert stale.status_code == 409


def test_identity_reset_revokes_and_replaces_wireguard_peer(app_client, monkeypatch) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    first_instance, first_identity_key = _enroll_identity(client, token)
    _activate_routed_ip(client, factory, token)
    first = _key_request(first_instance, first_identity_key, 1, bytes(range(33, 65)))
    assert (
        client.post("/api/v2/client/wireguard/key", json=first, headers=_auth(token)).status_code
        == 200
    )

    from blindport.core.models import ClientCredential, User
    from blindport.db import engine

    with Session(engine) as session:
        user = session.exec(select(User).where(User.public_id == UUID(signup["account_id"]))).one()
        credential = session.get(ClientCredential, user.id)
        assert credential is not None
        session.delete(credential)
        session.commit()

    revoked = client.get(
        "/internal/v1/wireguard/peers",
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert revoked["peers"] == []

    second_instance, second_identity_key = _enroll_identity(client, token)
    reset_config = client.get("/api/v2/client/wireguard", headers=_auth(token)).json()
    assert reset_config["instance_id"] == second_instance
    assert reset_config["generation"] == 0
    assert reset_config["public_key"] is None

    second = _key_request(second_instance, second_identity_key, 1, bytes(range(65, 97)))
    replaced = client.post("/api/v2/client/wireguard/key", json=second, headers=_auth(token))
    assert replaced.status_code == 200, replaced.text
    assert replaced.json()["public_key"] == second["public_key"]
    desired = client.get(
        "/internal/v1/wireguard/peers",
        headers={"X-Relay-Secret": "test-secret"},
    ).json()
    assert desired["peers"] == [
        {"public_key": second["public_key"], "allowed_prefixes": ["198.51.100.20/32"]}
    ]


def test_wireguard_delivery_rejects_wrong_product_or_disabled_plane(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    disabled = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard"},
        headers=_auth(token),
    )
    assert disabled.status_code == 400
    assert disabled.json()["detail"] == "WireGuard Blindport IP delivery is not configured"
    invalid = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "delivery": "wireguard"},
        headers=_auth(token),
    )
    assert invalid.status_code == 422
