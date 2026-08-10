"""Routed Blindport IP enrollment, isolation, and relay snapshot coverage."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlmodel import Session, select
from subscription_helpers import subscription_by_public_id

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
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
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
    v3_snapshot = client.get(
        "/internal/v3/wireguard/peers",
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert v3_snapshot.status_code == 200
    assert v3_snapshot.json()["prefix_bindings"] == [
        {"prefix": "198.51.100.20/32", "subscription_id": subscription["id"]}
    ]

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, subscription["id"])
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


def test_v3_desired_state_binds_each_prefix_while_grouping_one_peer(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    del client
    _configure_wireguard(monkeypatch)
    from blindport.core.models import (
        ClientCredential,
        DeliveryMode,
        ProductType,
        Subscription,
        SubscriptionStatus,
        User,
        WireGuardPeer,
    )
    from blindport.db import engine
    from blindport.services.wireguard import desired_state_v3

    now = datetime.now(UTC)
    with Session(engine) as session:
        user = User(hashed_token="same-peer-bandwidth-bindings")
        session.add(user)
        session.flush()
        assert user.id is not None
        session.add(
            ClientCredential(
                user_id=user.id,
                instance_id="00000000-0000-4000-8000-000000000001",
                public_key_fingerprint="a" * 64,
                generation=1,
                client_cert_pem="unused",
                serial="1",
                not_before=now,
                not_after=now,
                renew_after=now,
            )
        )
        session.add(
            WireGuardPeer(
                user_id=user.id,
                instance_id="00000000-0000-4000-8000-000000000001",
                public_key=RELAY_PUBLIC_KEY,
                generation=1,
            )
        )
        subscriptions = [
            Subscription(
                user_id=user.id,
                product=ProductType.IP,
                delivery=DeliveryMode.WIREGUARD,
                status=SubscriptionStatus.ACTIVE,
                assigned_ip=address,
                monthly_price_sats=1,
                current_period_start=now - timedelta(days=1),
                current_period_end=now + timedelta(days=365),
            )
            for address in ("198.51.100.20", "198.51.100.21")
        ]
        subscription_ids = {subscription.public_id for subscription in subscriptions}
        session.add_all(subscriptions)
        session.commit()
        snapshot = desired_state_v3(session)

    assert len(snapshot.peers) == 1
    assert snapshot.peers[0].public_key == RELAY_PUBLIC_KEY
    assert snapshot.peers[0].allowed_prefixes == ["198.51.100.20/32", "198.51.100.21/32"]
    assert [binding.prefix for binding in snapshot.prefix_bindings] == [
        "198.51.100.20/32",
        "198.51.100.21/32",
    ]
    assert {binding.subscription_id for binding in snapshot.prefix_bindings} == subscription_ids


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


def test_wireguard_delivery_rejects_wrong_product_or_disabled_plane(
    app_client, monkeypatch
) -> None:
    from blindport.services import subscriptions

    client, _ = app_client
    monkeypatch.setattr(
        subscriptions,
        "settings",
        subscriptions.settings.model_copy(update={"WIREGUARD_PUBLIC_IPS": ""}),
    )
    token = client.post("/api/v1/signup").json()["token"]
    disabled = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
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


def test_routed_ip_omitted_order_fields_normalize_and_explicit_monthly_is_rejected(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]

    omitted = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard"},
        headers=_auth(token),
    )
    assert omitted.status_code == 200, omitted.text
    assert (omitted.json()["delivery"], omitted.json()["billing_term"]) == ("wireguard", "yearly")

    monthly = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "monthly"},
        headers=_auth(token),
    )
    assert monthly.status_code == 422
    assert monthly.json()["detail"][0]["msg"] == (
        "Value error, WireGuard Blindport IP is available with yearly billing only"
    )

    anonymous = client.post(
        "/api/v2/orders",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "monthly"},
    )
    assert anonymous.status_code == 422
    assert anonymous.json()["detail"][0]["msg"] == monthly.json()["detail"][0]["msg"]

    yearly = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
        headers=_auth(token),
    )
    assert yearly.status_code == 200, yearly.text
    explicit_monthly = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": yearly.json()["id"],
            "method": "lightning",
            "billing_term": "monthly",
        },
        headers=_auth(token),
    )
    assert explicit_monthly.status_code == 400
    yearly_omitted = client.post(
        "/api/v1/payments",
        json={"subscription_id": yearly.json()["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert yearly_omitted.status_code == 200, yearly_omitted.text
    assert (yearly_omitted.json()["billing_term"], yearly_omitted.json()["period_days"]) == (
        "yearly",
        365,
    )


def test_routed_catalog_capacity_requires_global_yearly_billing(app_client, monkeypatch) -> None:
    client, _ = app_client
    _configure_wireguard(monkeypatch)
    from blindport.services import catalog

    monkeypatch.setattr(catalog.settings, "BILLING_YEARLY_ENABLED", False)
    ip = next(
        item for item in client.get("/api/v1/catalog").json()["products"] if item["product"] == "ip"
    )
    assert ip["capacity"]["wireguard_available"] == 0
    assert ip["capacity"]["framed_available"] == 0
    assert ip["capacity"]["total"] == 1


def test_routed_smtp_admin_is_default_deny_and_v2_only(app_client, monkeypatch) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    instance_id, identity_key = _enroll_identity(client, token)
    subscription = _activate_routed_ip(client, factory, token)
    key_request = _key_request(instance_id, identity_key, 1, bytes(range(33, 65)))
    assert (
        client.post(
            "/api/v2/client/wireguard/key", json=key_request, headers=_auth(token)
        ).status_code
        == 200
    )
    relay_headers = {"X-Relay-Secret": "test-secret"}
    v1_before = client.get("/internal/v1/wireguard/peers", headers=relay_headers).json()
    v2_before = client.get("/internal/v2/wireguard/peers", headers=relay_headers).json()
    assert "smtp_allowed_prefixes" not in v1_before
    assert v2_before["smtp_allowed_prefixes"] == []

    path = f"/api/v2/admin/subscriptions/{subscription['id']}/smtp-egress/approve"
    request = {
        "intended_use": "Transactional account notifications",
        "fee_paid_sats": 50000,
        "review_reference": "ticket-123",
    }
    assert client.post(path, json=request).status_code == 401
    low_fee = client.post(
        path,
        json={**request, "fee_paid_sats": 49999},
        headers=_auth("TESTADMIN0000"),
    )
    assert low_fee.status_code == 400
    assert (
        client.post(
            path,
            json={**request, "unexpected": True},
            headers=_auth("TESTADMIN0000"),
        ).status_code
        == 422
    )

    approved = client.post(path, json=request, headers=_auth("TESTADMIN0000"))
    assert approved.status_code == 200, approved.text
    assert approved.json()["smtp_enabled"] is True
    assert approved.json()["reviewed_by"] == "blindport-admin-api-v1"
    v2_approved = client.get("/internal/v2/wireguard/peers", headers=relay_headers).json()
    assert v2_approved["smtp_allowed_prefixes"] == ["198.51.100.20/32"]
    assert v2_approved["revision"] != v2_before["revision"]
    assert (
        client.get("/internal/v1/wireguard/peers", headers=relay_headers).json()["revision"]
        == v1_before["revision"]
    )

    revoke_path = f"/api/v2/admin/subscriptions/{subscription['id']}/smtp-egress/revoke"
    revoked = client.post(
        revoke_path,
        json={"reason": "Customer request"},
        headers=_auth("TESTADMIN0000"),
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["smtp_enabled"] is False
    v2_revoked = client.get("/internal/v2/wireguard/peers", headers=relay_headers).json()
    assert v2_revoked["smtp_allowed_prefixes"] == []
    assert v2_revoked["revision"] == v2_before["revision"]

    client.post("/admin/login", data={"token": "TESTADMIN0000"})
    panel = client.get("/admin")
    assert f"/admin/ip-leases/{approved.json()['lease_id']}/smtp/approve" in panel.text
    assert "Dedicated IP lease history" in panel.text
    browser_approve = client.post(
        f"/admin/ip-leases/{approved.json()['lease_id']}/smtp/approve",
        data={
            "intended_use": "Transactional account notifications",
            "fee_paid_sats": "50000",
            "review_reference": "browser-ticket-124",
        },
        follow_redirects=False,
    )
    assert browser_approve.status_code == 303
    assert browser_approve.headers["location"] == "/admin#ip-leases-title"
    assert client.get("/internal/v2/wireguard/peers", headers=relay_headers).json()[
        "smtp_allowed_prefixes"
    ] == ["198.51.100.20/32"]
    browser_revoke = client.post(
        f"/admin/ip-leases/{approved.json()['lease_id']}/smtp/revoke",
        data={"reason": "Browser review revoked"},
        follow_redirects=False,
    )
    assert browser_revoke.status_code == 303

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, subscription["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
    assert (
        client.get("/internal/v2/wireguard/peers", headers=relay_headers).json()[
            "smtp_allowed_prefixes"
        ]
        == []
    )
    inactive = client.post(path, json=request, headers=_auth("TESTADMIN0000"))
    assert inactive.status_code == 400
    assert inactive.json()["detail"] == "subscription is not an active routed Blindport IP"


def test_account_suspension_permanently_revokes_routed_smtp(app_client, monkeypatch) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    account = client.post("/api/v2/signup").json()
    subscription = _activate_routed_ip(client, factory, account["token"])
    path = f"/api/v2/admin/subscriptions/{subscription['id']}/smtp-egress/approve"
    request = {
        "intended_use": "Transactional account notifications",
        "fee_paid_sats": 50000,
        "review_reference": "suspension-review-1",
    }
    admin = _auth("TESTADMIN0000")

    assert client.post(path, json=request, headers=admin).status_code == 200
    suspended = client.post(f"/api/v2/admin/users/{account['account_id']}/suspend", headers=admin)
    assert suspended.status_code == 200, suspended.text
    blocked = client.post(path, json=request, headers=admin)
    assert blocked.status_code == 400
    assert blocked.json()["detail"] == "subscription is not an active routed Blindport IP"
    assert (
        client.post(
            f"/api/v2/admin/users/{account['account_id']}/unsuspend", headers=admin
        ).status_code
        == 200
    )

    from blindport.core.models import IPLease
    from blindport.db import engine

    with Session(engine) as session:
        lease = session.exec(select(IPLease)).one()
        assert lease.smtp_enabled is False
        assert lease.smtp_revoked_at is not None
        assert lease.smtp_revocation_reason == "account suspended"


def test_routed_dashboard_hides_payments_when_yearly_billing_is_disabled(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    _configure_wireguard(monkeypatch)
    account = client.post("/api/v2/signup").json()
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
        headers=_auth(account["token"]),
    )
    assert subscription.status_code == 200, subscription.text

    from blindport.api import pages

    monkeypatch.setattr(pages.settings, "BILLING_YEARLY_ENABLED", False)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Annual routed-IP payments are currently unavailable." in dashboard.text
    assert 'class="payBtn' not in dashboard.text
    assert 'class="stablecoinPayBtn' not in dashboard.text
    assert 'class="nwcPayBtn' not in dashboard.text
    assert 'class="inline-nwc-form' not in dashboard.text


def test_legacy_ip_payment_history_is_read_only_and_cannot_be_renewed(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
        headers=_auth(token),
    ).json()
    issued = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    from blindport.core.models import BillingTerm, DeliveryMode, Payment
    from blindport.db import engine

    factory.get_lightning_adapter().mark_paid(issued["payment_hash"])
    assert client.get(f"/api/v1/payments/{issued['id']}", headers=_auth(token)).status_code == 200
    with Session(engine) as session:
        payment = session.get(Payment, issued["id"])
        assert payment is not None
        subscription_row = subscription_by_public_id(session, subscription["id"])
        assert subscription_row is not None
        subscription_row.delivery = DeliveryMode.FRAMED
        session.add(subscription_row)
        session.commit()

    framed_renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert framed_renewal.status_code == 400
    assert (
        framed_renewal.json()["detail"] == "Blindport IP is available with WireGuard delivery only"
    )
    connected = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://historical-ip"},
        headers=_auth(token),
    )
    assert connected.status_code == 200, connected.text
    framed_auto_renew = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )
    assert framed_auto_renew.status_code == 400
    assert (
        framed_auto_renew.json()["detail"]
        == "Blindport IP is available with WireGuard delivery only"
    )

    with Session(engine) as session:
        subscription_row = subscription_by_public_id(session, subscription["id"])
        assert subscription_row is not None
        subscription_row.delivery = DeliveryMode.WIREGUARD
        subscription_row.billing_term = BillingTerm.MONTHLY
        session.add(subscription_row)
        session.commit()

    monthly_renewal = client.post(
        "/api/v1/payments",
        json={
            "subscription_id": subscription["id"],
            "method": "lightning",
            "billing_term": "yearly",
        },
        headers=_auth(token),
    )
    assert monthly_renewal.status_code == 400
    assert (
        monthly_renewal.json()["detail"]
        == "WireGuard Blindport IP is available with yearly billing only"
    )
    assert client.delete("/api/v1/me/nwc", headers=_auth(token)).status_code == 200
    monthly_auto_renew = client.post(
        "/api/v1/me/nwc",
        json={
            "nwc_uri": "nostr+walletconnect://historical-monthly-ip",
            "auto_renew_subscription_id": subscription["id"],
        },
        headers=_auth(token),
    )
    assert monthly_auto_renew.status_code == 400
    assert monthly_auto_renew.headers["Cache-Control"] == "no-store"
    assert (
        monthly_auto_renew.json()["detail"]
        == "WireGuard Blindport IP is available with yearly billing only"
    )
    assert client.get("/api/v1/me/nwc", headers=_auth(token)).json()["has_nwc"] is False

    client.cookies.set("blindport_token", token)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert (
        "This historical Blindport IP remains visible, but new payments and renewals are unavailable."
        in dashboard.text
    )
    assert 'class="payBtn' not in dashboard.text
    assert 'class="stablecoinPayBtn' not in dashboard.text
    assert 'class="nwcPayBtn' not in dashboard.text
    assert 'class="inline-nwc-form' not in dashboard.text
    assert 'class="autoRenewToggle' not in dashboard.text
    assert "Unavailable for historical endpoint" in dashboard.text

    historical = client.get(f"/api/v1/payments/{issued['id']}", headers=_auth(token))
    assert historical.status_code == 200
    assert historical.json()["id"] == issued["id"]


def test_ip_lease_lifecycle_and_reassignment_history(app_client, monkeypatch) -> None:
    client, factory = app_client
    _configure_wireguard(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _activate_routed_ip(client, factory, token)

    from blindport.core.models import IPLease, IPLeaseState
    from blindport.db import engine
    from blindport.services import subscriptions as subscription_service

    with Session(engine) as session:
        stored = subscription_by_public_id(session, subscription["id"])
        assert stored is not None
        first_lease = session.exec(select(IPLease)).one()
        first_id = first_lease.public_id
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
        subscription_service.expire_elapsed_subscriptions(session, [stored])
        session.refresh(first_lease)
        assert first_lease.state == IPLeaseState.QUARANTINED
        assert first_lease.expired_at is not None
        subscription_service.renew_subscription(session, stored, 365)
        session.commit()
        session.refresh(first_lease)
        assert first_lease.public_id == first_id
        assert first_lease.state == IPLeaseState.ACTIVE

        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
        subscription_service.expire_elapsed_subscriptions(session, [stored])
        stored.resource_quarantined_until = datetime.now(UTC) - timedelta(seconds=1)
        first_lease.quarantine_until = stored.resource_quarantined_until
        session.add(stored)
        session.add(first_lease)
        session.commit()
        subscription_service.reap_elapsed_resource_holds(session)
        session.refresh(first_lease)
        assert first_lease.state == IPLeaseState.RELEASED
        assert first_lease.released_at is not None

    second = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip", "delivery": "wireguard", "billing_term": "yearly"},
        headers=_auth(token),
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": second["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment.status_code == 200, payment.text
    with Session(engine) as session:
        leases = session.exec(select(IPLease).order_by(IPLease.created_at)).all()
        assert len(leases) == 2
        assert leases[0].released_at is not None
        assert leases[1].released_at is None
        assert leases[0].address == leases[1].address == "198.51.100.20"


def test_port_reservation_does_not_create_ip_lease(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment.status_code == 200, payment.text

    from blindport.core.models import IPLease
    from blindport.db import engine

    with Session(engine) as session:
        assert session.exec(select(IPLease)).all() == []
