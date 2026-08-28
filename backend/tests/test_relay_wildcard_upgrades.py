"""Focused lifecycle coverage for exact Relay to wildcard upgrades."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


class _TxtRecord:
    def __init__(self, value: str) -> None:
        self.strings = (value.encode("ascii"),)


class _Resolver:
    def __init__(self, answers: dict[tuple[str, str], object]) -> None:
        self.answers = answers

    def resolve(self, name: str, rdtype: str, *, search: bool, lifetime: float):
        return self.answers[(name, rdtype)]


def _set_resolver_verifier(client, subscription: dict) -> None:
    from blindport.api import v1
    from blindport.services.domain_verification import DnsPythonDomainVerifier

    resolver = _Resolver(
        {
            (subscription["domain_challenge_name"], "TXT"): [
                _TxtRecord(subscription["domain_challenge_value"])
            ],
        }
    )
    verifier = DnsPythonDomainVerifier(resolver=resolver, lifetime=0.5)
    client.app.dependency_overrides[v1._domain_verifier_dependency] = lambda: lambda: verifier


def _set_active_exact(
    public_id: str,
    *,
    period_start: datetime,
    period_end: datetime,
    billing_term: str = "monthly",
    monthly_price_sats: int = 3000,
    yearly_price_sats: int = 30000,
    managed: bool = False,
) -> None:
    from blindport.core.models import BillingTerm, Subscription, SubscriptionStatus
    from blindport.db import engine

    with Session(engine) as session:
        source = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(public_id))
        ).one()
        source.status = SubscriptionStatus.ACTIVE
        source.current_period_start = period_start
        source.current_period_end = period_end
        source.billing_term = BillingTerm(billing_term)
        source.monthly_price_sats = monthly_price_sats
        source.yearly_price_sats = yearly_price_sats
        source.domain_is_managed = managed
        source.domain_verified_at = None if managed else period_start
        # A stable non-generated target means the existing exact claim need not
        # re-query DNS before its blocked renewal-payment assertion.
        source.relay_pool_domain = "relay1.test"
        source.domain_claim_expires_at = None
        session.add(source)
        session.commit()


def _create_exact(client, token: str, domain: str = "app.example.com") -> dict:
    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": domain},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    return response.json()


def _upgrade(client, token: str, source_id: str, billing_term: str = "monthly"):
    return client.post(
        f"/api/v1/subscriptions/{source_id}/wildcard-upgrade",
        json={"billing_term": billing_term},
        headers=_auth(token),
    )


def _csr() -> str:
    key = Ed25519PrivateKey.generate()
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def test_monthly_upgrade_snapshots_floor_proration_and_wildcard_prices(
    app_client, monkeypatch
) -> None:
    from blindport.services import subscriptions

    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(subscriptions, "_utcnow", lambda: now)
    monkeypatch.setattr(subscriptions.settings, "RELAY_WILDCARD_MONTHLY_SATS", 8101)
    monkeypatch.setattr(subscriptions.settings, "RELAY_WILDCARD_YEARLY_SATS", 81001)
    _set_active_exact(
        source["id"],
        period_start=now - timedelta(days=15),
        period_end=now + timedelta(days=15, seconds=1),
    )

    created = _upgrade(client, token, source["id"])

    assert created.status_code == 200, created.text
    target = created.json()
    expected_credit = ((15 * 86_400 + 1) * 3000) // (30 * 86_400)
    assert target["domain"] == "example.com"
    assert target["status"] == "pending"
    assert target["relay_hostname_scope"] == "wildcard"
    assert target["upgrade_from_subscription_id"] == source["id"]
    assert target["upgrade_credit_sats"] == expected_credit
    assert (target["monthly_price_sats"], target["yearly_price_sats"]) == (8101, 81001)


def test_upgrade_rejects_ineligible_sources_and_conflicts(app_client, monkeypatch) -> None:
    from blindport.core.models import (
        Payment,
        PaymentMethod,
        ProductType,
        RelayHostnameScope,
        Subscription,
        SubscriptionStatus,
    )
    from blindport.db import engine

    client, _ = app_client
    owner = client.post("/api/v1/signup").json()["token"]
    other = client.post("/api/v1/signup").json()["token"]
    now = datetime.now(UTC)
    source = _create_exact(client, owner)
    _set_active_exact(
        source["id"], period_start=now - timedelta(days=1), period_end=now + timedelta(days=29)
    )

    assert _upgrade(client, other, source["id"]).status_code == 404

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.domain_is_managed = True
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.domain_is_managed = False
        stored.status = SubscriptionStatus.PENDING
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.status = SubscriptionStatus.EXPIRED
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.status = SubscriptionStatus.ACTIVE
        stored.product = ProductType.PORT
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.product = ProductType.RELAY
        stored.domain = "app.example"
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    # A source payment takes priority over creating another claim.
    with Session(engine) as session:
        stored = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        stored.domain = "app.example.com"
        session.add(
            Payment(subscription_id=stored.id, method=PaymentMethod.LIGHTNING, amount_sats=1)
        )
        session.add(stored)
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    # An independent exact descendant blocks the wildcard base.
    with Session(engine) as session:
        source_row = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        payment = session.exec(
            select(Payment).where(Payment.subscription_id == source_row.id)
        ).one()
        payment.status = "expired"
        session.add(payment)
        session.add_all(
            [
                Subscription(
                    user_id=source_row.user_id,
                    product=ProductType.RELAY,
                    status=SubscriptionStatus.ACTIVE,
                    domain="child.example.com",
                    relay_hostname_scope=RelayHostnameScope.EXACT,
                    monthly_price_sats=3000,
                ),
            ]
        )
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400

    # A sibling wildcard claim independently blocks the same base domain.
    with Session(engine) as session:
        source_row = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        exact = session.exec(
            select(Subscription).where(Subscription.domain == "child.example.com")
        ).one()
        exact.status = SubscriptionStatus.CANCELLED
        exact.domain = None
        session.add(exact)
        session.add(
            Subscription(
                user_id=source_row.user_id,
                product=ProductType.RELAY,
                status=SubscriptionStatus.CANCELLED,
                domain="sibling.example.com",
                relay_hostname_scope=RelayHostnameScope.WILDCARD,
                monthly_price_sats=7500,
            )
        )
        session.commit()
    assert _upgrade(client, owner, source["id"]).status_code == 400


def test_pending_upgrade_preserves_source_entitlements_and_blocks_source_changes(
    app_client, monkeypatch, tmp_path
) -> None:
    from blindport.api import v3
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    signup = client.post("/api/v2/signup").json()
    token = signup["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC)
    _set_active_exact(
        source["id"], period_start=now - timedelta(days=1), period_end=now + timedelta(days=29)
    )
    target = _upgrade(client, token, source["id"]).json()

    key_path = tmp_path / "offline.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    instance_id = str(uuid4())
    monkeypatch.setattr(v3.settings, "OFFLINE_ENTITLEMENTS_ENABLED", True)
    monkeypatch.setattr(v3.settings, "OFFLINE_ENTITLEMENT_KEY_ID", "upgrade-test")
    monkeypatch.setattr(v3.settings, "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE", str(key_path))
    assert (
        client.post(
            "/api/v2/client/certificate",
            headers=_auth(token),
            json={"instance_id": instance_id, "generation": 1, "csr_pem": _csr()},
        ).status_code
        == 200
    )

    v3_config = client.get(f"/api/v3/client/config?instance_id={instance_id}", headers=_auth(token))
    assert v3_config.status_code == 200, v3_config.text
    assert {row["subscription_id"] for row in v3_config.json()["subscriptions"]} == {source["id"]}
    resolved = client.post(
        "/internal/v3/resolve",
        json={"token": token, "claim": {"kind": "relay", "domain": "app.example.com"}},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["subscription_id"] == source["id"]
    assert target["status"] == "pending"

    blocked_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": source["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert blocked_payment.status_code == 400
    assert "pending wildcard upgrade" in blocked_payment.text
    with Session(engine) as session:
        source_row = session.exec(select(User)).first()
        assert source_row is not None
        source_row.has_nwc = True
        session.add(source_row)
        session.commit()
    blocked_auto_renew = client.post(
        f"/api/v1/subscriptions/{source['id']}/auto-renew?enable=true", headers=_auth(token)
    )
    assert blocked_auto_renew.status_code == 400
    assert "pending wildcard upgrade" in blocked_auto_renew.text


def test_lightning_upgrade_verifies_dns_and_transitions_once(app_client) -> None:
    from blindport.core.models import Subscription
    from blindport.db import engine

    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC)
    _set_active_exact(
        source["id"], period_start=now - timedelta(days=1), period_end=now + timedelta(days=29)
    )
    target = _upgrade(client, token, source["id"]).json()
    _set_resolver_verifier(client, target)

    verified = client.post(
        f"/api/v1/subscriptions/{target['id']}/verify-domain", headers=_auth(token)
    )
    assert verified.status_code == 200, verified.text
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": target["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment.status_code == 200, payment.text
    assert (
        payment.json()["service_price_sats"],
        payment.json()["discount_sats"],
        payment.json()["amount_sats"],
        payment.json()["standard_period_days"],
    ) == (7500, target["upgrade_credit_sats"], 7500 - target["upgrade_credit_sats"], 30)

    factory.get_lightning_adapter().mark_paid(payment.json()["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment.json()['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"
    assert (
        client.get(f"/api/v1/payments/{payment.json()['id']}", headers=_auth(token)).json()[
            "status"
        ]
        == "paid"
    )
    with Session(engine) as session:
        source_row = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        target_row = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(target["id"]))
        ).one()
        assert (source_row.status, source_row.domain) == ("cancelled", None)
        assert (target_row.status, target_row.domain, target_row.relay_hostname_scope) == (
            "active",
            "example.com",
            "wildcard",
        )
        assert target_row.current_period_end - target_row.current_period_start == timedelta(days=30)


def test_upgrade_invoice_is_bounded_by_source_and_settles_after_expiry_transition(
    app_client,
) -> None:
    from blindport.core.models import Subscription, SubscriptionStatus
    from blindport.db import engine

    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC)
    source_period_end = now + timedelta(minutes=30)
    _set_active_exact(
        source["id"], period_start=now - timedelta(days=30), period_end=source_period_end
    )
    target = _upgrade(client, token, source["id"]).json()
    _set_resolver_verifier(client, target)
    assert (
        client.post(
            f"/api/v1/subscriptions/{target['id']}/verify-domain", headers=_auth(token)
        ).status_code
        == 200
    )

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": target["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    assert datetime.fromisoformat(payment["expires_at"]) <= source_period_end

    with Session(engine) as session:
        source_row = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(source["id"]))
        ).one()
        source_row.status = SubscriptionStatus.EXPIRED
        source_row.domain_renewal_grace_expires_at = source_period_end + timedelta(days=7)
        session.add(source_row)
        session.commit()

    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert settled.status_code == 200, settled.text
    assert settled.json()["status"] == "paid"
    rows = {
        row["id"]: row for row in client.get("/api/v1/subscriptions", headers=_auth(token)).json()
    }
    assert (rows[source["id"]]["status"], rows[target["id"]]["status"]) == (
        "cancelled",
        "active",
    )


def test_cancelled_unpaid_upgrade_leaves_source_renewable_and_upgradeable(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC)
    _set_active_exact(
        source["id"], period_start=now - timedelta(days=1), period_end=now + timedelta(days=29)
    )
    target = _upgrade(client, token, source["id"]).json()
    cancelled = client.delete(f"/api/v1/subscriptions/{target['id']}", headers=_auth(token))
    assert cancelled.status_code == 200, cancelled.text
    assert (
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0]["status"]
        == "active"
    )
    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": source["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal.status_code == 200, renewal.text


def test_zero_due_upgrade_activates_without_an_invoice(app_client, monkeypatch) -> None:
    from blindport.services import subscriptions

    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(subscriptions, "_utcnow", lambda: now)
    _set_active_exact(
        source["id"],
        period_start=now - timedelta(days=30),
        period_end=now + timedelta(days=30),
        monthly_price_sats=7500,
    )
    target = _upgrade(client, token, source["id"]).json()
    _set_resolver_verifier(client, target)

    paid = client.post(
        "/api/v1/payments",
        json={"subscription_id": target["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert paid.status_code == 200, paid.text
    assert (paid.json()["status"], paid.json()["amount_sats"], paid.json()["invoice"]) == (
        "paid",
        0,
        None,
    )
    rows = {
        row["id"]: row
        for row in client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"]
    }
    assert (rows[source["id"]]["status"], rows[target["id"]]["status"]) == ("cancelled", "active")


def test_discounted_stablecoin_upgrade_floor_uses_full_wildcard_price(
    app_client, monkeypatch
) -> None:
    from blindport.services import payments, subscriptions

    client, factory = app_client
    monkeypatch.setattr(payments.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(payments.settings, "STABLECOIN_CHECKOUT_PROVIDER", "lightning_swap")
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MARKUP_BPS", 1000)
    monkeypatch.setattr(payments.settings, "STABLECOIN_SWAP_MIN_INVOICE_SATS", 5000)
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(subscriptions, "_utcnow", lambda: now)
    _set_active_exact(
        source["id"],
        period_start=now - timedelta(days=10),
        period_end=now + timedelta(days=20),
        monthly_price_sats=7500,
    )
    target = _upgrade(client, token, source["id"]).json()
    _set_resolver_verifier(client, target)

    created = client.post(
        "/api/v1/payments",
        json={"subscription_id": target["id"], "method": "stablecoin_swap"},
        headers=_auth(token),
    )
    assert created.status_code == 200, created.text
    payment = created.json()
    expected_days = payments.stablecoin_credited_days(5000, 2500, 250, 30, 7500)
    assert (
        payment["service_price_sats"],
        payment["discount_sats"],
        payment["base_amount_sats"],
    ) == (
        7500,
        5000,
        2500,
    )
    assert (
        payment["amount_sats"],
        payment["stablecoin_surcharge_sats"],
        payment["period_days"],
    ) == (
        5000,
        250,
        expected_days,
    )
    assert payment["period_days"] >= 30
    assert payment["period_days"] != payments.stablecoin_credited_days(5000, 2500, 250, 30, 2500)
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    assert (
        client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).json()["status"]
        == "paid"
    )


def test_annual_source_proration_uses_yearly_snapshot(app_client, monkeypatch) -> None:
    from blindport.services import subscriptions

    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    source = _create_exact(client, token)
    now = datetime.now(UTC).replace(microsecond=0)
    monkeypatch.setattr(subscriptions, "_utcnow", lambda: now)
    _set_active_exact(
        source["id"],
        period_start=now - timedelta(days=355),
        period_end=now + timedelta(days=10, seconds=1),
        billing_term="yearly",
        monthly_price_sats=1,
        yearly_price_sats=36500,
    )

    target = _upgrade(client, token, source["id"])

    assert target.status_code == 200, target.text
    assert target.json()["upgrade_credit_sats"] == ((10 * 86_400 + 1) * 36500) // (365 * 86_400)
