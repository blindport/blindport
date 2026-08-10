"""Blindport Relay managed-domain and customer DNS ownership verification tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import dns.exception
import dns.name
import dns.resolver
import pytest
from sqlmodel import Session
from subscription_helpers import subscription_by_public_id


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signup(client) -> str:
    return client.post("/api/v1/signup").json()["token"]


def _subscribe(client, token: str, domain: str) -> dict:
    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": domain},
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    return response.json()


class FakeTxtRecord:
    def __init__(self, *segments: bytes) -> None:
        self.strings = segments


class FakeCnameRecord:
    def __init__(self, target: str | dns.name.Name) -> None:
        self.target = dns.name.from_text(target) if isinstance(target, str) else target


class FakeResolver:
    def __init__(self, answer: object) -> None:
        self.answer = answer
        self.calls: list[tuple[str, str, bool, float]] = []

    def resolve(self, name: str, rdtype: str, *, search: bool, lifetime: float):
        self.calls.append((name, rdtype, search, lifetime))
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


def _set_verifier(client, verifier) -> None:
    from blindport.api import v1

    client.app.dependency_overrides[v1._domain_verifier_dependency] = lambda: lambda: verifier


def _activate_managed(client, factory, token: str, domain: str) -> dict:
    sub = _subscribe(client, token, domain)
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"
    return client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]


def test_managed_subdomain_is_immediately_verified_and_apex_is_rejected(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "Alice.RELAY.TEST.")

    assert sub["domain"] == "alice.relay.test"
    assert sub["domain_is_managed"] is True
    assert sub["domain_verified_at"] is not None
    assert sub["domain_verification_expires_at"] is not None
    assert sub["domain_challenge_name"] is None
    assert sub["domain_challenge_value"] is None
    assert sub["record_type"] is None
    assert sub["record_name"] is None
    assert sub["record_target"] is None

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment.status_code == 200, payment.text
    assert payment.json()["invoice"]

    apex = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "relay.test"},
        headers=_auth(token),
    )
    assert apex.status_code == 400
    assert "apex" in apex.json()["detail"]


def test_managed_apex_rejection_wins_over_broader_suffix(app_client, monkeypatch) -> None:
    client, _ = app_client
    token = _signup(client)

    from blindport.services import subscriptions

    monkeypatch.setattr(
        subscriptions.settings,
        "RELAY_MANAGED_SUFFIXES",
        "test,relay.test",
    )
    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "relay.test"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert "apex" in response.json()["detail"]


def test_custom_subscriptions_expose_unique_stable_cname_targets(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "BÜCHER.Example.")
    other = _subscribe(client, token, "other.example")

    assert sub["domain"] == "xn--bcher-kva.example"
    assert sub["domain_is_managed"] is False
    assert sub["domain_verified_at"] is None
    assert sub["domain_challenge_name"] is None
    assert sub["domain_challenge_value"] is None
    assert sub["record_type"] == "CNAME"
    assert sub["record_name"] == sub["domain"]
    assert sub["record_target"] == sub["relay_pool_domain"]
    label, base = sub["record_target"].split(".", 1)
    assert len(label) == 32
    assert label == label.lower()
    assert all(character in "0123456789abcdef" for character in label)
    assert base in {"relay1.test", "relay2.test"}
    assert other["record_target"] != sub["record_target"]
    assert {base, other["record_target"].split(".", 1)[1]} == {
        "relay1.test",
        "relay2.test",
    }
    assert sub["domain_verification_expires_at"] is not None

    listed = client.get("/api/v1/subscriptions", headers=_auth(token)).json()
    assert listed[0]["record_target"] == sub["record_target"]
    assert listed[1]["record_target"] == other["record_target"]


def test_exact_direct_cname_verifies_with_bounded_nonsearching_lookup(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")
    resolver = FakeResolver([FakeCnameRecord(sub["record_target"].upper() + ".")])

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(client, DnsPythonDomainVerifier(resolver=resolver, lifetime=1.25))
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["verified"] is True
    assert result["subscription"]["domain_verified_at"] is not None
    assert (
        result["subscription"]["domain_verification_expires_at"]
        == sub["domain_verification_expires_at"]
    )
    assert result["subscription"]["domain_challenge_name"] is None
    assert result["subscription"]["domain_challenge_value"] is None
    assert result["subscription"]["record_target"] == sub["record_target"]
    assert resolver.calls == [(sub["domain"], "CNAME", False, 1.25)]


def test_payment_creation_automatically_verifies_cname(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")
    resolver = FakeResolver([FakeCnameRecord(sub["record_target"] + ".")])

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(client, DnsPythonDomainVerifier(resolver=resolver, lifetime=0.75))
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )

    assert payment.status_code == 200, payment.text
    assert payment.json()["invoice"]
    listed = client.get("/api/v1/subscriptions", headers=_auth(token)).json()
    assert listed[0]["domain_verified_at"] is not None
    assert resolver.calls == [(sub["domain"], "CNAME", False, 0.75)]


def test_payment_creation_rejects_unmatched_cname_without_manual_check(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(
            resolver=FakeResolver([FakeCnameRecord("wrong.ingress.example.")]),
            lifetime=0.5,
        ),
    )
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )

    assert payment.status_code == 400
    assert payment.json()["detail"] == "CNAME target did not match"


def test_renewal_payment_rechecks_unique_cname_target(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    matching = FakeResolver([FakeCnameRecord(sub["record_target"] + ".")])
    _set_verifier(client, DnsPythonDomainVerifier(resolver=matching, lifetime=0.5))
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"

    mismatch = FakeResolver([FakeCnameRecord("wrong.ingress.example.")])
    _set_verifier(client, DnsPythonDomainVerifier(resolver=mismatch, lifetime=0.5))
    blocked = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert blocked.status_code == 400
    assert blocked.json()["detail"] == "CNAME target did not match"

    matching_again = FakeResolver([FakeCnameRecord(sub["record_target"] + ".")])
    _set_verifier(client, DnsPythonDomainVerifier(resolver=matching_again, lifetime=0.5))
    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal.status_code == 200, renewal.text
    assert matching_again.calls == [(sub["domain"], "CNAME", False, 0.5)]


@pytest.mark.parametrize(
    "answer,detail",
    [
        ([FakeCnameRecord("wrong.relay1.test.")], "did not match"),
        (dns.resolver.NXDOMAIN(), "does not exist"),
        (dns.resolver.NoAnswer(), "not found"),
        (dns.exception.Timeout(), "timed out"),
    ],
)
def test_unsuccessful_cname_results_are_clean(app_client, answer, detail: str) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(client, DnsPythonDomainVerifier(resolver=FakeResolver(answer), lifetime=0.5))
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )
    assert response.status_code == 200, response.text
    assert response.json()["verified"] is False
    assert detail in response.json()["detail"]
    assert response.json()["subscription"]["record_target"] == sub["record_target"]


@pytest.mark.parametrize("target", ["relay2.test.", "intermediate.example."])
def test_cname_does_not_accept_another_pool_target_or_chain(app_client, target: str) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")
    assert sub["record_target"].endswith(".relay1.test")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(resolver=FakeResolver([FakeCnameRecord(target)]), lifetime=0.5),
    )
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["verified"] is False
    assert response.json()["detail"] == "CNAME target did not match"


@pytest.mark.parametrize(
    "answer",
    [
        [FakeCnameRecord("first.example."), FakeCnameRecord("second.example.")],
        [FakeCnameRecord(dns.name.from_text("relative-target", origin=None))],
    ],
)
def test_invalid_cname_answers_are_upstream_errors(app_client, answer) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(resolver=FakeResolver(answer), lifetime=0.5),
    )
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )

    assert response.status_code == 502


def test_resolver_failure_is_upstream_error(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(resolver=FakeResolver(dns.resolver.NoNameservers()), lifetime=0.5),
    )
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )
    assert response.status_code == 502


def test_resolver_unavailable_is_service_unavailable(app_client) -> None:
    client, _ = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import ResolverUnavailableError

    class UnavailableVerifier:
        def verify_cname(self, name: str, expected_target: str):
            raise ResolverUnavailableError("DNS resolver is unavailable")

    _set_verifier(client, UnavailableVerifier())
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(token),
    )
    assert response.status_code == 503


def test_resolver_setup_is_lazy_for_managed_and_verified_idempotent_calls(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 3)
    token = _signup(client)
    managed = _subscribe(client, token, "lazy.relay.test")
    custom = _subscribe(client, token, "lazy.example")

    from blindport.api import v1
    from blindport.services.domain_verification import (
        DnsPythonDomainVerifier,
        ResolverUnavailableError,
    )

    _set_verifier(
        client,
        DnsPythonDomainVerifier(
            resolver=FakeResolver([FakeCnameRecord(custom["record_target"] + ".")]),
            lifetime=0.5,
        ),
    )
    verified = client.post(
        f"/api/v1/subscriptions/{custom['id']}/verify-domain",
        headers=_auth(token),
    )
    assert verified.json()["verified"] is True

    setup_calls = 0

    def failed_setup():
        nonlocal setup_calls
        setup_calls += 1
        raise ResolverUnavailableError("DNS resolver is not configured")

    client.app.dependency_overrides[v1._domain_verifier_dependency] = lambda: failed_setup
    for sub_id in (managed["id"], custom["id"]):
        response = client.post(
            f"/api/v1/subscriptions/{sub_id}/verify-domain",
            headers=_auth(token),
        )
        assert response.status_code == 200, response.text
        assert response.json()["verified"] is True
    assert setup_calls == 0

    outstanding = _subscribe(client, token, "outstanding.example")
    response = client.post(
        f"/api/v1/subscriptions/{outstanding['id']}/verify-domain",
        headers=_auth(token),
    )
    assert response.status_code == 503
    assert setup_calls == 1


def test_existing_pending_txt_claim_retains_legacy_verification(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    created = _subscribe(client, token, "legacy.example")

    from blindport.db import engine

    legacy_token = "legacy-token-created-before-cname-rollout"
    with Session(engine) as session:
        stored = subscription_by_public_id(session, created["id"])
        assert stored is not None
        stored.relay_pool_domain = None
        stored.domain_verification_token = legacy_token
        session.add(stored)
        session.commit()

    legacy = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    expected = f"blindport-verification={legacy_token}"
    assert legacy["record_type"] == "TXT"
    assert legacy["record_name"] == "_blindport-challenge.legacy.example"
    assert legacy["record_target"] == expected
    assert legacy["domain_challenge_name"] == legacy["record_name"]
    assert legacy["domain_challenge_value"] == expected

    resolver = FakeResolver(
        [FakeTxtRecord(b"unrelated"), FakeTxtRecord(expected[:20].encode(), expected[20:].encode())]
    )
    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(client, DnsPythonDomainVerifier(resolver=resolver, lifetime=0.75))
    response = client.post(
        f"/api/v1/subscriptions/{created['id']}/verify-domain",
        headers=_auth(token),
    )

    assert response.status_code == 200, response.text
    assert response.json()["verified"] is True
    assert response.json()["subscription"]["domain_challenge_value"] is None
    assert resolver.calls == [(legacy["record_name"], "TXT", False, 0.75)]

    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": created["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    active = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert active["status"] == "active"
    assert active["relay_pool_domain"] in {"relay1.test", "relay2.test"}
    assert active["record_type"] == "CNAME"
    assert active["record_name"] == "legacy.example"
    assert active["record_target"] == active["relay_pool_domain"]
    assert active["domain_challenge_name"] is None


def test_unverified_payment_is_blocked_before_adapter_call(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")
    calls = 0

    def create_invoice(amount_sats: int, memo: str, expiry_seconds: int | None = None):
        nonlocal calls
        calls += 1
        raise AssertionError("payment adapter must not be called")

    monkeypatch.setattr(factory.get_lightning_adapter(), "create_invoice", create_invoice)
    response = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "record name does not exist"
    assert calls == 0


def test_expired_claim_is_released_and_reclaimable(app_client) -> None:
    client, _ = app_client
    first_token = _signup(client)
    second_token = _signup(client)
    first = _subscribe(client, first_token, "customer.example")

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, first["id"])
        assert stored is not None
        stored.domain_claim_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    reclaimed = _subscribe(client, second_token, "customer.example")
    assert reclaimed["id"] != first["id"]

    old_verify = client.post(
        f"/api/v1/subscriptions/{first['id']}/verify-domain",
        headers=_auth(first_token),
    )
    assert old_verify.status_code == 400
    assert "expired" in old_verify.json()["detail"]
    old_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": first["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    assert old_payment.status_code == 400
    assert "expired" in old_payment.json()["detail"]

    with Session(engine) as session:
        expired = subscription_by_public_id(session, first["id"])
        assert expired is not None
        assert expired.status.value == "cancelled"
        assert expired.domain is None
        assert expired.relay_pool_domain is None


def test_expiry_releases_unpaid_managed_verified_and_unverified_claims(
    app_client, monkeypatch
) -> None:
    client, _ = app_client
    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 3)
    token = _signup(client)
    managed = _subscribe(client, token, "unpaid.relay.test")
    verified = _subscribe(client, token, "verified-unpaid.example")
    unverified = _subscribe(client, token, "unverified-unpaid.example")

    from blindport.db import engine
    from blindport.services.subscriptions import reap_expired_domain_claims

    with Session(engine) as session:
        verified_row = subscription_by_public_id(session, verified["id"])
        assert verified_row is not None
        verified_row.domain_verified_at = datetime.now(UTC)
        verified_row.domain_verification_token = None
        session.add(verified_row)
        for sub_id in (managed["id"], verified["id"], unverified["id"]):
            row = subscription_by_public_id(session, sub_id)
            assert row is not None
            row.domain_claim_expires_at = datetime.now(UTC) - timedelta(seconds=1)
            session.add(row)
        session.commit()

        assert reap_expired_domain_claims(session) == 3
        for sub_id in (managed["id"], verified["id"], unverified["id"]):
            row = subscription_by_public_id(session, sub_id, populate_existing=True)
            assert row is not None
            assert row.status.value == "cancelled"
            assert row.domain is None


@pytest.mark.parametrize("method", ["lightning", "nwc"])
def test_provider_settlement_wins_before_initial_claim_release(app_client, method: str) -> None:
    client, factory = app_client
    token = _signup(client)
    if method == "nwc":
        client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://domain-boundary"},
            headers=_auth(token),
        )
    sub = _subscribe(client, token, f"{method}.relay.test")
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": method},
        headers=_auth(token),
    ).json()

    from blindport.core.models import Payment
    from blindport.db import engine

    elapsed = datetime.now(UTC) - timedelta(seconds=1)
    with Session(engine) as session:
        stored_sub = subscription_by_public_id(session, sub["id"])
        stored_payment = session.get(Payment, payment["id"])
        assert stored_sub is not None and stored_payment is not None
        stored_sub.domain_claim_expires_at = elapsed
        stored_payment.created_at = elapsed - timedelta(seconds=1)
        stored_payment.expires_at = elapsed
        session.add(stored_sub)
        session.add(stored_payment)
        session.commit()

    if method == "lightning":
        factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    else:
        factory.get_nwc_adapter().mark_settled(payment["payment_hash"])

    current = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert current["status"] == "active"
    assert current["domain"] == f"{method}.relay.test"
    settled = client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).json()
    assert settled["status"] == "paid"


def test_processing_payment_and_failed_reconciliation_retain_elapsed_claim(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    token = _signup(client)
    processing_sub = _subscribe(client, token, "processing.relay.test")
    processing_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": processing_sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    uncertain_sub = _subscribe(client, token, "uncertain.relay.test")
    uncertain_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": uncertain_sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    from blindport.core.models import Payment, PaymentStatus
    from blindport.db import engine
    from blindport.services.subscriptions import reap_expired_domain_claims

    elapsed = datetime.now(UTC) - timedelta(seconds=1)
    with Session(engine) as session:
        for sub_id, payment_id in (
            (processing_sub["id"], processing_payment["id"]),
            (uncertain_sub["id"], uncertain_payment["id"]),
        ):
            stored_sub = subscription_by_public_id(session, sub_id)
            stored_payment = session.get(Payment, payment_id)
            assert stored_sub is not None and stored_payment is not None
            stored_sub.domain_claim_expires_at = elapsed
            stored_payment.expires_at = elapsed
            session.add(stored_sub)
            session.add(stored_payment)
        processing = session.get(Payment, processing_payment["id"])
        assert processing is not None
        processing.status = PaymentStatus.PROCESSING
        session.add(processing)
        session.commit()

        monkeypatch.setattr(
            factory.get_lightning_adapter(),
            "is_invoice_paid",
            lambda payment_hash: (_ for _ in ()).throw(RuntimeError("provider unavailable")),
        )
        assert reap_expired_domain_claims(session) == 0
        for sub_id in (processing_sub["id"], uncertain_sub["id"]):
            retained = subscription_by_public_id(session, sub_id, populate_existing=True)
            assert retained is not None
            assert retained.status.value == "pending"
            assert retained.domain is not None


def test_cross_user_cannot_verify_domain_claim(app_client) -> None:
    client, _ = app_client
    owner = _signup(client)
    other = _signup(client)
    sub = _subscribe(client, owner, "customer.example")
    response = client.post(
        f"/api/v1/subscriptions/{sub['id']}/verify-domain",
        headers=_auth(other),
    )
    assert response.status_code == 404


def test_reaper_never_releases_live_domain_claims(app_client, monkeypatch) -> None:
    client, _ = app_client
    from blindport.services import subscriptions

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 4)
    token = _signup(client)
    initial = _subscribe(client, token, "initial.example")
    verified = _subscribe(client, token, "verified.example")
    active = _subscribe(client, token, "active.relay.test")
    grace = _subscribe(client, token, "grace.relay.test")

    from blindport.core.models import SubscriptionStatus
    from blindport.db import engine
    from blindport.services.subscriptions import reap_expired_domain_claims

    elapsed = datetime.now(UTC) - timedelta(seconds=1)
    future = datetime.now(UTC) + timedelta(hours=1)
    with Session(engine) as session:
        stored_initial = subscription_by_public_id(session, initial["id"])
        stored_verified = subscription_by_public_id(session, verified["id"])
        stored_active = subscription_by_public_id(session, active["id"])
        stored_grace = subscription_by_public_id(session, grace["id"])
        assert all((stored_initial, stored_verified, stored_active, stored_grace))
        assert stored_initial is not None
        assert stored_verified is not None
        assert stored_active is not None
        assert stored_grace is not None

        stored_verified.domain_verified_at = datetime.now(UTC)
        stored_verified.domain_claim_expires_at = future
        stored_active.status = SubscriptionStatus.ACTIVE
        stored_active.current_period_end = future
        stored_active.domain_renewal_grace_expires_at = elapsed
        stored_grace.status = SubscriptionStatus.EXPIRED
        stored_grace.current_period_end = elapsed
        stored_grace.domain_renewal_grace_expires_at = future
        session.add(stored_verified)
        session.add(stored_active)
        session.add(stored_grace)
        session.commit()
        assert reap_expired_domain_claims(session) == 0
        for stored in (stored_initial, stored_verified, stored_active, stored_grace):
            session.refresh(stored)
            assert stored.domain is not None


def test_expiry_immediately_deauthorizes_but_retains_domain_during_grace(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    active = _activate_managed(client, factory, token, "expiry.relay.test")

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, active["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()

    resolved = client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert resolved.json()["relay_domains"] == []

    expired = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert expired["status"] == "expired"
    assert expired["domain"] == "expiry.relay.test"
    assert expired["relay_pool_domain"] == active["relay_pool_domain"]
    grace_deadline = datetime.fromisoformat(expired["domain_renewal_grace_expires_at"])
    assert grace_deadline.replace(tzinfo=grace_deadline.tzinfo or UTC) > datetime.now(UTC)


def test_owner_can_renew_during_grace_after_cname_reverification(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    pending = _subscribe(client, token, "renew.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(
            resolver=FakeResolver([FakeCnameRecord(pending["record_target"] + ".")]),
            lifetime=0.5,
        ),
    )
    verified = client.post(
        f"/api/v1/subscriptions/{pending['id']}/verify-domain", headers=_auth(token)
    )
    assert verified.json()["verified"] is True
    initial_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": pending["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial_payment["payment_hash"])
    client.get(f"/api/v1/payments/{initial_payment['id']}", headers=_auth(token))
    active = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert active["record_target"] == pending["record_target"]

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, active["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(minutes=1)
        session.add(stored)
        session.commit()

    client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": active["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal.status_code == 200, renewal.text
    factory.get_lightning_adapter().mark_paid(renewal.json()["payment_hash"])
    settled = client.get(f"/api/v1/payments/{renewal.json()['id']}", headers=_auth(token))
    assert settled.json()["status"] == "paid"

    renewed = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert renewed["status"] == "active"
    assert renewed["domain"] == "renew.example"
    assert renewed["relay_pool_domain"] == active["relay_pool_domain"]
    assert renewed["record_target"] == active["record_target"]
    assert renewed["domain_verified_at"] > active["domain_verified_at"]
    assert renewed["domain_challenge_value"] is None
    assert renewed["domain_renewal_grace_expires_at"] is None


def test_provider_settlement_wins_before_expired_domain_release(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    active = _activate_managed(client, factory, token, "renewal-boundary.relay.test")

    from blindport.core.models import Payment
    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, active["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(minutes=1)
        session.add(stored)
        session.commit()
    client.get("/api/v1/subscriptions", headers=_auth(token))
    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": active["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    elapsed = datetime.now(UTC) - timedelta(seconds=1)
    with Session(engine) as session:
        stored_sub = subscription_by_public_id(session, active["id"])
        stored_payment = session.get(Payment, renewal["id"])
        assert stored_sub is not None and stored_payment is not None
        stored_sub.domain_renewal_grace_expires_at = elapsed
        stored_payment.created_at = elapsed - timedelta(seconds=1)
        stored_payment.expires_at = elapsed
        session.add(stored_sub)
        session.add(stored_payment)
        session.commit()

    factory.get_lightning_adapter().mark_paid(renewal["payment_hash"])
    current = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert current["status"] == "active"
    assert current["domain"] == "renewal-boundary.relay.test"
    assert current["domain_renewal_grace_expires_at"] is None


def test_release_after_grace_clears_metadata_and_blocks_old_payment(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    active = _activate_managed(client, factory, token, "released.relay.test")

    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, active["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(minutes=1)
        session.add(stored)
        session.commit()
    client.post(
        "/internal/v1/resolve",
        json={"token": token},
        headers={"X-Relay-Secret": "test-secret"},
    )
    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": active["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()

    with Session(engine) as session:
        stored = subscription_by_public_id(session, active["id"])
        assert stored is not None
        elapsed = datetime.now(UTC) - timedelta(seconds=1)
        stored.domain_renewal_grace_expires_at = elapsed
        session.add(stored)
        from blindport.core.models import Payment

        stored_payment = session.get(Payment, renewal["id"])
        assert stored_payment is not None
        stored_payment.expires_at = elapsed
        session.add(stored_payment)
        session.commit()

    released = client.get("/api/v1/subscriptions", headers=_auth(token)).json()[0]
    assert released["status"] == "cancelled"
    assert released["domain"] is None
    assert released["relay_pool_domain"] is None
    assert released["domain_is_managed"] is False
    assert released["domain_verified_at"] is None
    assert released["domain_renewal_grace_expires_at"] is None

    factory.get_lightning_adapter().mark_paid(renewal["payment_hash"])
    old_payment = client.get(f"/api/v1/payments/{renewal['id']}", headers=_auth(token))
    assert old_payment.json()["status"] == "expired"
    retry = client.post(
        "/api/v1/payments",
        json={"subscription_id": active["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert retry.status_code == 400
    assert retry.json()["detail"] == (
        "Blindport Relay domain expired and was released; create a new subscription"
    )


def test_cross_user_reclaim_requires_fresh_custom_domain_verification(app_client) -> None:
    client, factory = app_client
    owner = _signup(client)
    other = _signup(client)
    first = _subscribe(client, owner, "reclaim.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(
            resolver=FakeResolver([FakeCnameRecord(first["record_target"] + ".")]),
            lifetime=0.5,
        ),
    )
    verified = client.post(
        f"/api/v1/subscriptions/{first['id']}/verify-domain", headers=_auth(owner)
    )
    assert verified.json()["verified"] is True
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": first["id"], "method": "lightning"},
        headers=_auth(owner),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(owner))

    from blindport.config import settings
    from blindport.db import engine

    with Session(engine) as session:
        stored = subscription_by_public_id(session, first["id"])
        assert stored is not None
        stored.current_period_end = datetime.now(UTC) - timedelta(
            seconds=settings.RELAY_RENEWAL_GRACE_SECONDS + 1
        )
        session.add(stored)
        session.commit()

    reclaimed = _subscribe(client, other, "reclaim.example")
    assert reclaimed["id"] != first["id"]
    assert reclaimed["domain_is_managed"] is False
    assert reclaimed["domain_verified_at"] is None
    assert reclaimed["domain_challenge_value"] is None
    assert reclaimed["record_type"] == "CNAME"
    assert reclaimed["record_target"] != first["record_target"]
    blocked = client.post(
        "/api/v1/payments",
        json={"subscription_id": reclaimed["id"], "method": "lightning"},
        headers=_auth(other),
    )
    assert blocked.status_code == 400
    assert blocked.json()["detail"] == "CNAME target did not match"


def test_verified_domain_is_authorized_only_after_paid_activation(app_client) -> None:
    client, factory = app_client
    token = _signup(client)
    sub = _subscribe(client, token, "customer.example")

    from blindport.services.domain_verification import DnsPythonDomainVerifier

    _set_verifier(
        client,
        DnsPythonDomainVerifier(
            resolver=FakeResolver([FakeCnameRecord(sub["record_target"] + ".")]),
            lifetime=0.5,
        ),
    )
    verified = client.post(f"/api/v1/subscriptions/{sub['id']}/verify-domain", headers=_auth(token))
    assert verified.json()["verified"] is True

    def resolve() -> list[str]:
        response = client.post(
            "/internal/v1/resolve",
            json={"token": token},
            headers={"X-Relay-Secret": "test-secret"},
        )
        assert response.status_code == 200
        return response.json()["relay_domains"]

    assert resolve() == []
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": sub["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    assert resolve() == []
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    assert resolve() == ["customer.example"]
