"""Transient direct-client and durable account rate-limit tests."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier
from uuid import uuid4

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signup(client) -> tuple[str, str]:
    response = client.post("/api/v2/signup")
    assert response.status_code == 200, response.text
    return response.json()["account_id"], response.json()["token"]


def _csr() -> str:
    key = Ed25519PrivateKey.generate()
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rate-limit-test")]))
        .sign(key, None)
    )
    return request.public_bytes(serialization.Encoding.PEM).decode("ascii")


def test_signup_uses_transient_trusted_client_limit(app_client, monkeypatch) -> None:
    from blindport.core.models import RateLimitBucket
    from blindport.db import engine
    from blindport.services import rate_limits

    client, _ = app_client
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_SIGNUP_REQUESTS", 1)
    first = client.post("/api/v1/signup", headers={"X-Forwarded-For": "198.51.100.1"})
    limited = client.post("/api/v1/signup", headers={"X-Forwarded-For": "203.0.113.2"})

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["detail"] == "request rate limit exceeded"
    assert int(limited.headers["Retry-After"]) >= 1
    with Session(engine) as session:
        buckets = session.exec(
            select(RateLimitBucket).where(RateLimitBucket.scope == "signup")
        ).all()
    assert buckets == []


def test_admin_login_is_direct_client_limited(app_client, monkeypatch) -> None:
    from blindport.services import rate_limits

    client, _ = app_client
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_ADMIN_LOGIN_REQUESTS", 1)
    rejected = client.post("/admin/login", data={"token": "wrong"})
    limited = client.post("/admin/login", data={"token": "wrong-again"})

    assert rejected.status_code == 401
    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) >= 1


def test_regular_browser_login_has_a_separate_transient_limit(
    app_client, customer_login, monkeypatch
) -> None:
    from blindport.core.models import RateLimitBucket
    from blindport.db import engine
    from blindport.services import rate_limits

    client, _ = app_client
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_BROWSER_LOGIN_REQUESTS", 1)
    rejected = customer_login(client, "wrong")
    limited = customer_login(client, "wrong-again")

    assert rejected.status_code == 401
    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "no-store"
    with Session(engine) as session:
        assert (
            session.exec(
                select(RateLimitBucket).where(RateLimitBucket.scope == "browser-login")
            ).all()
            == []
        )


def test_direct_client_bucket_expires_without_persistent_cleanup() -> None:
    from blindport.services.rate_limits import DirectRateLimiter, RateLimitScope, RateLimitSpec

    limiter = DirectRateLimiter(max_buckets=1)
    spec = RateLimitSpec(RateLimitScope.SIGNUP, requests=1, window_seconds=60)
    start = datetime(2030, 1, 1, tzinfo=UTC)

    limiter.consume(spec, "client:198.51.100.1", now=start)
    limiter.consume(spec, "client:203.0.113.2", now=start + timedelta(seconds=60))


def test_direct_client_limit_is_atomic_across_threads() -> None:
    from blindport.services.rate_limits import (
        DirectRateLimiter,
        RateLimitExceeded,
        RateLimitScope,
        RateLimitSpec,
    )

    limiter = DirectRateLimiter(max_buckets=10)
    spec = RateLimitSpec(RateLimitScope.SIGNUP, requests=7, window_seconds=60)
    start = datetime(2030, 1, 1, tzinfo=UTC)
    barrier = Barrier(20)

    def consume() -> bool:
        barrier.wait(timeout=5)
        try:
            limiter.consume(spec, "client:198.51.100.1", now=start)
        except RateLimitExceeded:
            return False
        return True

    with ThreadPoolExecutor(max_workers=20) as executor:
        allowed = list(executor.map(lambda _: consume(), range(20)))

    assert sum(allowed) == 7


def test_payment_retries_work_and_accounts_do_not_share_quota(app_client, monkeypatch) -> None:
    from blindport.services import rate_limits

    client, _ = app_client
    _, first_token = _signup(client)
    _, second_token = _signup(client)
    first_sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(first_token),
    ).json()
    second_sub = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers=_auth(second_token),
    ).json()
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_PAYMENT_CREATE_REQUESTS", 2)

    first = client.post(
        "/api/v1/payments",
        json={"subscription_id": first_sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    retry = client.post(
        "/api/v1/payments",
        json={"subscription_id": first_sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    limited = client.post(
        "/api/v1/payments",
        json={"subscription_id": first_sub["id"], "method": "lightning"},
        headers=_auth(first_token),
    )
    other_account = client.post(
        "/api/v1/payments",
        json={"subscription_id": second_sub["id"], "method": "lightning"},
        headers=_auth(second_token),
    )

    assert first.status_code == retry.status_code == 200
    assert first.json()["id"] == retry.json()["id"]
    assert limited.status_code == 429
    assert other_account.status_code == 200, other_account.text


def test_domain_verification_and_client_enrollment_have_independent_scopes(
    app_client, monkeypatch
) -> None:
    from blindport.services import rate_limits

    client, _ = app_client
    _, token = _signup(client)
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_DOMAIN_VERIFY_REQUESTS", 1)
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_CLIENT_CERT_REQUESTS", 1)

    unknown_subscription_id = str(uuid4())
    first_verify = client.post(
        f"/api/v1/subscriptions/{unknown_subscription_id}/verify-domain", headers=_auth(token)
    )
    limited_verify = client.post(
        f"/api/v1/subscriptions/{unknown_subscription_id}/verify-domain", headers=_auth(token)
    )
    enrollment_body = {
        "instance_id": str(uuid4()),
        "generation": 1,
        "csr_pem": _csr(),
    }
    first_enrollment = client.post(
        "/api/v2/client/certificate",
        json=enrollment_body,
        headers=_auth(token),
    )
    limited_enrollment = client.post(
        "/api/v2/client/certificate",
        json=enrollment_body,
        headers=_auth(token),
    )

    assert first_verify.status_code == 404
    assert limited_verify.status_code == 429
    assert first_enrollment.status_code == 200, first_enrollment.text
    assert limited_enrollment.status_code == 429
    assert limited_enrollment.headers["Cache-Control"] == "no-store"


def test_sqlite_fixed_window_increment_is_atomic(app_client) -> None:
    from blindport.core.models import RateLimitBucket
    from blindport.db import engine
    from blindport.services.rate_limits import (
        RateLimitExceeded,
        RateLimitScope,
        RateLimitSpec,
        enforce_rate_limit,
        hash_identifier,
    )

    client, _ = app_client
    assert client.get("/api/v1/health/live").status_code == 200
    identifier = f"account:{uuid4()}"
    spec = RateLimitSpec(RateLimitScope.PAYMENT_CREATE, requests=5, window_seconds=60)
    now = datetime(2030, 1, 1, tzinfo=UTC)

    def consume() -> bool:
        with Session(engine) as session:
            try:
                enforce_rate_limit(session, spec, identifier, now=now)
            except RateLimitExceeded:
                return False
        return True

    with ThreadPoolExecutor(max_workers=8) as executor:
        allowed = list(executor.map(lambda _: consume(), range(20)))

    assert sum(allowed) == 5
    with Session(engine) as session:
        bucket = session.exec(
            select(RateLimitBucket).where(
                RateLimitBucket.scope == spec.scope.value,
                RateLimitBucket.identifier_hash == hash_identifier(spec.scope, identifier),
            )
        ).one()
    assert bucket.request_count == 20


def test_cleanup_lease_deletes_only_one_bounded_stale_batch(app_client, monkeypatch) -> None:
    from blindport.core.models import RateLimitBucket, RateLimitMaintenance
    from blindport.db import engine
    from blindport.services import rate_limits

    client, _ = app_client
    assert client.get("/api/v1/health/live").status_code == 200
    now = datetime(2031, 1, 1, tzinfo=UTC)
    stale = now - timedelta(days=1)
    with Session(engine) as session:
        session.add(
            RateLimitMaintenance(
                name="rate-limit-buckets",
                next_cleanup_at=stale,
                bucket_count=5,
            )
        )
        for index in range(5):
            session.add(
                RateLimitBucket(
                    scope="signup",
                    identifier_hash=f"{index:064x}",
                    window_start=stale,
                    request_count=1,
                    expires_at=stale,
                )
            )
        session.commit()
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_CLEANUP_BATCH_SIZE", 2)
    spec = rate_limits.RateLimitSpec(rate_limits.RateLimitScope.PAYMENT_CREATE, 10, 60)
    with Session(engine) as session:
        rate_limits.enforce_rate_limit(session, spec, "account:cleanup", now=now)
    with Session(engine) as session:
        rate_limits.enforce_rate_limit(session, spec, "account:cleanup-second", now=now)

    with Session(engine) as session:
        stale_rows = session.exec(
            select(RateLimitBucket).where(RateLimitBucket.expires_at <= now)  # type: ignore[operator]
        ).all()
        maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
    assert len(stale_rows) == 3
    assert maintenance is not None
    assert maintenance.next_cleanup_at.replace(tzinfo=UTC) > now
    assert maintenance.bucket_count == 5


def test_bucket_cardinality_cap_fails_closed_without_evicting_active_quota(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import RateLimitBucket, RateLimitMaintenance
    from blindport.db import engine
    from blindport.services import rate_limits

    client, _ = app_client
    assert client.get("/api/v1/health/live").status_code == 200
    now = datetime(2032, 1, 1, tzinfo=UTC)
    future = now + timedelta(hours=1)
    with Session(engine) as session:
        session.add(
            RateLimitMaintenance(
                name="rate-limit-buckets",
                next_cleanup_at=future,
                bucket_count=2,
            )
        )
        for index in range(2):
            session.add(
                RateLimitBucket(
                    scope="signup",
                    identifier_hash=f"{index:064x}",
                    window_start=now,
                    request_count=1,
                    expires_at=future,
                )
            )
        session.commit()
    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_MAX_BUCKETS", 2)
    spec = rate_limits.RateLimitSpec(rate_limits.RateLimitScope.PAYMENT_CREATE, 10, 60)
    with Session(engine) as session:
        try:
            rate_limits.enforce_rate_limit(session, spec, "account:over-cap", now=now)
        except rate_limits.RateLimitExceeded as error:
            assert error.retry_after == rate_limits.settings.RATE_LIMIT_CLEANUP_INTERVAL_SECONDS
        else:  # pragma: no cover - keeps the failure message focused
            raise AssertionError("cardinality cap admitted a new bucket")

    with Session(engine) as session:
        rows = session.exec(select(RateLimitBucket)).all()
        maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
    assert len(rows) == 2
    assert maintenance is not None and maintenance.bucket_count == 2


def test_health_and_internal_relay_endpoints_are_not_rate_limited(app_client, monkeypatch) -> None:
    from blindport.services import rate_limits

    client, _ = app_client
    for setting_name in (
        "RATE_LIMIT_SIGNUP_REQUESTS",
        "RATE_LIMIT_ADMIN_LOGIN_REQUESTS",
        "RATE_LIMIT_PAYMENT_CREATE_REQUESTS",
        "RATE_LIMIT_DOMAIN_VERIFY_REQUESTS",
        "RATE_LIMIT_CLIENT_CERT_REQUESTS",
    ):
        monkeypatch.setattr(rate_limits.settings, setting_name, 1)

    assert client.get("/api/v1/health/live").status_code == 200
    assert client.get("/api/v1/health/live").status_code == 200
    first = client.post("/internal/v1/resolve", json={"token": "missing"})
    second = client.post("/internal/v1/resolve", json={"token": "missing"})
    assert first.status_code == second.status_code == 401
    assert "Retry-After" not in second.headers
