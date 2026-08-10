"""Focused tests for production catalog, account, and HTTP hardening."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from sqlmodel import Session

import blindport
from blindport.core.models import DeliveryMode, ProductType, Transport


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _signup(client) -> tuple[str, str]:
    response = client.post("/api/v2/signup")
    assert response.status_code == 200, response.text
    body = response.json()
    return body["account_id"], body["token"]


def _catalog_product(client, product: str) -> dict:
    response = client.get("/api/v1/catalog")
    assert response.status_code == 200, response.text
    return next(item for item in response.json()["products"] if item["product"] == product)


def _configure_wireguard(monkeypatch) -> None:
    from blindport.services import catalog, subscriptions

    for module in (catalog, subscriptions):
        monkeypatch.setattr(module.settings, "WIREGUARD_PUBLIC_IPS", "198.51.100.20")
        monkeypatch.setattr(module.settings, "WIREGUARD_RELAY_PUBLIC_KEY", "A" * 44)
        monkeypatch.setattr(module.settings, "WIREGUARD_ENDPOINT", "relay:51820")


def test_catalog_reports_transport_capacity_and_conservative_holds(app_client) -> None:
    client, _ = app_client
    _, token = _signup(client)
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "transport": "tcp"},
        headers=_auth(token),
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment.status_code == 200, payment.text

    product = _catalog_product(client, "port")
    assert product["capacity"]["tcp_available"] == 1
    assert product["capacity"]["udp_available"] == 2
    assert product["capacity"]["available"] == 3


def test_enabled_ip_can_be_sold_out_and_rejected_before_row_creation(
    app_client, monkeypatch
) -> None:
    from blindport.services import catalog, subscriptions

    client, _ = app_client
    monkeypatch.setattr(subscriptions.settings, "WIREGUARD_PUBLIC_IPS", "")
    monkeypatch.setattr(subscriptions.settings, "WIREGUARD_RELAY_PUBLIC_KEY", "A" * 44)
    monkeypatch.setattr(subscriptions.settings, "WIREGUARD_ENDPOINT", "relay:51820")
    monkeypatch.setattr(catalog.settings, "WIREGUARD_PUBLIC_IPS", "")
    product = _catalog_product(client, "ip")
    assert product["enabled"] is True
    assert product["sold_out"] is True
    assert product["capacity"]["available"] == 0

    _, token = _signup(client)
    response = client.post(
        "/api/v1/subscriptions",
        json={"product": "ip"},
        headers=_auth(token),
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "WireGuard Blindport IP delivery is not configured"
    assert client.get("/api/v1/subscriptions", headers=_auth(token)).json() == []


def test_catalog_rejects_framed_ip_delivery(app_client) -> None:
    from blindport.db import engine
    from blindport.services.catalog import ProductUnavailableError, require_product_available

    del app_client
    with (
        Session(engine) as session,
        pytest.raises(
            ProductUnavailableError,
            match="Blindport IP is available with WireGuard delivery only",
        ),
    ):
        require_product_available(
            session,
            ProductType.IP,
            delivery=DeliveryMode.FRAMED,
            transport=Transport.TCP,
            domain_is_managed=False,
        )


def test_sales_pause_and_managed_domain_cap_are_enforced(app_client, monkeypatch) -> None:
    from blindport.services import catalog as catalog_service

    _configure_wireguard(monkeypatch)
    client, _ = app_client
    _, token = _signup(client)
    monkeypatch.setattr(catalog_service.settings, "IP_SALES_PAUSED", True)
    paused = client.post("/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token))
    assert paused.status_code == 409
    assert paused.json()["detail"] == "ip sales are paused"

    monkeypatch.setattr(catalog_service.settings, "RELAY_MANAGED_DOMAIN_CAP", 1)
    first = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "one.relay.test"},
        headers=_auth(token),
    )
    assert first.status_code == 200, first.text
    relay = _catalog_product(client, "relay")
    assert relay["capacity"]["managed_domains_available"] == 0
    assert relay["capacity"]["customer_domains_available"] is True

    second = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "two.relay.test"},
        headers=_auth(token),
    )
    assert second.status_code == 409
    assert second.json()["detail"] == "no managed Blindport Relay domain capacity"


def test_durable_account_subscription_and_open_payment_caps(app_client, monkeypatch) -> None:
    from blindport.services import payments, subscriptions

    _configure_wireguard(monkeypatch)
    client, _ = app_client
    _, token = _signup(client)
    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS", 1)
    first = client.post("/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token))
    assert first.status_code == 200
    limited = client.post("/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token))
    assert limited.status_code == 429
    assert "non-cancelled subscription limit (1)" in limited.json()["detail"]

    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS", 3)
    monkeypatch.setattr(payments.settings, "ACCOUNT_MAX_OPEN_PAYMENTS", 1)
    first_payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": first.json()["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert first_payment.status_code == 200
    second_sub = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    payment_limited = client.post(
        "/api/v1/payments",
        json={"subscription_id": second_sub["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert payment_limited.status_code == 429
    assert "open payment/reservation limit (1)" in payment_limited.json()["detail"]


def test_unpaid_relay_claims_have_a_separate_per_account_cap(app_client, monkeypatch) -> None:
    from blindport.services import subscriptions

    client, _ = app_client
    _, token = _signup(client)
    monkeypatch.setattr(subscriptions.settings, "ACCOUNT_MAX_PENDING_RELAY_CLAIMS", 2)

    claims = []
    for domain in ("one.relay.test", "customer.example"):
        response = client.post(
            "/api/v1/subscriptions",
            json={"product": "relay", "domain": domain},
            headers=_auth(token),
        )
        assert response.status_code == 200, response.text
        claims.append(response.json())
    limited = client.post(
        "/api/v1/subscriptions",
        json={"product": "relay", "domain": "three.relay.test"},
        headers=_auth(token),
    )

    assert limited.status_code == 429
    assert limited.json()["detail"] == "account has reached the unpaid Relay claim limit (2)"
    managed_expiry = datetime.fromisoformat(claims[0]["domain_verification_expires_at"])
    customer_expiry = datetime.fromisoformat(claims[1]["domain_verification_expires_at"])
    assert 1790 <= (customer_expiry - managed_expiry).total_seconds() <= 1810


def test_suspension_revokes_normal_auth_and_relay_reauthorization(app_client, monkeypatch) -> None:
    _configure_wireguard(monkeypatch)
    client, factory = app_client
    account_id, token = _signup(client)
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token))
    relay_headers = {"X-Relay-Secret": "test-secret"}
    assert (
        client.post(
            "/internal/v1/resolve", json={"token": token}, headers=relay_headers
        ).status_code
        == 200
    )

    admin = _auth("TESTADMIN0000")
    suspended = client.post(f"/api/v2/admin/users/{account_id}/suspend", headers=admin)
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["account_id"] == account_id
    assert suspended.json()["is_suspended"] is True
    assert client.get("/api/v1/me", headers=_auth(token)).status_code == 403
    reauthorization = client.post(
        "/internal/v1/resolve", json={"token": token}, headers=relay_headers
    )
    assert reauthorization.status_code == 403

    restored = client.post(f"/api/v2/admin/users/{account_id}/unsuspend", headers=admin)
    assert restored.status_code == 200
    assert client.get("/api/v1/me", headers=_auth(token)).status_code == 200


def test_active_direct_lightning_subscription_can_renew_before_expiry(
    app_client, monkeypatch
) -> None:
    _configure_wireguard(monkeypatch)
    client, factory = app_client
    _, token = _signup(client)
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()
    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    first_end = datetime.fromisoformat(
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0][
            "current_period_end"
        ]
    )

    renewal = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    )
    assert renewal.status_code == 200, renewal.text
    factory.get_lightning_adapter().mark_paid(renewal.json()["payment_hash"])
    client.get(f"/api/v1/payments/{renewal.json()['id']}", headers=_auth(token))
    renewed_end = datetime.fromisoformat(
        client.get("/api/v1/me", headers=_auth(token)).json()["subscriptions"][0][
            "current_period_end"
        ]
    )
    assert renewed_end > first_end


def test_security_headers_and_production_admin_cookie(app_client, monkeypatch) -> None:
    from blindport.api import pages
    from blindport.config import EnvironmentMode

    client, _ = app_client
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in response.headers

    monkeypatch.setattr(pages.settings, "ENVIRONMENT", EnvironmentMode.PRODUCTION)
    login = client.post(
        "/admin/login",
        data={"token": "TESTADMIN0000"},
        follow_redirects=False,
    )
    cookie = login.headers["set-cookie"].lower()
    assert "secure" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "path=/admin" in cookie
    assert "max-age=900" in cookie
    assert "Strict-Transport-Security" in login.headers

    package = Path(blindport.__file__).parent
    source = (package / "static" / "account-storage.js").read_text(encoding="utf-8").lower()
    assert "localstorage" in source
    assert "document.cookie" not in source
    assert "blindport_token=" not in source


def test_production_customer_login_cookie_is_clearnet_secure_and_root_scoped(
    app_client, customer_login, monkeypatch
) -> None:
    from blindport.api import pages
    from blindport.config import EnvironmentMode
    from blindport.services import browser_sessions

    client, _ = app_client
    _, token = _signup(client)
    client.cookies.clear()
    monkeypatch.setattr(pages.settings, "ENVIRONMENT", EnvironmentMode.PRODUCTION)
    monkeypatch.setattr(browser_sessions.settings, "ENVIRONMENT", EnvironmentMode.PRODUCTION)

    response = customer_login(
        client,
        token,
        follow_redirects=False,
        origin="https://blindport.test",
    )
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(
        value.lower() for value in cookies if value.startswith("blindport_session=")
    )
    csrf_cookie = next(value.lower() for value in cookies if value.startswith("blindport_csrf="))

    assert response.status_code == 303
    assert "secure" in session_cookie
    assert "httponly" in session_cookie
    assert "path=/" in session_cookie
    assert "samesite=strict" in session_cookie
    assert "secure" in csrf_cookie
    assert "httponly" not in csrf_cookie
    assert "samesite=strict" in csrf_cookie
    assert any(value.startswith("blindport_token=") and "Max-Age=0" in value for value in cookies)
    assert any(
        value.startswith("blindport_admin_session=") and "Max-Age=0" in value for value in cookies
    )


def test_dashboard_renders_catalog_controls_and_external_scripts(app_client) -> None:
    client, _ = app_client
    _, token = _signup(client)
    client.cookies.clear()
    client.cookies.set("blindport_token", token, domain="testserver.local", path="/")

    response = client.get("/dashboard")

    assert response.status_code == 200, response.text
    assert "Dedicated public IP" in response.text
    assert "One public port" in response.text
    assert "Public hostname" in response.text
    assert client.cookies.get("blindport_token") is None
    assert client.cookies.get("blindport_session") is not None
    assert ">TCP</option>" in response.text
    assert "2 available" not in response.text
    assert 'data-token="' not in response.text
    assert token not in response.text
    assert "window.BLINDPORT_TOKEN" not in response.text
    assert '<script src="/static/dashboard.js"></script>' in response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_one_time_signup_token_response_is_not_cacheable(app_client) -> None:
    client, _ = app_client

    response = client.post("/api/v1/signup")

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_non_ascii_admin_token_is_rejected_without_server_error(app_client) -> None:
    client, _ = app_client

    response = client.post("/admin/login", data={"token": "not-the-token-\N{SNOWMAN}"})

    assert response.status_code == 401


def test_internal_authentication_uses_dedicated_relay_secret(app_client, monkeypatch) -> None:
    from blindport.api import internal

    client, _ = app_client
    monkeypatch.setattr(internal.settings, "RELAY_SECRET", "dedicated-relay-secret")
    old_secret = client.post(
        "/internal/v1/resolve",
        json={"token": "missing"},
        headers={"X-Relay-Secret": "test-secret"},
    )
    dedicated_secret = client.post(
        "/internal/v1/resolve",
        json={"token": "missing"},
        headers={"X-Relay-Secret": "dedicated-relay-secret"},
    )

    assert old_secret.status_code == 401
    assert dedicated_secret.status_code != 401
