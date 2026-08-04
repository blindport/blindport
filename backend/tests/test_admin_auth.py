"""Administrator bearer and browser-session separation regressions."""

from __future__ import annotations

from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_startup_does_not_create_admin_user_and_admin_is_not_a_customer(app_client) -> None:
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    with Session(engine) as session:
        assert session.exec(select(User).where(User.is_admin.is_(True))).all() == []  # type: ignore[union-attr]

    assert client.get("/api/v1/me", headers=_auth("TESTADMIN0000")).status_code == 401
    assert client.get("/api/v2/me", headers=_auth("TESTADMIN0000")).status_code == 401
    assert (
        client.post(
            "/api/v2/admin/users/00000000-0000-0000-0000-000000000000/suspend",
            headers=_auth("TESTADMIN0000"),
        ).status_code
        == 404
    )


def test_admin_api_uses_exact_configured_bearer_and_rejects_browser_session(
    app_client, monkeypatch
) -> None:
    from blindport.core import auth

    client, _ = app_client
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN", "Exact-Admin-I0")
    account = client.post("/api/v2/signup").json()

    for variant in ("exact-admin-i0", "Exact-Admin-I0 "):
        response = client.post(
            f"/api/v2/admin/users/{account['account_id']}/suspend",
            headers=_auth(variant),
        )
        assert response.status_code == 401

    browser_login = client.post("/login", data={"token": "Exact-Admin-I0"}, follow_redirects=False)
    assert browser_login.status_code == 303
    assert client.post(f"/api/v2/admin/users/{account['account_id']}/suspend").status_code == 401

    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN", "ROTATEDADMIN0000")
    assert (
        client.post(
            f"/api/v2/admin/users/{account['account_id']}/suspend",
            headers=_auth("Exact-Admin-I0"),
        ).status_code
        == 401
    )
    assert (
        client.post(
            f"/api/v2/admin/users/{account['account_id']}/suspend",
            headers=_auth("ROTATEDADMIN0000"),
        ).status_code
        == 200
    )


def test_legacy_admin_rows_have_no_customer_relay_or_admin_access(app_client) -> None:
    from blindport.core import tokens
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    legacy_token = "LEGACYADMIN0000"
    with Session(engine) as session:
        session.add(
            User(
                hashed_token=tokens.hash_token(tokens.crockford.normalize(legacy_token)),
                is_admin=True,
            )
        )
        session.commit()

    assert client.get("/api/v1/me", headers=_auth(legacy_token)).status_code == 401
    assert (
        client.post(
            "/internal/v1/resolve",
            json={"token": legacy_token},
            headers={"X-Relay-Secret": "test-secret"},
        ).status_code
        == 404
    )
    assert (
        client.post("/api/v1/admin/users/999/suspend", headers=_auth(legacy_token)).status_code
        == 401
    )


def test_regular_admin_login_classifies_before_redirect_and_never_reflects_secret(
    app_client, monkeypatch
) -> None:
    from blindport.api import pages

    client, _ = app_client
    looked_up: list[str] = []
    original_lookup = pages._get_user_by_token

    def tracking_lookup(session, token):
        looked_up.append(token)
        return original_lookup(session, token)

    monkeypatch.setattr(pages, "_get_user_by_token", tracking_lookup)
    client.cookies.set(
        "blindport_token",
        "stale-customer-token",
        domain="testserver.local",
        path="/",
    )
    response = client.post("/login", data={"token": "TESTADMIN0000"}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert looked_up == ["TESTADMIN0000"]
    assert "TESTADMIN0000" not in response.text
    assert "TESTADMIN0000" not in response.headers["set-cookie"]
    assert "blindport_admin_session=" in response.headers["set-cookie"]
    assert client.cookies.get("blindport_token") is None
    assert client.get("/admin").status_code == 200


def test_admin_browser_session_rejects_tamper_expiry_and_token_rotation(
    app_client, monkeypatch
) -> None:
    from blindport.core import auth

    client, _ = app_client
    client.post("/admin/login", data={"token": "TESTADMIN0000"})
    session_cookie = client.cookies.get("blindport_admin_session")
    assert session_cookie

    client.cookies.set("blindport_admin_session", f"{session_cookie}x", path="/admin")
    assert "Admin sign in" in client.get("/admin").text

    client.cookies.set("blindport_admin_session", session_cookie, path="/admin")
    monkeypatch.setattr(auth.settings, "ADMIN_SESSION_MAX_AGE_SECONDS", -1)
    assert "Admin sign in" in client.get("/admin").text

    monkeypatch.setattr(auth.settings, "ADMIN_SESSION_MAX_AGE_SECONDS", 900)
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN", "ROTATEDADMIN0000")
    assert "Admin sign in" in client.get("/admin").text


def test_upgrade_expires_legacy_raw_admin_cookie(app_client) -> None:
    client, _ = app_client
    client.cookies.set(
        "blindport_admin",
        "TESTADMIN0000",
        domain="testserver.local",
        path="/",
    )

    response = client.get("/admin")

    assert "Admin sign in" in response.text
    assert client.cookies.get("blindport_admin") is None
    assert "blindport_admin=" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]


def test_customer_login_clears_admin_session_and_sets_only_customer_access(app_client) -> None:
    client, _ = app_client
    account = client.post("/api/v2/signup").json()
    client.post("/admin/login", data={"token": "TESTADMIN0000"})

    response = client.post("/login", data={"token": account["token"]}, follow_redirects=False)

    assert response.status_code == 303
    assert response.headers["location"] == "/dashboard"
    assert client.cookies.get("blindport_token") == account["token"]
    assert client.cookies.get("blindport_admin_session") is None
    assert account["account_id"] in client.get("/dashboard").text
    assert "Admin sign in" in client.get("/admin").text


def test_invalid_browser_logins_are_generic_no_store_and_do_not_reflect_input(
    app_client,
) -> None:
    client, _ = app_client
    secret = "not-valid-and-do-not-reflect"

    for path in ("/login", "/admin/login"):
        response = client.post(path, data={"token": secret})
        assert response.status_code == 401
        assert response.headers["Cache-Control"] == "no-store"
        assert "Invalid credentials." in response.text
        assert secret not in response.text
        assert secret not in str(response.headers)


def test_admin_panel_hides_legacy_admin_rows_from_accounts_and_stats(app_client) -> None:
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    customer = client.post("/api/v2/signup").json()
    with Session(engine) as session:
        legacy = User(hashed_token="legacy-admin-panel-row", is_admin=True, is_suspended=True)
        session.add(legacy)
        session.commit()
        session.refresh(legacy)
        legacy_public_id = str(legacy.public_id)

    client.post("/admin/login", data={"token": "TESTADMIN0000"})
    panel = client.get("/admin")

    assert customer["account_id"] in panel.text
    assert legacy_public_id not in panel.text
    assert "<span>Accounts</span><strong>1</strong>" in panel.text


def test_admin_panel_can_suspend_and_restore_customer_accounts(app_client) -> None:
    client, _ = app_client
    account = client.post("/api/v2/signup").json()
    client.post("/admin/login", data={"token": "TESTADMIN0000"})

    panel = client.get("/admin")
    assert f'/admin/accounts/{account["account_id"]}/suspend' in panel.text

    suspended = client.post(
        f'/admin/accounts/{account["account_id"]}/suspend',
        follow_redirects=False,
    )
    assert suspended.status_code == 303
    assert suspended.headers["location"] == "/admin#accounts-title"
    assert client.get("/api/v2/me", headers=_auth(account["token"])).status_code == 403
    assert f'/admin/accounts/{account["account_id"]}/restore' in client.get("/admin").text

    restored = client.post(
        f'/admin/accounts/{account["account_id"]}/restore',
        follow_redirects=False,
    )
    assert restored.status_code == 303
    assert client.get("/api/v2/me", headers=_auth(account["token"])).status_code == 200


def test_admin_panel_mutation_requires_browser_session(app_client) -> None:
    client, _ = app_client
    account = client.post("/api/v2/signup").json()

    response = client.post(
        f'/admin/accounts/{account["account_id"]}/suspend',
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/admin"
    assert response.headers["Cache-Control"] == "no-store"
    assert client.get("/api/v2/me", headers=_auth(account["token"])).status_code == 200
