"""Focused tests for opaque browser sessions and dual authentication."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from sqlmodel import Session, select

from blindport.core.auth import current_user
from blindport.core.models import BrowserSession, User


def _request(host: str = "testserver") -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/",
            "headers": [(b"host", host.encode("ascii"))],
        }
    )


def _user(session: Session, suffix: str = "user") -> User:
    user = User(hashed_token=f"browser-session-{suffix}")
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def _issue(session: Session, user: User, now: datetime | None = None):
    from blindport.services.browser_sessions import issue_browser_session

    issued = issue_browser_session(session, user, "token", now)
    session.commit()
    return issued


def _authenticated_probe(client) -> str:
    path = "/_test-browser-session-auth"

    @client.app.api_route(path, methods=["GET", "POST"])
    def probe(user: User = Depends(current_user)) -> JSONResponse:
        return JSONResponse({"user_id": user.id})

    return path


def test_issuance_persists_only_domain_separated_hashes(app_client) -> None:
    from blindport.db import engine
    from blindport.services.browser_sessions import hash_browser_session_token

    del app_client
    with Session(engine) as session:
        user = _user(session)
        issued = _issue(session, user)
        record = session.get(BrowserSession, issued.model.id)

        assert record is not None
        assert record.token_hash == hash_browser_session_token(issued.session_token)
        assert len(record.token_hash) == 64
        assert len(record.csrf_token_hash) == 64
        assert issued.session_token not in vars(record).values()
        assert issued.csrf_token not in vars(record).values()


def test_cookie_flags_follow_development_production_and_onion_policy(
    app_client, monkeypatch
) -> None:
    from blindport.config import EnvironmentMode
    from blindport.services import browser_sessions

    del app_client
    issued = browser_sessions.IssuedBrowserSession(
        BrowserSession(
            user_id=1, token_hash="a" * 64, csrf_token_hash="b" * 64, auth_method="token"
        ),
        "session-token",
        "csrf-token",
    )

    development = JSONResponse({})
    browser_sessions.set_browser_session_cookies(development, _request(), issued)
    development_cookies = development.headers.getlist("set-cookie")
    assert any(
        "blindport_session=" in value and "HttpOnly" in value for value in development_cookies
    )
    assert any(
        "blindport_csrf=" in value and "HttpOnly" not in value for value in development_cookies
    )
    assert all("SameSite=strict" in value for value in development_cookies[:2])
    assert all("Secure" not in value for value in development_cookies)

    monkeypatch.setattr(browser_sessions.settings, "ENVIRONMENT", EnvironmentMode.PRODUCTION)
    production = JSONResponse({})
    browser_sessions.set_browser_session_cookies(production, _request("blindport.test"), issued)
    assert all("Secure" in value for value in production.headers.getlist("set-cookie"))

    monkeypatch.setattr(browser_sessions.settings, "ONION_HOST", "exampleonion.onion")
    onion = JSONResponse({})
    browser_sessions.set_browser_session_cookies(onion, _request("exampleonion.onion"), issued)
    assert all("Secure" not in value for value in onion.headers.getlist("set-cookie"))


def test_resolve_expiry_and_revocation(app_client) -> None:
    from blindport.db import engine
    from blindport.services.browser_sessions import (
        resolve_browser_session,
        revoke_browser_session,
    )

    del app_client
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(engine) as session:
        user = _user(session)
        issued = _issue(session, user, now)

        resolved = resolve_browser_session(
            session, issued.session_token, now + timedelta(minutes=1)
        )
        assert resolved is not None
        assert resolved[0].id == issued.model.id
        assert resolved[1].id == user.id

        issued_id = issued.model.id
        revoke_browser_session(session, issued.session_token)
        revoke_browser_session(session, issued.session_token)
        assert session.get(BrowserSession, issued_id) is None

        expired = _issue(session, user, now)
        expired_id = expired.model.id
        assert (
            resolve_browser_session(
                session,
                expired.session_token,
                now + timedelta(days=31),
            )
            is None
        )
        assert session.get(BrowserSession, expired_id) is None


def test_issuance_evicts_oldest_sessions_at_configured_limit(app_client, monkeypatch) -> None:
    from blindport.db import engine
    from blindport.services import browser_sessions

    del app_client
    monkeypatch.setattr(browser_sessions.settings, "BROWSER_SESSION_MAX_PER_USER", 2)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(engine) as session:
        user = _user(session)
        first = _issue(session, user, now)
        second = _issue(session, user, now + timedelta(seconds=1))
        third = _issue(session, user, now + timedelta(seconds=2))

        records = session.exec(
            select(BrowserSession)
            .where(BrowserSession.user_id == user.id)
            .order_by(BrowserSession.created_at)
        ).all()
        assert [record.id for record in records] == [second.model.id, third.model.id]
        assert session.get(BrowserSession, first.model.id) is None


def test_bearer_header_takes_precedence_over_browser_session(app_client) -> None:
    from blindport.db import engine

    client, _ = app_client
    with Session(engine) as session:
        issued = _issue(session, _user(session))
    client.cookies.set("blindport_session", issued.session_token)
    path = _authenticated_probe(client)

    response = client.get(path, headers={"Authorization": "not a bearer token"})

    assert response.status_code == 401


def test_current_user_accepts_session_on_safe_requests_and_requires_csrf_on_unsafe(
    app_client,
) -> None:
    from blindport.db import engine

    client, _ = app_client
    with Session(engine) as session:
        issued = _issue(session, _user(session))
    client.cookies.set(
        "blindport_session", issued.session_token, domain="testserver.local", path="/"
    )
    client.cookies.set("blindport_csrf", issued.csrf_token, domain="testserver.local", path="/")
    path = _authenticated_probe(client)

    assert client.get(path).status_code == 200
    assert client.post(path).status_code == 403
    assert client.post(path, headers={"X-CSRF-Token": issued.csrf_token}).status_code == 200


def test_agent_provisioning_requires_bearer_while_account_api_accepts_session(app_client) -> None:
    client, _ = app_client
    signup = client.post("/api/v1/signup")
    assert signup.status_code == 200
    token = signup.json()["token"]

    account = client.get("/api/v1/me")

    assert account.status_code == 200
    assert account.headers["cache-control"] == "no-store"
    assert account.headers["pragma"] == "no-cache"

    agent_requests = (
        ("put", "/api/v1/client/orders/test-order"),
        ("get", "/api/v1/client/version"),
        ("get", "/api/v1/client/config"),
        ("get", "/api/v1/client/cert"),
        ("post", "/api/v2/client/certificate"),
        ("get", "/api/v2/client/config"),
        ("get", "/api/v2/client/wireguard"),
        ("post", "/api/v2/client/wireguard/key"),
        ("get", "/api/v3/client/config"),
    )
    for method, path in agent_requests:
        response = client.request(method, path)
        assert response.status_code == 401, (path, response.text)

    bearer = client.get("/api/v1/client/version", headers={"Authorization": f"Bearer {token}"})

    assert bearer.status_code == 200


def test_suspended_browser_session_is_forbidden(app_client) -> None:
    from blindport.db import engine

    client, _ = app_client
    with Session(engine) as session:
        user = _user(session)
        issued = _issue(session, user)
        user.is_suspended = True
        session.add(user)
        session.commit()
    client.cookies.set("blindport_session", issued.session_token)
    path = _authenticated_probe(client)

    response = client.get(path)

    assert response.status_code == 403
    assert response.json()["detail"] == "account suspended"


def test_secret_key_rotation_invalidates_browser_sessions(app_client, monkeypatch) -> None:
    from blindport.db import engine
    from blindport.services import browser_sessions

    client, _ = app_client
    with Session(engine) as session:
        issued = _issue(session, _user(session))
    client.cookies.set("blindport_session", issued.session_token)
    monkeypatch.setattr(browser_sessions.settings, "SECRET_KEY", "rotated-secret")
    path = _authenticated_probe(client)

    response = client.get(path)

    assert response.status_code == 401


def test_login_form_uses_browser_bound_csrf_token(app_client) -> None:
    client, _ = app_client

    page = client.get("/dashboard")

    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.text.count('name="login_csrf_token"') == 2
    csrf_cookie = next(
        value
        for value in page.headers.get_list("set-cookie")
        if value.startswith("blindport_login_csrf=")
    )
    assert "HttpOnly" in csrf_cookie
    assert "SameSite=strict" in csrf_cookie
    assert "Max-Age=3600" in csrf_cookie

    missing = client.post("/login", data={"token": "attacker-controlled-token"})
    mismatched = client.post(
        "/login",
        data={"token": "attacker-controlled-token", "login_csrf_token": "wrong"},
    )

    assert missing.status_code == 403
    assert mismatched.status_code == 403
    assert missing.json() == mismatched.json() == {"detail": "login CSRF validation failed"}
    assert client.cookies.get("blindport_session") is None


def test_logout_requires_session_csrf_and_ignores_bearer_authority(app_client) -> None:
    from blindport.db import engine

    client, _ = app_client
    with Session(engine) as session:
        issued = _issue(session, _user(session, "logout"))
        issued_id = issued.model.id
    client.cookies.set(
        "blindport_session", issued.session_token, domain="testserver.local", path="/"
    )
    client.cookies.set("blindport_csrf", issued.csrf_token, domain="testserver.local", path="/")

    denied = client.delete(
        "/api/v1/browser-session",
        headers={"Authorization": "Bearer unrelated-or-invalid"},
    )

    assert denied.status_code == 403
    with Session(engine) as session:
        assert session.get(BrowserSession, issued_id) is not None

    deleted = client.delete(
        "/api/v1/browser-session",
        headers={
            "Authorization": "Bearer unrelated-or-invalid",
            "X-CSRF-Token": issued.csrf_token,
        },
    )

    assert deleted.status_code == 204
    assert client.cookies.get("blindport_session") is None
    with Session(engine) as session:
        assert session.get(BrowserSession, issued_id) is None


@pytest.mark.parametrize(
    ("path", "body", "expected_status"),
    [
        ("/api/v1/signup", None, 200),
        ("/api/v2/signup", None, 200),
        ("/api/v2/orders", {"product": "port"}, 201),
    ],
)
def test_account_creation_issues_opaque_session_without_bearer_cookie(
    app_client, path, body, expected_status
) -> None:
    client, _ = app_client

    response = client.post(path, json=body) if body is not None else client.post(path)

    assert response.status_code == expected_status, response.text
    assert response.json()["token"]
    assert client.cookies.get("blindport_session")
    assert client.cookies.get("blindport_csrf")
    assert client.cookies.get("blindport_token") is None
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    ("module_name", "path", "body"),
    [
        ("v1", "/api/v1/signup", None),
        ("v2", "/api/v2/signup", None),
        ("v2", "/api/v2/orders", {"product": "port"}),
    ],
)
def test_account_creation_rolls_back_when_session_issuance_fails(
    app_client, monkeypatch, module_name, path, body
) -> None:
    from blindport.api import v1, v2
    from blindport.core.models import Subscription
    from blindport.db import engine

    client, _ = app_client
    module = v1 if module_name == "v1" else v2

    def fail_session_issuance(*_args, **_kwargs):
        raise ValueError("injected browser session failure")

    monkeypatch.setattr(module, "issue_browser_session", fail_session_issuance)

    response = client.post(path, json=body) if body is not None else client.post(path)

    assert response.status_code == 400
    assert client.cookies.get("blindport_session") is None
    with Session(engine) as session:
        assert session.exec(select(User)).all() == []
        assert session.exec(select(Subscription)).all() == []
