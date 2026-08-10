"""Focused API tests for passkey enrollment and browser authentication."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _enable_passkeys(monkeypatch):
    from blindport.api import passkeys

    monkeypatch.setattr(passkeys.settings, "PASSKEYS_ENABLED", True)
    return passkeys


def _signup(client) -> tuple[str, int]:
    response = client.post("/api/v1/signup")
    assert response.status_code == 200
    body = response.json()
    return body["token"], body["user_id"]


def _registration_options(client, token: str) -> dict:
    response = client.post(
        "/api/v1/passkeys/registration/options",
        json={"name": "Laptop"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    return response.json()


def _authentication_options(client) -> dict:
    response = client.post("/api/v1/passkeys/authentication/options")
    assert response.status_code == 200
    return response.json()


def _credential(user_id: int, credential_id: bytes = b"credential-id"):
    from blindport.core.models import PasskeyCredential

    return PasskeyCredential(
        user_id=user_id,
        credential_id=credential_id,
        credential_public_key=b"public-key",
        sign_count=3,
        name="Laptop",
        transports_json='["internal"]',
        device_type="single_device",
    )


def test_passkeys_are_hidden_when_disabled_and_not_cacheable(app_client) -> None:
    client, _ = app_client

    response = client.post("/api/v1/passkeys/authentication/options")

    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


async def test_passkey_post_body_limit_rejects_chunked_request_without_content_length(
    app_client,
) -> None:
    client, _ = app_client
    from blindport.main import PASSKEY_POST_BODY_LIMIT

    request_messages = iter(
        (
            {"type": "http.request", "body": b"x" * PASSKEY_POST_BODY_LIMIT, "more_body": True},
            {"type": "http.request", "body": b"x", "more_body": False},
        )
    )
    response_messages = []

    async def receive():
        return next(request_messages)

    async def send(message) -> None:
        response_messages.append(message)

    await client.app(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/api/v1/passkeys/authentication",
            "raw_path": b"/api/v1/passkeys/authentication",
            "query_string": b"",
            "headers": [(b"host", b"testserver"), (b"content-type", b"application/json")],
            "client": ("127.0.0.1", 123),
            "server": ("testserver", 80),
        },
        receive,
        send,
    )

    start = next(
        message for message in response_messages if message["type"] == "http.response.start"
    )
    headers = {key.decode(): value.decode() for key, value in start["headers"]}
    body = b"".join(
        message.get("body", b"")
        for message in response_messages
        if message["type"] == "http.response.body"
    )

    assert start["status"] == 413
    assert headers["content-type"] == "application/json"
    assert headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert body == b'{"detail":"request body too large"}'


def test_passkeys_are_hidden_on_the_onion_origin(app_client, monkeypatch) -> None:
    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    onion_host = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
    monkeypatch.setattr(passkeys.settings, "ONION_HOST", onion_host)

    response = client.post(f"http://{onion_host}/api/v1/passkeys/authentication/options")

    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert response.headers["cache-control"] == "no-store"


def test_registration_options_require_discoverable_uv_and_persist_challenge(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import WebAuthnChallenge
    from blindport.db import engine

    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    monkeypatch.setattr(passkeys.settings, "PASSKEY_CHALLENGE_TTL_SECONDS", 123)
    token, user_id = _signup(client)

    response = client.post(
        "/api/v1/passkeys/registration/options",
        json={"name": "Laptop"},
        headers=_auth(token),
    )

    assert response.status_code == 200
    body = response.json()
    selection = body["options"]["authenticatorSelection"]
    assert selection == {
        "residentKey": "required",
        "requireResidentKey": True,
        "userVerification": "required",
    }
    assert body["options"]["timeout"] == 123_000
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    ceremony_cookie = next(
        value
        for value in response.headers.get_list("set-cookie")
        if value.startswith("blindport_ceremony_binding=")
    )
    assert "HttpOnly" in ceremony_cookie
    assert "Path=/api/v1/passkeys" in ceremony_cookie
    assert "SameSite=strict" in ceremony_cookie

    with Session(engine) as session:
        challenge = session.get(WebAuthnChallenge, body["challenge_id"])
        assert challenge is not None
        assert challenge.ceremony_type == "registration"
        assert challenge.user_id == user_id
        assert challenge.challenge
        assert challenge.expires_at.replace(tzinfo=UTC) > datetime.now(UTC)


def test_registration_persists_credential_consumes_challenge_and_rejects_replay(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import PasskeyCredential, WebAuthnChallenge
    from blindport.db import engine

    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    token, user_id = _signup(client)
    options = _registration_options(client, token)
    credential_id = b"registered-credential"
    monkeypatch.setattr(
        passkeys,
        "parse_registration_credential_json",
        lambda _: SimpleNamespace(response=SimpleNamespace(transports=["internal"])),
    )
    monkeypatch.setattr(
        passkeys,
        "verify_registration_response",
        lambda **_: SimpleNamespace(
            credential_id=credential_id,
            credential_public_key=b"public-key",
            sign_count=4,
            credential_device_type=SimpleNamespace(value="single_device"),
            credential_backed_up=False,
        ),
    )
    payload = {
        "challenge_id": options["challenge_id"],
        "credential": {"id": "mock"},
        "name": "Laptop",
    }

    registered = client.post("/api/v1/passkeys/registration", json=payload, headers=_auth(token))

    assert registered.status_code == 200
    assert registered.json()["passkey"]["name"] == "Laptop"
    assert registered.headers["cache-control"] == "no-store"
    with Session(engine) as session:
        stored = session.exec(
            select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
        ).one()
        assert stored.credential_id == credential_id
        assert stored.sign_count == 4
        assert session.get(WebAuthnChallenge, options["challenge_id"]) is None

    replay = client.post("/api/v1/passkeys/registration", json=payload, headers=_auth(token))

    assert replay.status_code == 400
    assert replay.json() == {"detail": "passkey verification failed"}
    assert replay.headers["cache-control"] == "no-store"


def test_wrong_registration_binding_preserves_rightful_challenge(app_client, monkeypatch) -> None:
    from blindport.core.models import WebAuthnChallenge
    from blindport.db import engine

    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    token, _ = _signup(client)
    options = _registration_options(client, token)
    monkeypatch.setattr(
        passkeys,
        "parse_registration_credential_json",
        lambda _: SimpleNamespace(response=SimpleNamespace(transports=[])),
    )
    monkeypatch.setattr(
        passkeys,
        "verify_registration_response",
        lambda **_: SimpleNamespace(
            credential_id=b"bound-credential",
            credential_public_key=b"public-key",
            sign_count=0,
            credential_device_type=SimpleNamespace(value="single_device"),
            credential_backed_up=False,
        ),
    )
    payload = {
        "challenge_id": options["challenge_id"],
        "credential": {"id": "mock"},
        "name": "Laptop",
    }

    wrong_binding = client.post(
        "/api/v1/passkeys/registration",
        json=payload,
        headers={**_auth(token), "Cookie": "blindport_ceremony_binding=wrong"},
    )

    assert wrong_binding.status_code == 400
    assert wrong_binding.json() == {"detail": "passkey verification failed"}
    with Session(engine) as session:
        assert session.get(WebAuthnChallenge, options["challenge_id"]) is not None

    rightful = client.post("/api/v1/passkeys/registration", json=payload, headers=_auth(token))

    assert rightful.status_code == 200
    with Session(engine) as session:
        assert session.get(WebAuthnChallenge, options["challenge_id"]) is None


def test_discoverable_authentication_validates_handle_updates_credential_and_issues_session(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import BrowserSession, PasskeyCredential, User, WebAuthnChallenge
    from blindport.db import engine

    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    _, user_id = _signup(client)
    with Session(engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        public_id = user.public_id
        session.add(_credential(user_id))
        session.commit()
    options = _authentication_options(client)
    monkeypatch.setattr(
        passkeys,
        "parse_authentication_credential_json",
        lambda _: SimpleNamespace(
            raw_id=b"credential-id", response=SimpleNamespace(user_handle=public_id.bytes)
        ),
    )
    monkeypatch.setattr(
        passkeys,
        "verify_authentication_response",
        lambda **_: SimpleNamespace(
            new_sign_count=9,
            credential_device_type=SimpleNamespace(value="multi_device"),
            credential_backed_up=True,
        ),
    )

    authenticated = client.post(
        "/api/v1/passkeys/authentication",
        json={"challenge_id": options["challenge_id"], "credential": {"id": "mock"}},
    )

    assert authenticated.status_code == 200
    assert authenticated.json() == {"account_id": str(public_id)}
    assert "token" not in authenticated.json()
    session_cookie = next(
        value
        for value in authenticated.headers.get_list("set-cookie")
        if value.startswith("blindport_session=")
    )
    assert "HttpOnly" in session_cookie
    assert "SameSite=strict" in session_cookie
    assert not any(
        value.startswith("blindport_token=") and "Max-Age=0" not in value
        for value in authenticated.headers.get_list("set-cookie")
    )
    with Session(engine) as session:
        stored = session.exec(select(PasskeyCredential)).one()
        assert stored.sign_count == 9
        assert stored.device_type == "multi_device"
        assert stored.backed_up is True
        assert stored.last_used_at is not None
        issued = session.exec(
            select(BrowserSession).where(BrowserSession.auth_method == "passkey")
        ).one()
        assert issued.user_id == user_id
        assert session.get(WebAuthnChallenge, options["challenge_id"]) is None


def test_authentication_rejects_wrong_handle_and_suspended_user(app_client, monkeypatch) -> None:
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    _, user_id = _signup(client)
    with Session(engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        session.add(_credential(user_id))
        session.commit()
    monkeypatch.setattr(
        passkeys,
        "parse_authentication_credential_json",
        lambda _: SimpleNamespace(
            raw_id=b"credential-id", response=SimpleNamespace(user_handle=b"wrong-user-handle")
        ),
    )

    wrong_handle_options = _authentication_options(client)
    wrong_handle = client.post(
        "/api/v1/passkeys/authentication",
        json={"challenge_id": wrong_handle_options["challenge_id"], "credential": {"id": "mock"}},
    )

    assert wrong_handle.status_code == 401
    assert wrong_handle.json() == {"detail": "passkey verification failed"}
    with Session(engine) as session:
        user = session.get(User, user_id)
        assert user is not None
        user.is_suspended = True
        session.add(user)
        session.commit()

    suspended_options = _authentication_options(client)
    suspended = client.post(
        "/api/v1/passkeys/authentication",
        json={"challenge_id": suspended_options["challenge_id"], "credential": {"id": "mock"}},
    )

    assert suspended.status_code == 401
    assert suspended.json() == {"detail": "passkey verification failed"}


def test_authentication_challenge_replay_and_expiry_are_rejected(app_client, monkeypatch) -> None:
    from blindport.core.models import WebAuthnChallenge
    from blindport.db import engine

    client, _ = app_client
    _enable_passkeys(monkeypatch)
    replay_options = _authentication_options(client)
    payload = {"challenge_id": replay_options["challenge_id"], "credential": {"id": "unknown"}}

    first = client.post("/api/v1/passkeys/authentication", json=payload)
    replay = client.post("/api/v1/passkeys/authentication", json=payload)

    assert first.status_code == replay.status_code == 401
    assert first.json() == replay.json() == {"detail": "passkey verification failed"}
    expired_options = _authentication_options(client)
    with Session(engine) as session:
        challenge = session.get(WebAuthnChallenge, expired_options["challenge_id"])
        assert challenge is not None
        challenge.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(challenge)
        session.commit()

    expired = client.post(
        "/api/v1/passkeys/authentication",
        json={"challenge_id": expired_options["challenge_id"], "credential": {"id": "unknown"}},
    )

    assert expired.status_code == 401
    assert expired.json() == {"detail": "passkey verification failed"}


def test_pending_challenge_capacity_is_bounded(app_client, monkeypatch) -> None:
    client, _ = app_client
    passkeys = _enable_passkeys(monkeypatch)
    monkeypatch.setattr(passkeys.settings, "PASSKEY_MAX_PENDING_CHALLENGES", 1)

    first = client.post("/api/v1/passkeys/authentication/options")
    limited = client.post("/api/v1/passkeys/authentication/options")

    assert first.status_code == 200
    assert limited.status_code == 429
    assert limited.json() == {"detail": "too many pending passkey requests"}
    assert limited.headers["cache-control"] == "no-store"


def test_passkey_list_and_delete_enforce_ownership_and_browser_csrf(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import PasskeyCredential, User
    from blindport.db import engine
    from blindport.services.browser_sessions import issue_browser_session

    client, _ = app_client
    _enable_passkeys(monkeypatch)
    owner_token, owner_id = _signup(client)
    _, other_id = _signup(client)
    with Session(engine) as session:
        owner = _credential(owner_id, b"owner-credential")
        other = _credential(other_id, b"other-credential")
        session.add_all([owner, other])
        session.commit()
        session.refresh(owner)
        owner_identifier = owner.credential_id
        other_identifier = other.credential_id
        owner_user = session.get(User, owner_id)
        assert owner_user is not None
        issued = issue_browser_session(session, owner_user, "token")
        session.commit()

    listed = client.get("/api/v1/passkeys", headers=_auth(owner_token))

    assert listed.status_code == 200
    assert [item["name"] for item in listed.json()] == ["Laptop"]
    assert listed.headers["cache-control"] == "no-store"
    other_id_encoded = base64.urlsafe_b64encode(other_identifier).rstrip(b"=").decode()
    denied = client.delete(f"/api/v1/passkeys/{other_id_encoded}", headers=_auth(owner_token))
    assert denied.status_code == 404
    assert denied.json() == {"detail": "passkey not found"}

    client.cookies.set(
        "blindport_session", issued.session_token, domain="testserver.local", path="/"
    )
    client.cookies.set("blindport_csrf", issued.csrf_token, domain="testserver.local", path="/")
    owner_id_encoded = base64.urlsafe_b64encode(owner_identifier).rstrip(b"=").decode()
    csrf_denied = client.delete(f"/api/v1/passkeys/{owner_id_encoded}")
    assert csrf_denied.status_code == 403
    assert csrf_denied.json() == {"detail": "CSRF validation failed"}

    deleted = client.delete(
        f"/api/v1/passkeys/{owner_id_encoded}", headers={"X-CSRF-Token": issued.csrf_token}
    )
    assert deleted.status_code == 204
    assert deleted.headers["cache-control"] == "no-store"
    with Session(engine) as session:
        assert (
            session.exec(
                select(PasskeyCredential).where(PasskeyCredential.user_id == owner_id)
            ).all()
            == []
        )
