"""Opaque browser-session issuance, resolution, and cookie handling."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe

from fastapi import Request, Response
from sqlalchemy import delete
from sqlmodel import Session, select

from ..config import settings
from ..core.models import BrowserSession, User

SESSION_COOKIE = "blindport_session"
CSRF_COOKIE = "blindport_csrf"
LEGACY_TOKEN_COOKIE = "blindport_token"
CEREMONY_BINDING_COOKIE = "blindport_ceremony_binding"
LOGIN_CSRF_COOKIE = "blindport_login_csrf"

_SESSION_HASH_DOMAIN = b"blindport-browser-session-v1\0"
_CSRF_HASH_DOMAIN = b"blindport-browser-csrf-v1\0"
_CEREMONY_BINDING_HASH_DOMAIN = b"blindport-webauthn-ceremony-binding-v1\0"
_LAST_SEEN_WRITE_INTERVAL = timedelta(minutes=5)
_LOGIN_CSRF_MAX_AGE_SECONDS = 3600


@dataclass(frozen=True, slots=True)
class IssuedBrowserSession:
    model: BrowserSession
    session_token: str
    csrf_token: str


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _now(value: datetime | None) -> datetime:
    return _utc(value) if value is not None else datetime.now(UTC)


def _ascii(value: str) -> bytes | None:
    try:
        return value.encode("ascii")
    except UnicodeEncodeError:
        return None


def _hash(value: str, domain: bytes) -> str:
    raw_value = _ascii(value)
    if raw_value is None:
        raise ValueError("browser session values must be ASCII")
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"), domain + raw_value, hashlib.sha256
    ).hexdigest()


def hash_browser_session_token(value: str) -> str:
    """Return the domain-separated lookup hash for an opaque session token."""
    return _hash(value, _SESSION_HASH_DOMAIN)


def hash_csrf_token(value: str) -> str:
    """Return the domain-separated persisted hash for a CSRF token."""
    return _hash(value, _CSRF_HASH_DOMAIN)


def hash_ceremony_binding(value: str) -> str:
    """Return the domain-separated lookup hash for WebAuthn ceremony bindings."""
    return _hash(value, _CEREMONY_BINDING_HASH_DOMAIN)


def generate_ceremony_binding() -> str:
    """Create an opaque value which binds one browser to a WebAuthn ceremony."""
    return token_urlsafe(32)


def generate_login_csrf_token() -> str:
    """Create a browser-bound token for the session-establishing login form."""
    return token_urlsafe(32)


def _constant_time_equal(left: str, right: str) -> bool:
    left_bytes = _ascii(left)
    right_bytes = _ascii(right)
    return (
        left_bytes is not None
        and right_bytes is not None
        and hmac.compare_digest(left_bytes, right_bytes)
    )


def _is_stale(value: datetime | None, now: datetime) -> bool:
    return value is None or _utc(value) <= now - _LAST_SEEN_WRITE_INTERVAL


def issue_browser_session(
    session: Session,
    user: User,
    auth_method: str,
    now: datetime | None = None,
) -> IssuedBrowserSession:
    """Create an uncommitted opaque session for an active customer account."""
    if auth_method not in {"token", "passkey"}:
        raise ValueError("auth_method must be token or passkey")
    if user.id is None:
        raise ValueError("user must be persisted")

    current_time = _now(now)
    locked_user = session.exec(
        select(User).where(User.id == user.id).with_for_update()
    ).one_or_none()
    if locked_user is None or locked_user.is_admin or locked_user.is_suspended:
        raise ValueError("user must be an active customer account")

    session.execute(
        delete(BrowserSession)
        .where(BrowserSession.user_id == locked_user.id, BrowserSession.expires_at <= current_time)
        .execution_options(synchronize_session=False)
    )
    existing = session.exec(
        select(BrowserSession)
        .where(BrowserSession.user_id == locked_user.id)
        .order_by(BrowserSession.created_at, BrowserSession.id)
    ).all()
    overflow = len(existing) - settings.BROWSER_SESSION_MAX_PER_USER + 1
    for existing_session in existing[: max(0, overflow)]:
        session.delete(existing_session)

    raw_session_token = token_urlsafe(32)
    raw_csrf_token = token_urlsafe(32)
    record = BrowserSession(
        user_id=locked_user.id,
        token_hash=hash_browser_session_token(raw_session_token),
        csrf_token_hash=hash_csrf_token(raw_csrf_token),
        auth_method=auth_method,
        created_at=current_time,
        expires_at=current_time + timedelta(seconds=settings.BROWSER_SESSION_MAX_AGE_SECONDS),
        last_seen_at=current_time,
    )
    session.add(record)
    session.flush()
    return IssuedBrowserSession(record, raw_session_token, raw_csrf_token)


def resolve_browser_session(
    session: Session, raw_token: str, now: datetime | None = None
) -> tuple[BrowserSession, User] | None:
    """Resolve an active session and update activity timestamps at most every five minutes."""
    if not raw_token:
        return None
    try:
        token_hash = hash_browser_session_token(raw_token)
    except ValueError:
        return None

    record = session.exec(
        select(BrowserSession).where(BrowserSession.token_hash == token_hash)
    ).first()
    if record is None or not _constant_time_equal(record.token_hash, token_hash):
        return None

    current_time = _now(now)
    if _utc(record.expires_at) <= current_time:
        session.delete(record)
        session.commit()
        return None

    user = session.get(User, record.user_id)
    if user is None or user.is_admin or user.is_suspended:
        return None

    changed = False
    if _is_stale(record.last_seen_at, current_time):
        record.last_seen_at = current_time
        changed = True
    if _is_stale(user.last_seen_at, current_time):
        user.last_seen_at = current_time
        changed = True
    if changed:
        session.commit()
        session.refresh(record)
        session.refresh(user)
    return record, user


def revoke_browser_session(session: Session, raw_token: str) -> None:
    """Delete a matching opaque session. This is intentionally idempotent."""
    if raw_token:
        try:
            token_hash = hash_browser_session_token(raw_token)
        except ValueError:
            token_hash = None
        if token_hash is not None:
            session.execute(
                delete(BrowserSession)
                .where(BrowserSession.token_hash == token_hash)
                .execution_options(synchronize_session=False)
            )
    session.commit()


def browser_cookie_secure(request: Request) -> bool:
    """Use Secure cookies in production except over the configured onion origin."""
    return settings.ENVIRONMENT.value == "production" and not (
        settings.ONION_HOST and request.url.hostname == settings.ONION_HOST
    )


def set_browser_session_cookies(
    response: Response, request: Request, issued: IssuedBrowserSession
) -> None:
    """Attach the session pair without changing the caller's transaction."""
    secure = browser_cookie_secure(request)
    cookie_options = {
        "max_age": settings.BROWSER_SESSION_MAX_AGE_SECONDS,
        "path": "/",
        "secure": secure,
        "samesite": "strict",
    }
    response.set_cookie(SESSION_COOKIE, issued.session_token, httponly=True, **cookie_options)
    response.set_cookie(CSRF_COOKIE, issued.csrf_token, httponly=False, **cookie_options)
    response.delete_cookie(LEGACY_TOKEN_COOKIE, path="/", secure=secure, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def clear_browser_session_cookies(response: Response, request: Request) -> None:
    """Expire browser authentication cookies without changing the caller's transaction."""
    secure = browser_cookie_secure(request)
    cookie_options = {"path": "/", "secure": secure, "samesite": "strict"}
    response.delete_cookie(SESSION_COOKIE, httponly=True, **cookie_options)
    response.delete_cookie(CSRF_COOKIE, httponly=False, **cookie_options)
    response.delete_cookie(LEGACY_TOKEN_COOKIE, path="/", secure=secure, samesite="lax")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def set_login_csrf_cookie(response: Response, request: Request, token: str) -> None:
    """Bind the server-rendered login form to the browser that requested it."""
    response.set_cookie(
        LOGIN_CSRF_COOKIE,
        token,
        max_age=_LOGIN_CSRF_MAX_AGE_SECONDS,
        path="/",
        secure=browser_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def clear_login_csrf_cookie(response: Response, request: Request) -> None:
    """Expire the login-form binding after successful authentication."""
    response.delete_cookie(
        LOGIN_CSRF_COOKIE,
        path="/",
        secure=browser_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )


def valid_login_csrf(cookie_value: str | None, form_value: str | None) -> bool:
    """Validate the login form's random double-submit token."""
    return bool(
        cookie_value
        and form_value
        and len(cookie_value) <= 128
        and len(form_value) <= 128
        and _constant_time_equal(cookie_value, form_value)
    )


def set_ceremony_binding_cookie(response: Response, request: Request, binding: str) -> None:
    """Attach a short-lived, HttpOnly binding cookie to a WebAuthn ceremony response."""
    response.set_cookie(
        CEREMONY_BINDING_COOKIE,
        binding,
        max_age=settings.PASSKEY_CHALLENGE_TTL_SECONDS,
        path="/api/v1/passkeys",
        secure=browser_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def clear_ceremony_binding_cookie(response: Response, request: Request) -> None:
    """Expire the WebAuthn ceremony binding cookie."""
    response.delete_cookie(
        CEREMONY_BINDING_COOKIE,
        path="/api/v1/passkeys",
        secure=browser_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def valid_csrf(
    session_record: BrowserSession, cookie_value: str | None, header_value: str | None
) -> bool:
    """Validate the double-submit token against the session's persisted CSRF hash."""
    if not cookie_value or not header_value or not _constant_time_equal(cookie_value, header_value):
        return False
    try:
        expected_hash = hash_csrf_token(cookie_value)
    except ValueError:
        return False
    return _constant_time_equal(session_record.csrf_token_hash, expected_hash)
