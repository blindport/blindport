"""Authentication: bearer-token dependency for FastAPI."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, Request, status
from itsdangerous import BadData, URLSafeTimedSerializer
from sqlalchemy import or_, update
from sqlmodel import Session, select

from ..config import settings
from ..db import get_session
from ..services.browser_sessions import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    hash_browser_session_token,
    resolve_browser_session,
    valid_csrf,
)
from . import tokens
from .models import BrowserSession, User

_LAST_SEEN_WRITE_INTERVAL = timedelta(minutes=5)
_ADMIN_BROWSER_AUDIENCE = "blindport-admin-browser-v1"
_ADMIN_BROWSER_SALT = "blindport-admin-browser-session"


@dataclass(frozen=True, slots=True)
class AdminPrincipal:
    """Dedicated principal for the configured API administrator."""

    audience: str = "blindport-admin-api-v1"


def _extract_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing Authorization header")
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid Authorization header")
    return parts[1]


def _touch_last_seen(session: Session, user: User, now: datetime) -> bool:
    result = session.execute(
        update(User)
        .where(
            User.id == user.id,
            or_(
                User.last_seen_at.is_(None),  # type: ignore[union-attr]
                User.last_seen_at <= now - _LAST_SEEN_WRITE_INTERVAL,  # type: ignore[operator]
            ),
        )
        .values(last_seen_at=now)
        .execution_options(synchronize_session=False)
    )
    session.commit()
    session.refresh(user)
    return result.rowcount == 1


def _current_bearer_user(authorization: str | None, session: Session) -> User:
    """Resolve an active non-admin customer from a bearer credential."""
    provided = _extract_token(authorization)
    try:
        normalized = tokens.crockford.normalize(provided)
    except Exception as error:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token") from error
    hashed = tokens.hash_token(normalized)
    user = session.exec(
        select(User).where(User.hashed_token == hashed, User.is_admin.is_(False))  # type: ignore[union-attr]
    ).first()
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account suspended")
    # Daemons poll authenticated endpoints frequently. Keep activity useful
    # without turning every poll into a database write.
    now = datetime.now(UTC)
    last_seen = user.last_seen_at
    normalized_last_seen = (
        last_seen.replace(tzinfo=UTC)
        if last_seen is not None and last_seen.tzinfo is None
        else last_seen
    )
    if normalized_last_seen is None or normalized_last_seen <= now - _LAST_SEEN_WRITE_INTERVAL:
        _touch_last_seen(session, user, now)
    return user


def current_bearer_user(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> User:
    """Resolve a customer exclusively from an Authorization bearer token."""
    user = _current_bearer_user(authorization, session)
    session.expunge(user)
    return user


def current_user(
    request: Request,
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> User:
    """Resolve the current user from bearer or browser-session authentication.

    The returned User is detached from the lookup session so callers can safely
    attach it to their own session via `session.merge(...)`.
    """
    if authorization is not None:
        user = _current_bearer_user(authorization, session)
    else:
        resolved = optional_browser_session(request, session)
        if resolved is None:
            _raise_browser_session_auth_error(session, request.cookies.get(SESSION_COOKIE, ""))
        browser_session, user = resolved
        if request.method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and not valid_csrf(
            browser_session,
            request.cookies.get(CSRF_COOKIE),
            request.headers.get("X-CSRF-Token"),
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF validation failed")
    session.expunge(user)
    return user


def optional_browser_session(
    request: Request, session: Session
) -> tuple[BrowserSession, User] | None:
    """Resolve an active browser session for server-rendered pages without raising."""
    return resolve_browser_session(session, request.cookies.get(SESSION_COOKIE, ""))


def _raise_browser_session_auth_error(session: Session, raw_token: str) -> None:
    """Preserve the established suspended-account response for browser sessions."""
    try:
        token_hash = hash_browser_session_token(raw_token) if raw_token else None
    except ValueError:
        token_hash = None
    if token_hash is not None:
        browser_session = session.exec(
            select(BrowserSession).where(BrowserSession.token_hash == token_hash)
        ).first()
        if browser_session is not None:
            user = session.get(User, browser_session.user_id)
            if user is not None and not user.is_admin and user.is_suspended:
                raise HTTPException(status.HTTP_403_FORBIDDEN, "account suspended")
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")


def current_admin(authorization: str | None = Header(default=None)) -> AdminPrincipal:
    """Authenticate the configured admin bearer without consulting customer rows."""
    provided = _extract_token(authorization)
    if not is_exact_admin_token(provided):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
    return AdminPrincipal()


def is_exact_admin_token(provided: str) -> bool:
    """Compare an unmodified token to the configured administrator credential."""
    return hmac.compare_digest(provided.encode("utf-8"), settings.ADMIN_TOKEN.encode("utf-8"))


def is_admin_token(authorization: str | None) -> bool:
    """Constant-string check for the configured admin token."""
    if not authorization:
        return False
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return is_exact_admin_token(parts[1])


def _admin_token_fingerprint() -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        f"{_ADMIN_BROWSER_AUDIENCE}\0{settings.ADMIN_TOKEN}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _admin_session_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(
        settings.SECRET_KEY,
        salt=_ADMIN_BROWSER_SALT,
        signer_kwargs={"digest_method": hashlib.sha256},
    )


def create_admin_browser_session() -> str:
    """Issue a signed browser-only session containing no administrator secret."""
    return _admin_session_serializer().dumps(
        {"aud": _ADMIN_BROWSER_AUDIENCE, "fingerprint": _admin_token_fingerprint()}
    )


def validate_admin_browser_session(value: str) -> bool:
    if not value:
        return False
    try:
        payload = _admin_session_serializer().loads(
            value,
            max_age=settings.ADMIN_SESSION_MAX_AGE_SECONDS,
        )
    except BadData:
        return False
    if not isinstance(payload, dict) or payload.get("aud") != _ADMIN_BROWSER_AUDIENCE:
        return False
    fingerprint = payload.get("fingerprint")
    if not isinstance(fingerprint, str):
        return False
    try:
        provided_fingerprint = fingerprint.encode("ascii")
    except UnicodeEncodeError:
        return False
    return hmac.compare_digest(
        provided_fingerprint,
        _admin_token_fingerprint().encode("ascii"),
    )
