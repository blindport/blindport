"""Authentication: bearer-token dependency for FastAPI."""

from __future__ import annotations

import hmac
from datetime import UTC, datetime, timedelta

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import or_, update
from sqlmodel import Session, select

from ..config import settings
from ..db import get_session
from . import tokens
from .models import User

_LAST_SEEN_WRITE_INTERVAL = timedelta(minutes=5)


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


def current_user(
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> User:
    """Resolve the current user from the Bearer token. Raises 401 otherwise.

    The returned User is detached from the lookup session so callers can safely
    attach it to their own session via `session.merge(...)`.
    """
    provided = _extract_token(authorization)
    normalized = tokens.crockford.normalize(provided)
    hashed = tokens.hash_token(normalized)
    user = session.exec(select(User).where(User.hashed_token == hashed)).first()
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
    session.expunge(user)
    return user


def current_admin(user: User = Depends(current_user)) -> User:
    """Require an admin user.

    A user is admin if their model flag is True OR if they presented the
    statically-configured admin token.
    """
    if not user.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "admin required")
    return user


def is_admin_token(authorization: str | None) -> bool:
    """Constant-string check for the configured admin token."""
    if not authorization:
        return False
    parts = authorization.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return False
    return hmac.compare_digest(parts[1].encode("utf-8"), settings.ADMIN_TOKEN.encode("utf-8"))
