"""Durable fixed-window request rate limiting for public endpoints."""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import case, delete, update
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session, SQLModel, select
from starlette.requests import Request

from ..config import settings
from ..core.models import RateLimitBucket, RateLimitMaintenance

_CLEANUP_LEASE_NAME = "rate-limit-buckets"


class RateLimitScope(StrEnum):
    SIGNUP = "signup"
    ADMIN_LOGIN = "admin-login"
    PAYMENT_CREATE = "payment-create"
    DOMAIN_VERIFY = "domain-verify"
    CLIENT_CERTIFICATE = "client-certificate"


@dataclass(frozen=True)
class RateLimitSpec:
    scope: RateLimitScope
    requests: int
    window_seconds: int


class RateLimitExceeded(RuntimeError):
    """The current identifier exhausted one endpoint-specific request window."""

    def __init__(self, retry_after: int) -> None:
        super().__init__("request rate limit exceeded")
        self.retry_after = retry_after


def spec_for(scope: RateLimitScope) -> RateLimitSpec:
    configured = {
        RateLimitScope.SIGNUP: (
            settings.RATE_LIMIT_SIGNUP_REQUESTS,
            settings.RATE_LIMIT_SIGNUP_WINDOW_SECONDS,
        ),
        RateLimitScope.ADMIN_LOGIN: (
            settings.RATE_LIMIT_ADMIN_LOGIN_REQUESTS,
            settings.RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS,
        ),
        RateLimitScope.PAYMENT_CREATE: (
            settings.RATE_LIMIT_PAYMENT_CREATE_REQUESTS,
            settings.RATE_LIMIT_PAYMENT_CREATE_WINDOW_SECONDS,
        ),
        RateLimitScope.DOMAIN_VERIFY: (
            settings.RATE_LIMIT_DOMAIN_VERIFY_REQUESTS,
            settings.RATE_LIMIT_DOMAIN_VERIFY_WINDOW_SECONDS,
        ),
        RateLimitScope.CLIENT_CERTIFICATE: (
            settings.RATE_LIMIT_CLIENT_CERT_REQUESTS,
            settings.RATE_LIMIT_CLIENT_CERT_WINDOW_SECONDS,
        ),
    }
    requests, window_seconds = configured[scope]
    return RateLimitSpec(scope, requests, window_seconds)


def direct_client_identifier(request: Request) -> str:
    """Use only ASGI's trusted client tuple, never application-parsed proxy headers."""
    return f"client:{request.client.host if request.client is not None else 'unavailable'}"


def account_identifier(user_id: int) -> str:
    return f"account:{user_id}"


def hash_identifier(scope: RateLimitScope, identifier: str) -> str:
    """Return a domain-separated HMAC so raw IPs and account ids are never persisted."""
    message = f"blindport:rate-limit:v1:{scope.value}:{identifier}".encode()
    return hmac.new(settings.token_hash_key.encode(), message, hashlib.sha256).hexdigest()


def _dialect_insert(session: Session, model: type[SQLModel]) -> Any:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        return postgresql_insert(model)
    if dialect == "sqlite":
        return sqlite_insert(model)
    raise RuntimeError(f"rate limiting does not support database dialect {dialect!r}")


def _cleanup_if_due(session: Session, now: datetime) -> None:
    insert_maintenance = _dialect_insert(session, RateLimitMaintenance).values(
        name=_CLEANUP_LEASE_NAME,
        next_cleanup_at=now,
        bucket_count=0,
    )
    session.execute(insert_maintenance.on_conflict_do_nothing(index_elements=["name"]))
    claimed = session.execute(
        update(RateLimitMaintenance)
        .where(
            RateLimitMaintenance.name == _CLEANUP_LEASE_NAME,
            RateLimitMaintenance.next_cleanup_at <= now,  # type: ignore[operator]
        )
        .values(
            next_cleanup_at=now + timedelta(seconds=settings.RATE_LIMIT_CLEANUP_INTERVAL_SECONDS)
        )
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        return

    stale_ids = (
        select(RateLimitBucket.id)
        .where(RateLimitBucket.expires_at <= now)  # type: ignore[operator]
        .order_by(RateLimitBucket.expires_at, RateLimitBucket.id)
        .limit(settings.RATE_LIMIT_CLEANUP_BATCH_SIZE)
    )
    deleted = session.execute(
        delete(RateLimitBucket)
        .where(RateLimitBucket.id.in_(stale_ids))  # type: ignore[union-attr]
        .execution_options(synchronize_session=False)
    )
    if deleted.rowcount:
        session.execute(
            update(RateLimitMaintenance)
            .where(RateLimitMaintenance.name == _CLEANUP_LEASE_NAME)
            .values(
                bucket_count=case(
                    (
                        RateLimitMaintenance.bucket_count >= deleted.rowcount,
                        RateLimitMaintenance.bucket_count - deleted.rowcount,
                    ),
                    else_=0,
                )
            )
            .execution_options(synchronize_session=False)
        )


def _consume_existing_bucket(
    session: Session,
    spec: RateLimitSpec,
    identifier_hash: str,
    window_start: datetime,
    expires_at: datetime,
) -> int | None:
    return session.execute(
        update(RateLimitBucket)
        .where(
            RateLimitBucket.scope == spec.scope.value,
            RateLimitBucket.identifier_hash == identifier_hash,
            RateLimitBucket.window_start == window_start,
        )
        .values(
            request_count=RateLimitBucket.request_count + 1,
            expires_at=expires_at,
        )
        .returning(RateLimitBucket.request_count)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()


def _reserve_bucket_slot(session: Session) -> bool:
    reserved = session.execute(
        update(RateLimitMaintenance)
        .where(
            RateLimitMaintenance.name == _CLEANUP_LEASE_NAME,
            RateLimitMaintenance.bucket_count < settings.RATE_LIMIT_MAX_BUCKETS,  # type: ignore[operator]
        )
        .values(bucket_count=RateLimitMaintenance.bucket_count + 1)
        .returning(RateLimitMaintenance.bucket_count)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    return reserved is not None


def _release_bucket_slot(session: Session) -> None:
    session.execute(
        update(RateLimitMaintenance)
        .where(RateLimitMaintenance.name == _CLEANUP_LEASE_NAME)
        .values(bucket_count=RateLimitMaintenance.bucket_count - 1)
        .execution_options(synchronize_session=False)
    )


def enforce_rate_limit(
    session: Session,
    spec: RateLimitSpec,
    identifier: str,
    *,
    now: datetime | None = None,
) -> None:
    """Atomically consume one request from a durable fixed window."""
    now = now or datetime.now(UTC)
    window_epoch = int(now.timestamp()) // spec.window_seconds * spec.window_seconds
    window_start = datetime.fromtimestamp(window_epoch, UTC)
    window_end = window_start + timedelta(seconds=spec.window_seconds)
    expires_at = window_end + timedelta(seconds=settings.RATE_LIMIT_BUCKET_RETENTION_SECONDS)
    identifier_hash = hash_identifier(spec.scope, identifier)

    _cleanup_if_due(session, now)
    consumed = _consume_existing_bucket(
        session,
        spec,
        identifier_hash,
        window_start,
        expires_at,
    )
    if consumed is None and not _reserve_bucket_slot(session):
        session.commit()
        raise RateLimitExceeded(settings.RATE_LIMIT_CLEANUP_INTERVAL_SECONDS)

    if consumed is None:
        insert_bucket = _dialect_insert(session, RateLimitBucket).values(
            scope=spec.scope.value,
            identifier_hash=identifier_hash,
            window_start=window_start,
            request_count=1,
            expires_at=expires_at,
        )
        consumed = session.execute(
            insert_bucket.on_conflict_do_nothing(
                index_elements=["scope", "identifier_hash", "window_start"]
            ).returning(RateLimitBucket.request_count)
        ).scalar_one_or_none()
        if consumed is None:
            _release_bucket_slot(session)
            consumed = _consume_existing_bucket(
                session,
                spec,
                identifier_hash,
                window_start,
                expires_at,
            )
            if consumed is None:  # pragma: no cover - conflicting row is transaction-visible
                session.rollback()
                raise RuntimeError("rate-limit bucket conflict disappeared")
    session.commit()
    if consumed > spec.requests:
        retry_after = max(1, math.ceil((window_end - now).total_seconds()))
        raise RateLimitExceeded(retry_after)
