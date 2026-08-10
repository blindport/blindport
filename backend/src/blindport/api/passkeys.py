"""WebAuthn passkey enrollment, authentication, and browser-session endpoints."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from sqlalchemy import delete, func, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    options_to_json,
    parse_authentication_credential_json,
    parse_registration_credential_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from ..config import settings
from ..core import tokens
from ..core.auth import current_user
from ..core.models import PasskeyCredential, User, WebAuthnChallenge
from ..core.schemas import (
    BrowserSessionTokenRequest,
    BrowserSessionTokenResponse,
    PasskeyAuthenticationResponse,
    PasskeyRegistrationOptionsRequest,
    PasskeyRegistrationRequest,
    PasskeyRegistrationResponse,
    PasskeyResponse,
    WebAuthnCredentialRequest,
    WebAuthnOptionsResponse,
)
from ..db import get_session
from ..services.browser_sessions import (
    CEREMONY_BINDING_COOKIE,
    CSRF_COOKIE,
    SESSION_COOKIE,
    clear_browser_session_cookies,
    clear_ceremony_binding_cookie,
    clear_login_csrf_cookie,
    generate_ceremony_binding,
    hash_ceremony_binding,
    issue_browser_session,
    resolve_browser_session,
    revoke_browser_session,
    set_browser_session_cookies,
    set_ceremony_binding_cookie,
    valid_csrf,
)
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    enforce_direct_rate_limit,
    spec_for,
)

router = APIRouter(prefix="/api/v1")

_NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_CHALLENGE_CAPACITY_LOCK_ID = 0x425057415554484E


def _require_passkeys_enabled(request: Request) -> None:
    if not settings.PASSKEYS_ENABLED or (
        settings.ONION_HOST and request.url.hostname == settings.ONION_HOST
    ):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found", headers=_NO_STORE_HEADERS)


def _now() -> datetime:
    return datetime.now(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    if not value or len(value) % 4 == 1 or _BASE64URL_RE.fullmatch(value) is None:
        raise ValueError("credential id is invalid")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise ValueError("credential id is invalid") from error
    if not decoded or _base64url_encode(decoded) != value:
        raise ValueError("credential id is invalid")
    return decoded


def _binding_hash(request: Request) -> str:
    binding = request.cookies.get(CEREMONY_BINDING_COOKIE, "")
    try:
        return hash_ceremony_binding(binding)
    except ValueError:
        return ""


def _consume_challenge(
    session: Session,
    challenge_id: str,
    ceremony_type: str,
    binding_hash: str,
    now: datetime,
    *,
    user_id: int | None,
) -> bytes | None:
    result = session.execute(
        delete(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.id == challenge_id,
            WebAuthnChallenge.ceremony_type == ceremony_type,
            WebAuthnChallenge.user_id == user_id,
            WebAuthnChallenge.binding_hash == binding_hash,
            WebAuthnChallenge.expires_at > now,  # type: ignore[operator]
        )
        .returning(WebAuthnChallenge.challenge)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    session.commit()
    return result


def _valid_transports(value: str) -> list[AuthenticatorTransport] | None:
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
            return None
        transports = [AuthenticatorTransport(item) for item in parsed]
    except (json.JSONDecodeError, ValueError):
        return None
    normalized = sorted({transport.value for transport in transports})
    if value != json.dumps(normalized, separators=(",", ":"), ensure_ascii=True):
        return None
    return [AuthenticatorTransport(transport) for transport in normalized]


def _serialize_transports(transports: list[AuthenticatorTransport] | None) -> str:
    try:
        values = sorted({AuthenticatorTransport(transport).value for transport in transports or []})
    except ValueError as error:
        raise ValueError("passkey transports are invalid") from error
    return json.dumps(values, separators=(",", ":"), ensure_ascii=True)


def _passkey_response(credential: PasskeyCredential) -> PasskeyResponse:
    transports = _valid_transports(credential.transports_json)
    return PasskeyResponse(
        credential_id=_base64url_encode(credential.credential_id),
        name=credential.name,
        transports=[transport.value for transport in transports or []],
        device_type=credential.device_type,
        backed_up=credential.backed_up,
        created_at=credential.created_at,
        updated_at=credential.updated_at,
        last_used_at=credential.last_used_at,
    )


def _enforce_pending_challenge_limit(session: Session, now: datetime) -> None:
    pending = int(
        session.exec(
            select(func.count())
            .select_from(WebAuthnChallenge)
            .where(WebAuthnChallenge.expires_at > now)  # type: ignore[operator]
        ).one()
        or 0
    )
    if pending >= settings.PASSKEY_MAX_PENDING_CHALLENGES:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many pending passkey requests",
            headers=_NO_STORE_HEADERS,
        )


def _lock_pending_challenge_capacity(session: Session) -> None:
    """Serialize the global challenge cap on the production database."""
    if session.get_bind().dialect.name == "postgresql":
        session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_id)"),
            {"lock_id": _CHALLENGE_CAPACITY_LOCK_ID},
        )


def _options_payload(options: Any) -> dict[str, Any]:
    try:
        payload = json.loads(options_to_json(options))
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("WebAuthn options serialization failed") from error
    if not isinstance(payload, dict):
        raise RuntimeError("WebAuthn options serialization failed")
    return payload


def _verification_error(status_code: int) -> HTTPException:
    return HTTPException(status_code, "passkey verification failed", headers=_NO_STORE_HEADERS)


def _browser_login_error() -> HTTPException:
    return HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "browser sign-in failed",
        headers=_NO_STORE_HEADERS,
    )


@router.post("/browser-session/token", response_model=BrowserSessionTokenResponse)
def exchange_token_for_browser_session(
    body: BrowserSessionTokenRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> BrowserSessionTokenResponse:
    """Exchange a customer bearer token for an opaque browser session."""
    try:
        enforce_direct_rate_limit(request, spec_for(RateLimitScope.BROWSER_LOGIN))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={**_NO_STORE_HEADERS, "Retry-After": str(error.retry_after)},
        ) from error
    try:
        normalized = tokens.crockford.normalize(body.token)
    except Exception:
        raise _browser_login_error() from None
    user = session.exec(
        select(User).where(
            User.hashed_token == tokens.hash_token(normalized),
            User.is_admin.is_(False),  # type: ignore[union-attr]
            User.is_suspended.is_(False),  # type: ignore[union-attr]
        )
    ).one_or_none()
    if user is None:
        raise _browser_login_error()
    try:
        issued = issue_browser_session(session, user, "token")
        session.commit()
    except ValueError:
        session.rollback()
        raise _browser_login_error() from None
    set_browser_session_cookies(response, request, issued)
    return BrowserSessionTokenResponse(account_id=user.public_id)


@router.get(
    "/passkeys",
    response_model=list[PasskeyResponse],
    dependencies=[Depends(_require_passkeys_enabled)],
)
def list_passkeys(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[PasskeyResponse]:
    response.headers.update(_NO_STORE_HEADERS)
    credentials = session.exec(
        select(PasskeyCredential)
        .where(PasskeyCredential.user_id == user.id)
        .order_by(PasskeyCredential.created_at, PasskeyCredential.id)
    ).all()
    return [_passkey_response(credential) for credential in credentials]


@router.post(
    "/passkeys/registration/options",
    response_model=WebAuthnOptionsResponse,
    dependencies=[Depends(_require_passkeys_enabled)],
)
def registration_options(
    body: PasskeyRegistrationOptionsRequest,
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> WebAuthnOptionsResponse:
    now = _now()
    if user.id is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "account is unavailable", headers=_NO_STORE_HEADERS
        )
    credentials = session.exec(
        select(PasskeyCredential).where(PasskeyCredential.user_id == user.id)
    ).all()
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=credential.credential_id, transports=transports)
        for credential in credentials
        if (transports := _valid_transports(credential.transports_json)) is not None
    ]
    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_name=str(user.public_id),
        user_display_name=str(user.public_id),
        user_id=user.public_id.bytes,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=exclude_credentials or None,
        timeout=settings.PASSKEY_CHALLENGE_TTL_SECONDS * 1000,
    )
    _lock_pending_challenge_capacity(session)
    session.execute(
        delete(WebAuthnChallenge)
        .where(WebAuthnChallenge.expires_at <= now)  # type: ignore[operator]
        .execution_options(synchronize_session=False)
    )
    session.execute(
        delete(WebAuthnChallenge)
        .where(
            WebAuthnChallenge.ceremony_type == "registration",
            WebAuthnChallenge.user_id == user.id,
        )
        .execution_options(synchronize_session=False)
    )
    _enforce_pending_challenge_limit(session, now)
    binding = generate_ceremony_binding()
    challenge_record = WebAuthnChallenge(
        challenge=options.challenge,
        ceremony_type="registration",
        user_id=user.id,
        binding_hash=hash_ceremony_binding(binding),
        expires_at=now + timedelta(seconds=settings.PASSKEY_CHALLENGE_TTL_SECONDS),
        created_at=now,
    )
    session.add(challenge_record)
    session.commit()
    set_ceremony_binding_cookie(response, request, binding)
    return WebAuthnOptionsResponse(
        challenge_id=challenge_record.id,
        options=_options_payload(options),
    )


@router.post(
    "/passkeys/registration",
    response_model=PasskeyRegistrationResponse,
    dependencies=[Depends(_require_passkeys_enabled)],
)
def register_passkey(
    body: PasskeyRegistrationRequest,
    request: Request,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> PasskeyRegistrationResponse:
    if user.id is None:
        raise _verification_error(status.HTTP_400_BAD_REQUEST)
    expected_challenge = _consume_challenge(
        session,
        body.challenge_id,
        "registration",
        _binding_hash(request),
        _now(),
        user_id=user.id,
    )
    if expected_challenge is None:
        raise _verification_error(status.HTTP_400_BAD_REQUEST)
    try:
        credential = parse_registration_credential_json(body.credential)
        verified = verify_registration_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            require_user_verification=True,
        )
        transports_json = _serialize_transports(credential.response.transports)
    except (TypeError, ValueError, WebAuthnException):
        raise _verification_error(status.HTTP_400_BAD_REQUEST) from None

    existing = session.exec(
        select(PasskeyCredential)
        .where(PasskeyCredential.credential_id == verified.credential_id)
        .with_for_update()
    ).one_or_none()
    if existing is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "passkey already registered", headers=_NO_STORE_HEADERS
        )
    locked_user = session.exec(
        select(User)
        .where(User.id == user.id, User.is_admin.is_(False), User.is_suspended.is_(False))  # type: ignore[union-attr]
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if locked_user is None:
        raise _verification_error(status.HTTP_400_BAD_REQUEST)
    credential_count = len(
        session.exec(
            select(PasskeyCredential.id).where(PasskeyCredential.user_id == locked_user.id)
        ).all()
    )
    if credential_count >= settings.PASSKEY_MAX_CREDENTIALS_PER_USER:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "passkey limit reached", headers=_NO_STORE_HEADERS
        )
    now = _now()
    stored = PasskeyCredential(
        user_id=locked_user.id or 0,
        credential_id=verified.credential_id,
        credential_public_key=verified.credential_public_key,
        sign_count=verified.sign_count,
        name=body.name,
        transports_json=transports_json,
        device_type=verified.credential_device_type.value,
        backed_up=verified.credential_backed_up,
        created_at=now,
        updated_at=now,
    )
    session.add(stored)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(
            status.HTTP_409_CONFLICT, "passkey already registered", headers=_NO_STORE_HEADERS
        ) from None
    clear_ceremony_binding_cookie(response, request)
    return PasskeyRegistrationResponse(passkey=_passkey_response(stored))


@router.post(
    "/passkeys/authentication/options",
    response_model=WebAuthnOptionsResponse,
    dependencies=[Depends(_require_passkeys_enabled)],
)
def authentication_options(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> WebAuthnOptionsResponse:
    try:
        enforce_direct_rate_limit(request, spec_for(RateLimitScope.BROWSER_LOGIN))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={**_NO_STORE_HEADERS, "Retry-After": str(error.retry_after)},
        ) from error
    now = _now()
    options = generate_authentication_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
        timeout=settings.PASSKEY_CHALLENGE_TTL_SECONDS * 1000,
    )
    _lock_pending_challenge_capacity(session)
    session.execute(
        delete(WebAuthnChallenge)
        .where(WebAuthnChallenge.expires_at <= now)  # type: ignore[operator]
        .execution_options(synchronize_session=False)
    )
    _enforce_pending_challenge_limit(session, now)
    binding = generate_ceremony_binding()
    challenge_record = WebAuthnChallenge(
        challenge=options.challenge,
        ceremony_type="authentication",
        binding_hash=hash_ceremony_binding(binding),
        expires_at=now + timedelta(seconds=settings.PASSKEY_CHALLENGE_TTL_SECONDS),
        created_at=now,
    )
    session.add(challenge_record)
    session.commit()
    set_ceremony_binding_cookie(response, request, binding)
    return WebAuthnOptionsResponse(
        challenge_id=challenge_record.id,
        options=_options_payload(options),
    )


@router.post(
    "/passkeys/authentication",
    response_model=PasskeyAuthenticationResponse,
    dependencies=[Depends(_require_passkeys_enabled)],
)
def authenticate_passkey(
    body: WebAuthnCredentialRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> PasskeyAuthenticationResponse:
    expected_challenge = _consume_challenge(
        session,
        body.challenge_id,
        "authentication",
        _binding_hash(request),
        _now(),
        user_id=None,
    )
    if expected_challenge is None:
        raise _verification_error(status.HTTP_401_UNAUTHORIZED)
    try:
        credential = parse_authentication_credential_json(body.credential)
    except (TypeError, ValueError, WebAuthnException):
        raise _verification_error(status.HTTP_401_UNAUTHORIZED) from None
    stored = session.exec(
        select(PasskeyCredential)
        .where(PasskeyCredential.credential_id == credential.raw_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if stored is None:
        raise _verification_error(status.HTTP_401_UNAUTHORIZED)
    locked_user = session.exec(
        select(User)
        .where(User.id == stored.user_id, User.is_admin.is_(False), User.is_suspended.is_(False))  # type: ignore[union-attr]
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if locked_user is None:
        raise _verification_error(status.HTTP_401_UNAUTHORIZED)
    if credential.response.user_handle is not None and not hmac.compare_digest(
        credential.response.user_handle, locked_user.public_id.bytes
    ):
        raise _verification_error(status.HTTP_401_UNAUTHORIZED)
    try:
        verified = verify_authentication_response(
            credential=credential,
            expected_challenge=expected_challenge,
            expected_rp_id=settings.WEBAUTHN_RP_ID,
            expected_origin=settings.WEBAUTHN_ORIGIN,
            credential_public_key=stored.credential_public_key,
            credential_current_sign_count=stored.sign_count,
            require_user_verification=True,
        )
    except (TypeError, ValueError, WebAuthnException):
        raise _verification_error(status.HTTP_401_UNAUTHORIZED) from None
    now = _now()
    stored.sign_count = verified.new_sign_count
    stored.device_type = verified.credential_device_type.value
    stored.backed_up = verified.credential_backed_up
    stored.updated_at = now
    stored.last_used_at = now
    session.add(stored)
    try:
        issued = issue_browser_session(session, locked_user, "passkey", now)
        session.commit()
    except ValueError:
        session.rollback()
        raise _verification_error(status.HTTP_401_UNAUTHORIZED) from None
    set_browser_session_cookies(response, request, issued)
    clear_ceremony_binding_cookie(response, request)
    clear_login_csrf_cookie(response, request)
    return PasskeyAuthenticationResponse(account_id=locked_user.public_id)


@router.delete(
    "/passkeys/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(_require_passkeys_enabled)],
)
def delete_passkey(
    credential_id: str = Path(min_length=1, max_length=1024),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> Response:
    try:
        decoded_id = _base64url_decode(credential_id)
    except ValueError:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "passkey not found", headers=_NO_STORE_HEADERS
        ) from None
    credential = session.exec(
        select(PasskeyCredential).where(
            PasskeyCredential.credential_id == decoded_id,
            PasskeyCredential.user_id == user.id,
        )
    ).one_or_none()
    if credential is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "passkey not found", headers=_NO_STORE_HEADERS
        )
    session.delete(credential)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers=_NO_STORE_HEADERS)


@router.delete(
    "/browser-session",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_browser_session(
    request: Request,
    session: Session = Depends(get_session),
) -> Response:
    raw_token = request.cookies.get(SESSION_COOKIE, "")
    resolved = resolve_browser_session(session, raw_token)
    if resolved is not None and not valid_csrf(
        resolved[0],
        request.cookies.get(CSRF_COOKIE),
        request.headers.get("X-CSRF-Token"),
    ):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "CSRF validation failed",
            headers=_NO_STORE_HEADERS,
        )
    revoke_browser_session(session, raw_token)
    response = Response(status_code=status.HTTP_204_NO_CONTENT, headers=_NO_STORE_HEADERS)
    clear_browser_session_cookies(response, request)
    return response
