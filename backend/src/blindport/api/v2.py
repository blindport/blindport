"""Public REST API endpoints versioned at /api/v2."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session, select

from ..core import tokens
from ..core.auth import AdminPrincipal, current_admin, current_user
from ..core.models import ProductType, Subscription, User
from ..core.schemas import (
    AccountMeResponse,
    AccountSignupResponse,
    AnonymousOrderRequest,
    AnonymousOrderResponse,
    ClientCertificateRequest,
    ClientCertificateResponse,
    PublicAccountStatusResponse,
    WireGuardConfigResponse,
    WireGuardKeyRequest,
)
from ..db import get_session
from ..services import subscriptions as subs_svc
from ..services.allocator import NoCapacityError
from ..services.catalog import ProductUnavailableError
from ..services.client_enrollment import (
    ClientEnrollmentConflictError,
    enroll_client_certificate,
)
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    account_identifier,
    enforce_direct_rate_limit,
    enforce_rate_limit,
    spec_for,
)
from ..services.wireguard import (
    WireGuardEnrollmentConflictError,
)
from ..services.wireguard import (
    client_config as wireguard_client_config,
)
from ..services.wireguard import (
    enroll_key as enroll_wireguard_key,
)

router = APIRouter(prefix="/api/v2")


@router.post("/signup", response_model=AccountSignupResponse)
def signup(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AccountSignupResponse:
    """Create an anonymous account identified externally only by its public UUID."""
    response.headers["Cache-Control"] = "no-store"
    try:
        enforce_direct_rate_limit(request, spec_for(RateLimitScope.SIGNUP))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={"Cache-Control": "no-store", "Retry-After": str(error.retry_after)},
        ) from error
    display, normalized = tokens.generate_token()
    user = User(display_token=None, hashed_token=tokens.hash_token(normalized))
    session.add(user)
    session.commit()
    session.refresh(user)
    return AccountSignupResponse(token=display, account_id=user.public_id)


@router.get("/me", response_model=AccountMeResponse)
def me(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> AccountMeResponse:
    from .v1 import _sub_to_response

    subs_svc.reap_expired_domain_claims(session)
    subscriptions = session.exec(select(Subscription).where(Subscription.user_id == user.id)).all()
    subs_svc.expire_elapsed_subscriptions(session, subscriptions)
    return AccountMeResponse(
        account_id=user.public_id,
        is_admin=user.is_admin,
        created_at=user.created_at,
        subscriptions=[_sub_to_response(subscription) for subscription in subscriptions],
    )


def _set_account_suspension(
    account_id: UUID,
    suspended: bool,
    session: Session,
) -> PublicAccountStatusResponse:
    target = session.exec(select(User).where(User.public_id == account_id)).first()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    target.is_suspended = suspended
    session.add(target)
    session.commit()
    return PublicAccountStatusResponse(
        account_id=target.public_id,
        is_suspended=target.is_suspended,
    )


@router.post("/admin/users/{account_id}/suspend", response_model=PublicAccountStatusResponse)
def suspend_account(
    account_id: UUID,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> PublicAccountStatusResponse:
    return _set_account_suspension(account_id, True, session)


@router.post("/admin/users/{account_id}/unsuspend", response_model=PublicAccountStatusResponse)
def unsuspend_account(
    account_id: UUID,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> PublicAccountStatusResponse:
    return _set_account_suspension(account_id, False, session)


@router.post(
    "/orders",
    response_model=AnonymousOrderResponse,
    status_code=status.HTTP_201_CREATED,
)
def anonymous_order(
    body: AnonymousOrderRequest,
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> AnonymousOrderResponse:
    """Create an anonymous account and unbilled pending subscription atomically."""
    response.headers["Cache-Control"] = "no-store"
    try:
        enforce_direct_rate_limit(request, spec_for(RateLimitScope.SIGNUP))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={
                "Cache-Control": "no-store",
                "Retry-After": str(error.retry_after),
            },
        ) from error

    if body.product == ProductType.RELAY:
        subs_svc.reap_expired_domain_claims(session)

    display, normalized = tokens.generate_token()
    user = User(display_token=None, hashed_token=tokens.hash_token(normalized))
    try:
        session.add(user)
        session.flush()
        subscription = subs_svc.create_subscription(
            session,
            user=user,
            product=body.product,
            domain=body.domain,
            transport=body.transport,
            delivery=body.delivery,
            billing_term=body.billing_term,
            commit=False,
            reap_domains=False,
        )
        session.commit()
        session.refresh(user)
        session.refresh(subscription)
    except subs_svc.AccountLimitError as error:
        session.rollback()
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(error)) from error
    except ProductUnavailableError as error:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except NoCapacityError as error:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error

    from .v1 import _sub_to_response

    subscription_response = _sub_to_response(subscription)
    return AnonymousOrderResponse(
        token=display,
        account_id=user.public_id,
        monthly_price_sats=subscription.monthly_price_sats,
        yearly_price_sats=subscription.yearly_price_sats,
        billing_term=subscription.billing_term,
        period_days=subscription_response.period_days,
        subscription=subscription_response,
    )


@router.post("/client/certificate", response_model=ClientCertificateResponse)
def client_certificate(
    request: ClientCertificateRequest,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ClientCertificateResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        enforce_rate_limit(
            session,
            spec_for(RateLimitScope.CLIENT_CERTIFICATE),
            account_identifier(user.id or 0),
        )
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={
                "Cache-Control": "no-store",
                "Retry-After": str(error.retry_after),
            },
        ) from error
    try:
        enrolled = enroll_client_certificate(
            session,
            user.id or 0,
            user.public_id,
            request.instance_id,
            request.generation,
            request.csr_pem,
        )
    except ClientEnrollmentConflictError as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            str(error),
            headers={"Cache-Control": "no-store"},
        ) from error
    return ClientCertificateResponse(**vars(enrolled))


@router.get("/client/wireguard", response_model=WireGuardConfigResponse)
def wireguard_config(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> WireGuardConfigResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        config = wireguard_client_config(session, user.id or 0)
    except WireGuardEnrollmentConflictError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    return WireGuardConfigResponse(**vars(config))


@router.post("/client/wireguard/key", response_model=WireGuardConfigResponse)
def wireguard_key(
    request: WireGuardKeyRequest,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> WireGuardConfigResponse:
    response.headers["Cache-Control"] = "no-store"
    try:
        config = enroll_wireguard_key(
            session,
            user.id or 0,
            request.instance_id,
            request.generation,
            request.public_key,
            request.signature,
        )
    except WireGuardEnrollmentConflictError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return WireGuardConfigResponse(**vars(config))
