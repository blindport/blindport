"""Public REST API endpoints (versioned at /api/v1)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlmodel import Session, select

from ..adapters.base import NwcAdapterError
from ..adapters.factory import get_cashu_adapter, get_nwc_adapter
from ..config import settings
from ..core import qr, tokens
from ..core.auth import AdminPrincipal, current_admin, current_user
from ..core.ca import issue_client_cert
from ..core.credentials import CredentialError
from ..core.models import (
    DeliveryMode,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..core.schemas import (
    AccountStatusResponse,
    AgentOrderRequest,
    AgentOrderResponse,
    CashuMintAndRedeemRequest,
    CashuQuoteRequest,
    CashuQuoteResponse,
    CatalogResponse,
    ClientCertResponse,
    CreatePaymentRequest,
    CreateSubscriptionRequest,
    DomainVerificationResponse,
    MeResponse,
    NwcStatusResponse,
    PaymentResponse,
    RelayProvisioningResponse,
    ReminderEmailStatusResponse,
    SetNwcRequest,
    SetReminderEmailRequest,
    SignupResponse,
    SubmitCashuTokenRequest,
    SubscriptionResponse,
)
from ..db import get_session
from ..services import agent_orders as agent_orders_svc
from ..services import payments as payments_svc
from ..services import subscriptions as subs_svc
from ..services.allocator import NoCapacityError
from ..services.catalog import ProductUnavailableError, get_catalog
from ..services.domain_verification import (
    DomainVerificationResult,
    DomainVerifier,
    ResolverFailureError,
    ResolverUnavailableError,
    get_domain_verifier,
)
from ..services.health import readiness_status
from ..services.nwc_credentials import (
    clear_nwc_credential,
    nwc_capabilities,
    store_nwc_credential,
)
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    account_identifier,
    direct_client_identifier,
    enforce_rate_limit,
    spec_for,
)
from ..services.reminders import (
    ReminderEmailError,
    cancel_pending_reminders,
    clear_reminder_email,
    store_reminder_email,
)

router = APIRouter(prefix="/api/v1")


def _enforce_public_rate_limit(
    session: Session,
    scope: RateLimitScope,
    identifier: str,
) -> None:
    try:
        enforce_rate_limit(session, spec_for(scope), identifier)
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={"Retry-After": str(error.retry_after)},
        ) from error


# ---- auth / accounts ------------------------------------------------------


@router.get("/catalog", response_model=CatalogResponse)
def catalog(session: Session = Depends(get_session)) -> CatalogResponse:
    return get_catalog(session)


@router.post("/signup", response_model=SignupResponse)
def signup(
    request: Request,
    response: Response,
    session: Session = Depends(get_session),
) -> SignupResponse:
    """Create a new anonymous account. Returns the bearer token exactly once."""
    response.headers["Cache-Control"] = "no-store"
    _enforce_public_rate_limit(
        session,
        RateLimitScope.SIGNUP,
        direct_client_identifier(request),
    )
    display, normalized = tokens.generate_token()
    hashed = tokens.hash_token(normalized)
    user = User(display_token=None, hashed_token=hashed)
    session.add(user)
    session.commit()
    session.refresh(user)
    return SignupResponse(token=display, user_id=user.id or 0)


def _sub_to_response(sub: Subscription) -> SubscriptionResponse:
    challenge_name = None
    challenge_value = None
    record_type = None
    record_name = None
    record_target = None
    if (
        sub.status == SubscriptionStatus.PENDING
        and not sub.domain_is_managed
        and sub.domain
        and sub.domain_verification_token
    ):
        challenge_name = subs_svc.domain_challenge_name(sub.domain)
        challenge_value = subs_svc.domain_challenge_value(sub.domain_verification_token)
        record_type = "TXT"
        record_name = challenge_name
        record_target = challenge_value
    elif (
        sub.product == ProductType.RELAY
        and not sub.domain_is_managed
        and sub.domain
        and sub.relay_pool_domain
    ):
        record_type = "CNAME"
        record_name = sub.domain
        record_target = sub.relay_pool_domain
    return SubscriptionResponse(
        id=sub.public_id,
        product=sub.product,
        delivery=sub.delivery,
        status=sub.status,
        assigned_ip=sub.assigned_ip,
        assigned_port=sub.assigned_port,
        transport=sub.transport,
        domain=sub.domain,
        relay_pool_domain=sub.relay_pool_domain,
        domain_is_managed=sub.domain_is_managed,
        domain_verified_at=sub.domain_verified_at,
        domain_verification_expires_at=sub.domain_claim_expires_at,
        domain_renewal_grace_expires_at=sub.domain_renewal_grace_expires_at,
        domain_challenge_name=challenge_name,
        domain_challenge_value=challenge_value,
        record_type=record_type,
        record_name=record_name,
        record_target=record_target,
        monthly_price_sats=sub.monthly_price_sats,
        yearly_price_sats=sub.yearly_price_sats,
        billing_term=sub.billing_term,
        period_days=subs_svc.billing_period_days(sub.billing_term),
        current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end,
        auto_renew=sub.auto_renew,
    )


@router.get("/me", response_model=MeResponse)
def me(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> MeResponse:
    subs_svc.reap_expired_domain_claims(session)
    subs = session.exec(select(Subscription).where(Subscription.user_id == user.id)).all()
    subs_svc.expire_elapsed_subscriptions(session, subs)
    return MeResponse(
        user_id=user.id or 0,
        is_admin=user.is_admin,
        created_at=user.created_at,
        subscriptions=[_sub_to_response(s) for s in subs],
    )


def _nwc_status(user: User) -> NwcStatusResponse:
    return NwcStatusResponse(
        has_nwc=user.has_nwc,
        capabilities=nwc_capabilities(user),
        last_validated_at=user.nwc_last_validated_at,
    )


def _locked_nwc_user(session: Session, user: User) -> User:
    if user.id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable")
    locked = session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    open_payment = session.exec(
        select(Payment.id)
        .join(Subscription, Subscription.id == Payment.subscription_id)
        .where(
            Subscription.user_id == locked.id,
            Payment.method == PaymentMethod.NWC,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
    ).first()
    if open_payment is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "wallet connection cannot change while an NWC payment is open",
        )
    return locked


@router.get("/me/nwc", response_model=NwcStatusResponse)
def get_nwc_status(user: User = Depends(current_user)) -> NwcStatusResponse:
    return _nwc_status(user)


@router.post("/me/nwc", response_model=NwcStatusResponse)
def set_nwc(
    body: SetNwcRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NwcStatusResponse:
    try:
        payments_svc.require_payment_method_enabled(PaymentMethod.NWC)
    except payments_svc.DisabledPaymentMethodError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    _enforce_public_rate_limit(
        session,
        RateLimitScope.PAYMENT_CREATE,
        account_identifier(user.id or 0),
    )
    nwc_uri = body.nwc_uri.strip()
    if not nwc_uri or len(nwc_uri) > 4096:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "wallet connection URI is invalid")
    try:
        validation = get_nwc_adapter().validate_connection(nwc_uri)
    except NwcAdapterError as error:
        response_status = (
            status.HTTP_502_BAD_GATEWAY if error.retryable else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(response_status, str(error)) from error
    user = _locked_nwc_user(session, user)
    try:
        store_nwc_credential(user, nwc_uri, validation.capabilities)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "wallet credential encryption is unavailable",
        ) from error
    session.add(user)
    session.commit()
    session.refresh(user)
    return _nwc_status(user)


@router.delete("/me/nwc", response_model=NwcStatusResponse)
def clear_nwc(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NwcStatusResponse:
    user = _locked_nwc_user(session, user)
    clear_nwc_credential(user)
    for subscription in session.exec(
        select(Subscription).where(Subscription.user_id == user.id, Subscription.auto_renew)
    ).all():
        subscription.auto_renew = False
        session.add(subscription)
    session.add(user)
    session.commit()
    session.refresh(user)
    return _nwc_status(user)


def _reminder_status(user: User) -> ReminderEmailStatusResponse:
    return ReminderEmailStatusResponse(configured=user.has_reminder_email)


def _locked_reminder_user(session: Session, user: User) -> User:
    if user.id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable")
    return session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()


@router.get("/me/reminder-email", response_model=ReminderEmailStatusResponse)
def get_reminder_email_status(
    response: Response,
    user: User = Depends(current_user),
) -> ReminderEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not settings.REMINDER_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return _reminder_status(user)


@router.post("/me/reminder-email", response_model=ReminderEmailStatusResponse)
async def set_reminder_email(
    response: Response,
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ReminderEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not settings.REMINDER_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    _enforce_public_rate_limit(
        session,
        RateLimitScope.PAYMENT_CREATE,
        account_identifier(user.id or 0),
    )
    try:
        content_type = request.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type != "application/json":
            raise ValueError("invalid content type")
        encoded = bytearray()
        async for chunk in request.stream():
            encoded.extend(chunk)
            if len(encoded) > 1024:
                raise ValueError("request body is too large")
        validated = SetReminderEmailRequest.model_validate(json.loads(encoded))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, ValidationError) as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "reminder email address is invalid",
            headers={"Cache-Control": "no-store"},
        ) from error
    user = _locked_reminder_user(session, user)
    try:
        cancel_pending_reminders(session, user)
        store_reminder_email(user, validated.email)
    except ReminderEmailError as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            str(error),
            headers={"Cache-Control": "no-store"},
        ) from error
    except CredentialError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "reminder email encryption is unavailable",
            headers={"Cache-Control": "no-store"},
        ) from error
    session.add(user)
    session.commit()
    session.refresh(user)
    return _reminder_status(user)


@router.delete("/me/reminder-email", response_model=ReminderEmailStatusResponse)
def delete_reminder_email(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> ReminderEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not settings.REMINDER_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    _enforce_public_rate_limit(
        session,
        RateLimitScope.PAYMENT_CREATE,
        account_identifier(user.id or 0),
    )
    user = _locked_reminder_user(session, user)
    clear_reminder_email(user)
    cancel_pending_reminders(session, user)
    session.add(user)
    session.commit()
    session.refresh(user)
    return _reminder_status(user)


# ---- subscriptions --------------------------------------------------------


@router.put(
    "/client/orders/{order_key}",
    response_model=AgentOrderResponse,
)
def put_client_order(
    order_key: Annotated[
        str,
        Path(min_length=1, max_length=63, pattern=r"^[a-z0-9](?:[a-z0-9_-]{0,62})$"),
    ],
    body: AgentOrderRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> AgentOrderResponse:
    _enforce_public_rate_limit(
        session,
        RateLimitScope.PAYMENT_CREATE,
        account_identifier(user.id or 0),
    )
    try:
        result = agent_orders_svc.put_agent_order(
            session,
            user,
            order_key,
            agent_orders_svc.AgentOrderSpec(
                product=body.product,
                billing_term=body.billing_term,
                delivery=body.delivery,
                transport=body.transport,
                domain=body.domain,
            ),
        )
    except agent_orders_svc.AgentOrderConflictError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except subs_svc.AccountLimitError as error:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(error)) from error
    except (ProductUnavailableError, NoCapacityError) as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return AgentOrderResponse(
        order_key=result.order.order_key,
        subscription=_sub_to_response(result.subscription),
        payment=(
            _payment_to_response(result.payment, result.subscription)
            if result.payment is not None
            else None
        ),
        state=result.state,
    )


@router.post("/subscriptions", response_model=SubscriptionResponse)
def create_subscription(
    body: CreateSubscriptionRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> SubscriptionResponse:
    try:
        sub = subs_svc.create_subscription(
            session,
            user=user,
            product=body.product,
            domain=body.domain,
            transport=body.transport,
            delivery=body.delivery,
            billing_term=body.billing_term,
        )
    except subs_svc.AccountLimitError as e:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(e)) from e
    except ProductUnavailableError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except NoCapacityError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return _sub_to_response(sub)


@router.get("/subscriptions", response_model=list[SubscriptionResponse])
def list_subscriptions(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[SubscriptionResponse]:
    subs_svc.reap_expired_domain_claims(session)
    rows = session.exec(select(Subscription).where(Subscription.user_id == user.id)).all()
    subs_svc.expire_elapsed_subscriptions(session, rows)
    return [_sub_to_response(s) for s in rows]


def _domain_verifier_dependency() -> Callable[[], DomainVerifier]:
    return get_domain_verifier


def _verify_domain_or_http(
    session: Session,
    sub: Subscription,
    verifier_factory: Callable[[], DomainVerifier],
    *,
    force: bool = False,
) -> DomainVerificationResult:
    try:
        return subs_svc.verify_subscription_domain(
            session,
            sub,
            verifier_factory,
            force=force,
        )
    except ResolverUnavailableError as e:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(e)) from e
    except ResolverFailureError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e


@router.post(
    "/subscriptions/{public_id}/verify-domain",
    response_model=DomainVerificationResponse,
)
def verify_domain(
    public_id: UUID,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    verifier_factory: Callable[[], DomainVerifier] = Depends(_domain_verifier_dependency),
) -> DomainVerificationResponse:
    _enforce_public_rate_limit(
        session,
        RateLimitScope.DOMAIN_VERIFY,
        account_identifier(user.id or 0),
    )
    sub = session.exec(
        select(Subscription).where(
            Subscription.public_id == public_id,
            Subscription.user_id == user.id,
        )
    ).first()
    if sub is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    result = _verify_domain_or_http(session, sub, verifier_factory)
    return DomainVerificationResponse(
        verified=result.verified,
        detail=result.detail,
        subscription=_sub_to_response(sub),
    )


@router.post("/subscriptions/{public_id}/auto-renew")
def toggle_auto_renew(
    public_id: UUID,
    enable: bool,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> dict:
    sub = session.exec(
        select(Subscription).where(
            Subscription.public_id == public_id,
            Subscription.user_id == user.id,
        )
    ).first()
    if sub is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    if enable:
        try:
            payments_svc.require_payment_method_enabled(PaymentMethod.NWC)
        except payments_svc.DisabledPaymentMethodError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    if enable and not user.has_nwc:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "cannot enable auto-renew without a wallet connection"
        )
    sub.auto_renew = enable
    session.add(sub)
    session.commit()
    return {"ok": True, "auto_renew": sub.auto_renew}


# ---- payments -------------------------------------------------------------


def _payment_to_response(p: Payment, subscription: Subscription) -> PaymentResponse:
    lightning_uri = None
    qr_svg = None
    if p.method == PaymentMethod.LIGHTNING and p.invoice:
        lightning_uri = f"lightning:{p.invoice}"
        qr_svg = qr.render_svg(p.invoice.upper())
    return PaymentResponse(
        id=p.id or 0,
        subscription_id=subscription.public_id,
        method=p.method,
        status=p.status,
        amount_sats=p.amount_sats,
        billing_term=p.billing_term,
        period_days=p.period_days,
        invoice=p.invoice,
        payment_hash=p.payment_hash,
        lightning_uri=lightning_uri,
        qr_svg=qr_svg,
        cashu_token_required=(
            p.method == PaymentMethod.CASHU and p.status == PaymentStatus.PENDING
        ),
        nwc_state=p.nwc_state,
        nwc_attempt_count=p.nwc_attempt_count,
        nwc_error_code=p.nwc_error_code,
        expires_at=p.expires_at,
    )


@router.post("/payments", response_model=PaymentResponse)
def create_payment(
    body: CreatePaymentRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    verifier_factory: Callable[[], DomainVerifier] = Depends(_domain_verifier_dependency),
) -> PaymentResponse:
    _enforce_public_rate_limit(
        session,
        RateLimitScope.PAYMENT_CREATE,
        account_identifier(user.id or 0),
    )
    sub = session.exec(
        select(Subscription).where(
            Subscription.public_id == body.subscription_id,
            Subscription.user_id == user.id,
        )
    ).first()
    if sub is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    requires_domain_lookup = (
        sub.product == ProductType.RELAY
        and not sub.domain_is_managed
        and sub.status != SubscriptionStatus.CANCELLED
        and sub.domain is not None
        and (sub.domain_verified_at is None or subs_svc.uses_unique_cname_target(sub))
    )
    if requires_domain_lookup:
        _enforce_public_rate_limit(
            session,
            RateLimitScope.DOMAIN_VERIFY,
            account_identifier(user.id or 0),
        )
        verification = _verify_domain_or_http(
            session,
            sub,
            verifier_factory,
            force=sub.domain_verified_at is not None,
        )
        if not verification.verified:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, verification.detail)
    try:
        p = payments_svc.create_payment(session, sub, body.method, body.billing_term)
    except subs_svc.AccountLimitError as e:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(e)) from e
    except NoCapacityError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except payments_svc.PaymentProviderError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return _payment_to_response(p, sub)


# ---- administration -------------------------------------------------------


def _set_account_suspension(
    user_id: int,
    suspended: bool,
    session: Session,
) -> AccountStatusResponse:
    target = session.get(User, user_id)
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    target.is_suspended = suspended
    session.add(target)
    session.commit()
    return AccountStatusResponse(user_id=target.id or 0, is_suspended=target.is_suspended)


@router.post("/admin/users/{user_id}/suspend", response_model=AccountStatusResponse)
def suspend_account(
    user_id: int,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AccountStatusResponse:
    return _set_account_suspension(user_id, True, session)


@router.post("/admin/users/{user_id}/unsuspend", response_model=AccountStatusResponse)
def unsuspend_account(
    user_id: int,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AccountStatusResponse:
    return _set_account_suspension(user_id, False, session)


@router.get("/payments/{payment_id}", response_model=PaymentResponse)
def get_payment(
    payment_id: int,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> PaymentResponse:
    p = session.get(Payment, payment_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    sub = session.get(Subscription, p.subscription_id)
    if not sub or sub.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    # Lazy settle on read for Lightning/NWC.
    try:
        p = payments_svc.check_and_settle_payment(session, p)
    except payments_svc.DisabledPaymentMethodError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    except payments_svc.PaymentProviderError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    return _payment_to_response(p, sub)


@router.post("/payments/cashu-submit", response_model=PaymentResponse)
def submit_cashu(
    body: SubmitCashuTokenRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> PaymentResponse:
    p = session.get(Payment, body.payment_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    sub = session.get(Subscription, p.subscription_id)
    if not sub or sub.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    try:
        p = payments_svc.submit_cashu_token(session, p, body.cashu_token)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    return _payment_to_response(p, sub)


@router.post("/payments/cashu-quote", response_model=CashuQuoteResponse)
def cashu_quote(
    body: CashuQuoteRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> CashuQuoteResponse:
    """Mint a bolt11 invoice the user can pay to obtain ecash off the trusted mint.

    The user's Cashu wallet then settles this invoice and mints ecash against
    the returned ``quote_id``. The resulting token must still be submitted via
    ``/payments/cashu-submit`` for the backend to verify and credit the payment.
    """
    p = session.get(Payment, body.payment_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    sub = session.get(Subscription, p.subscription_id)
    if not sub or sub.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    try:
        p = payments_svc.require_cashu_payment_eligible(session, p)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    cashu = get_cashu_adapter()
    try:
        quote = cashu.request_mint_quote(p.amount_sats)
    except NotImplementedError as e:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "configured cashu adapter does not support mint quotes",
        ) from e
    except Exception as e:  # pragma: no cover - mint unreachable
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"mint error: {e}") from e
    return CashuQuoteResponse(
        payment_id=p.id,
        quote_id=quote.quote_id,
        bolt11=quote.bolt11,
        amount_sats=quote.amount_sats,
        mint_url=quote.mint_url,
        expires_at=quote.expires_at,
        lightning_uri=f"lightning:{quote.bolt11}",
        qr_svg=qr.render_svg(quote.bolt11.upper()),
    )


@router.post("/payments/cashu-mint-and-redeem", response_model=PaymentResponse)
def cashu_mint_and_redeem(
    body: CashuMintAndRedeemRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> PaymentResponse:
    """Backend-side wallet: mint ecash against a paid NUT-04 quote and settle.

    Polled by the dashboard while the user pays the bolt11 invoice. While the
    quote is unpaid, the payment is returned unchanged so the caller can poll
    again. Once paid on the mint, the backend mints+swaps the resulting ecash
    into operator-owned proofs and marks the payment paid.
    """
    p = session.get(Payment, body.payment_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    sub = session.get(Subscription, p.subscription_id)
    if not sub or sub.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    try:
        p = payments_svc.mint_and_redeem_quote(session, p, body.quote_id, body.mint_url)
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    except Exception as e:  # pragma: no cover - mint-side errors
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"mint error: {e}") from e
    return _payment_to_response(p, sub)


# ---- client provisioning --------------------------------------------------


@router.get("/client/config", response_model=list[RelayProvisioningResponse])
def client_config(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[RelayProvisioningResponse]:
    """Returned to the Linux daemon. Lists relay endpoints + resource bindings
    for every active subscription the user has.
    """
    subs_svc.reap_expired_domain_claims(session)
    out: list[RelayProvisioningResponse] = []
    rows = session.exec(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status == SubscriptionStatus.ACTIVE,
        )
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, rows)
    for s in rows:
        if s.status != SubscriptionStatus.ACTIVE:
            continue
        if s.product == ProductType.IP and s.delivery == DeliveryMode.WIREGUARD:
            continue
        relay_endpoints = (
            settings.relay_control_urls_list
            if s.product == ProductType.RELAY
            else [settings.RELAY_CONTROL_URL]
        )
        out.append(
            RelayProvisioningResponse(
                relay_endpoint=relay_endpoints[0],
                relay_endpoints=relay_endpoints,
                assigned_ip=s.assigned_ip,
                assigned_port=s.assigned_port,
                transport=s.transport,
                domain=s.domain,
                product=s.product,
                subscription_id=s.public_id,
            )
        )
    return out


@router.get("/client/cert", response_model=ClientCertResponse)
def client_cert(
    response: Response,
    user: User = Depends(current_user),
) -> ClientCertResponse:
    """Issue a short-lived mTLS client certificate for the calling user.

    The relay control plane requires every connecting client to present a
    cert signed by this CA, and the legacy certificate user id must match the
    bearer token identity. Because this endpoint issues a new keypair to an
    authenticated account, mTLS is transport authentication and identity
    binding, not a second factor against bearer-token theft.

    Certs are intentionally short-lived (settings.CLIENT_CERT_TTL_DAYS,
    default 30); application authorization is refreshed periodically by the
    relay and bounded by its maximum authorization-staleness setting.
    """
    if not settings.LEGACY_CLIENT_CERT_ISSUANCE_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    response.headers["Cache-Control"] = "no-store"
    issued = issue_client_cert(user.id or 0)
    return ClientCertResponse(
        ca_cert_pem=issued.ca_cert_pem,
        client_cert_pem=issued.client_cert_pem,
        client_key_pem=issued.client_key_pem,
        not_after=issued.not_after.isoformat(),
        serial=f"{issued.serial:x}",
    )


# ---- health ---------------------------------------------------------------


@router.get("/health")
def health() -> JSONResponse:
    return _readiness_response()


@router.get("/health/live")
def health_live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/ready")
def health_ready() -> JSONResponse:
    return _readiness_response()


def _readiness_response() -> JSONResponse:
    ready, components = readiness_status()
    return JSONResponse(
        status_code=status.HTTP_200_OK if ready else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "ok" if ready else "unavailable",
            "components": components,
        },
    )
