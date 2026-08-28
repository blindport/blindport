"""Public REST API endpoints (versioned at /api/v1)."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Annotated, Literal, cast
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
from sqlalchemy import func
from sqlmodel import Session, select
from starlette.concurrency import run_in_threadpool

from ..adapters.base import NwcAdapterError
from ..adapters.factory import get_nwc_adapter
from ..config import settings
from ..core import qr, tokens
from ..core.auth import AdminPrincipal, current_admin, current_bearer_user, current_user
from ..core.ca import issue_client_cert
from ..core.credentials import CredentialError
from ..core.models import (
    Announcement,
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    AnnouncementState,
    DeliveryMode,
    NotificationDelivery,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    RelayHostnameScope,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..core.schemas import (
    AccountStatusResponse,
    AgentOrderRequest,
    AgentOrderResponse,
    AnnouncementDetailResponse,
    AnnouncementSummaryResponse,
    CatalogResponse,
    ClientCertResponse,
    ClientVersionResponse,
    CreateAnnouncementRequest,
    CreatePaymentRequest,
    CreateSubscriptionRequest,
    CreateWildcardUpgradeRequest,
    DomainVerificationResponse,
    MeResponse,
    NotificationEmailRequest,
    NotificationEmailStatusResponse,
    NwcStatusResponse,
    PaymentConflictResponse,
    PaymentResponse,
    RelayAssignmentResponse,
    RelayProvisioningResponse,
    SetNwcRequest,
    SignupResponse,
    SubscriptionResponse,
)
from ..db import get_session
from ..services import agent_orders as agent_orders_svc
from ..services import ip_leases, relay_routing
from ..services import payments as payments_svc
from ..services import subscriptions as subs_svc
from ..services.allocator import NoCapacityError
from ..services.announcements import (
    AnnouncementError,
    cancel_announcement,
    create_announcement,
    queue_announcement,
)
from ..services.browser_sessions import issue_browser_session, set_browser_session_cookies
from ..services.catalog import ProductUnavailableError, get_catalog
from ..services.domain_verification import (
    DomainVerificationResult,
    DomainVerifier,
    ResolverFailureError,
    ResolverUnavailableError,
    get_domain_verifier,
)
from ..services.health import readiness_status
from ..services.notification_email import (
    cancel_pending_notification_email_deliveries,
    clear_notification_email,
    store_notification_email,
)
from ..services.nwc_credentials import (
    clear_nwc_credential,
    decrypt_nwc_credential,
    nwc_capabilities,
    nwc_encryption,
    store_nwc_credential,
)
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    account_identifier,
    enforce_direct_rate_limit,
    enforce_rate_limit,
    spec_for,
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
    try:
        enforce_direct_rate_limit(request, spec_for(RateLimitScope.SIGNUP))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={"Retry-After": str(error.retry_after)},
        ) from error
    display, normalized = tokens.generate_token()
    hashed = tokens.hash_token(normalized)
    user = User(display_token=None, hashed_token=hashed)
    session.add(user)
    try:
        session.flush()
        issued = issue_browser_session(session, user, "token")
        session.commit()
        session.refresh(user)
    except ValueError:
        session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable") from None
    set_browser_session_cookies(response, request, issued)
    return SignupResponse(token=display, user_id=user.id or 0)


def _sub_to_response(
    sub: Subscription,
    *,
    session: Session | None = None,
    upgrade_source_public_id: UUID | None = None,
) -> SubscriptionResponse:
    challenge_name = None
    challenge_value = None
    record_type = None
    record_name = None
    record_target = None
    if (
        sub.relay_hostname_scope == RelayHostnameScope.WILDCARD
        and sub.status == SubscriptionStatus.PENDING
        and not sub.domain_is_managed
        and sub.domain
        and sub.domain_verification_token
        and sub.relay_pool_domain
    ):
        challenge_name = subs_svc.domain_challenge_name(sub.domain)
        challenge_value = subs_svc.domain_challenge_value(sub.domain_verification_token)
        record_type = "CNAME"
        record_name = subs_svc.wildcard_route_name(sub.domain)
        record_target = sub.relay_pool_domain
    elif (
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
    port_edges = (
        relay_routing.port_edges(sub.assigned_ip)
        if sub.product == ProductType.PORT and sub.assigned_ip
        else []
    )
    return SubscriptionResponse(
        id=sub.public_id,
        product=sub.product,
        delivery=sub.delivery,
        status=sub.status,
        assigned_ip=sub.assigned_ip,
        assigned_port=sub.assigned_port,
        port_hostname=(
            relay_routing.port_hostname(sub.public_id) if sub.product == ProductType.PORT else None
        ),
        port_ips=[edge.ip for edge in port_edges],
        transport=sub.transport,
        domain=sub.domain,
        relay_pool_domain=sub.relay_pool_domain,
        relay_hostname_scope=sub.relay_hostname_scope,
        tls_passthrough_only=sub.relay_hostname_scope == RelayHostnameScope.WILDCARD,
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
        upgrade_from_subscription_id=(
            upgrade_source_public_id
            or (
                source.public_id
                if session is not None
                and sub.upgrade_from_subscription_id is not None
                and (source := session.get(Subscription, sub.upgrade_from_subscription_id))
                is not None
                else None
            )
        ),
        upgrade_credit_sats=sub.upgrade_credit_sats,
        upgrade_source_period_end=sub.upgrade_source_period_end,
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
        subscriptions=[_sub_to_response(s, session=session) for s in subs],
    )


def _nwc_status(user: User) -> NwcStatusResponse:
    return NwcStatusResponse(
        has_nwc=user.has_nwc,
        capabilities=nwc_capabilities(user),
        encryption=cast(Literal["nip44_v2", "nip04"] | None, nwc_encryption(user)),
        last_validated_at=user.nwc_last_validated_at,
    )


_NWC_RESPONSE_HEADERS = {"Cache-Control": "no-store"}


class NwcBudgetResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    state: Literal["available", "unlimited", "unsupported"]
    used_budget_msats: int | None = Field(default=None, ge=0, le=9_007_199_254_740_991)
    total_budget_msats: int | None = Field(default=None, ge=0, le=9_007_199_254_740_991)
    renews_at: int | None = Field(default=None, ge=0, le=253_402_300_799)
    renewal_period: Literal["daily", "weekly", "monthly", "yearly", "never"] | None = None

    @model_validator(mode="after")
    def validate_state(self):
        amounts = self.used_budget_msats is not None and self.total_budget_msats is not None
        if self.state == "available":
            if (
                not amounts
                or self.used_budget_msats > self.total_budget_msats
                or self.renewal_period is None
            ):
                raise ValueError("available budget requires valid amounts and renewal period")
            if self.renewal_period == "never" and self.renews_at is not None:
                raise ValueError("non-renewing budget has a renewal time")
        elif self.used_budget_msats is not None or self.total_budget_msats is not None:
            raise ValueError("non-finite budget includes amounts")
        elif self.renews_at is not None or self.renewal_period is not None:
            raise ValueError("non-finite budget includes renewal details")
        return self


def _locked_nwc_user(session: Session, user: User) -> User:
    if user.id is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "account is unavailable",
            headers=_NWC_RESPONSE_HEADERS,
        )
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
            headers=_NWC_RESPONSE_HEADERS,
        )
    return locked


@router.get("/me/nwc", response_model=NwcStatusResponse)
def get_nwc_status(
    response: Response,
    user: User = Depends(current_user),
) -> NwcStatusResponse:
    response.headers.update(_NWC_RESPONSE_HEADERS)
    return _nwc_status(user)


@router.get("/me/nwc/budget", response_model=NwcBudgetResponse)
async def get_nwc_budget(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NwcBudgetResponse:
    response.headers.update(_NWC_RESPONSE_HEADERS)
    try:
        _enforce_public_rate_limit(
            session,
            RateLimitScope.PAYMENT_CREATE,
            account_identifier(user.id or 0),
        )
    except HTTPException as error:
        error.headers = {**(error.headers or {}), **_NWC_RESPONSE_HEADERS}
        raise
    try:
        nwc_uri = decrypt_nwc_credential(user)
    except CredentialError as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "wallet connection is unavailable",
            headers=_NWC_RESPONSE_HEADERS,
        ) from error
    try:
        budget = await run_in_threadpool(get_nwc_adapter().get_budget, nwc_uri)
    except NwcAdapterError as error:
        response_status = (
            status.HTTP_502_BAD_GATEWAY
            if error.retryable
            or error.code
            in {
                "internal",
                "invalid_request",
                "invalid_wallet_response",
                "protocol",
                "response_too_large",
            }
            else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(
            response_status,
            str(error),
            headers=_NWC_RESPONSE_HEADERS,
        ) from error
    try:
        return NwcBudgetResponse(
            state=cast(Literal["available", "unlimited", "unsupported"], budget.state.value),
            used_budget_msats=budget.used_budget_msats,
            total_budget_msats=budget.total_budget_msats,
            renews_at=budget.renews_at,
            renewal_period=cast(
                Literal["daily", "weekly", "monthly", "yearly", "never"] | None,
                budget.renewal_period,
            ),
        )
    except ValidationError as error:
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "wallet adapter returned an invalid budget",
            headers=_NWC_RESPONSE_HEADERS,
        ) from error


@router.post("/me/nwc", response_model=NwcStatusResponse)
async def set_nwc(
    response: Response,
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NwcStatusResponse:
    response.headers.update(_NWC_RESPONSE_HEADERS)
    try:
        payments_svc.require_payment_method_enabled(PaymentMethod.NWC)
    except payments_svc.DisabledPaymentMethodError as e:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            str(e),
            headers=_NWC_RESPONSE_HEADERS,
        ) from e
    try:
        _enforce_public_rate_limit(
            session,
            RateLimitScope.PAYMENT_CREATE,
            account_identifier(user.id or 0),
        )
    except HTTPException as error:
        error.headers = {**(error.headers or {}), **_NWC_RESPONSE_HEADERS}
        raise
    try:
        content_type = request.headers.get("Content-Type", "").partition(";")[0].strip().lower()
        if content_type != "application/json" and not (
            content_type.startswith("application/") and content_type.endswith("+json")
        ):
            raise ValueError("invalid content type")
        encoded = bytearray()
        async for chunk in request.stream():
            if len(encoded) + len(chunk) > 16_384:
                raise ValueError("request body is too large")
            encoded.extend(chunk)
        body = SetNwcRequest.model_validate(json.loads(encoded))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, ValidationError):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "wallet connection request is invalid",
            headers=_NWC_RESPONSE_HEADERS,
        ) from None
    nwc_uri = body.nwc_uri.strip()
    if not nwc_uri or len(nwc_uri) > 4096:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "wallet connection URI is invalid",
            headers=_NWC_RESPONSE_HEADERS,
        )
    try:
        validation = await run_in_threadpool(get_nwc_adapter().validate_connection, nwc_uri)
    except NwcAdapterError as error:
        response_status = (
            status.HTTP_502_BAD_GATEWAY if error.retryable else status.HTTP_400_BAD_REQUEST
        )
        raise HTTPException(
            response_status,
            str(error),
            headers=_NWC_RESPONSE_HEADERS,
        ) from error
    user = _locked_nwc_user(session, user)
    subscription = None
    if body.auto_renew_subscription_id is not None:
        subscription = session.exec(
            select(Subscription)
            .where(
                Subscription.public_id == body.auto_renew_subscription_id,
                Subscription.user_id == user.id,
                Subscription.status != SubscriptionStatus.CANCELLED,
            )
            .with_for_update()
        ).first()
        if subscription is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                "subscription not found",
                headers=_NWC_RESPONSE_HEADERS,
            )
        try:
            subs_svc.require_product_billing_term(
                subscription.product,
                subscription.delivery,
                subscription.billing_term,
            )
        except ValueError as error:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                str(error),
                headers=_NWC_RESPONSE_HEADERS,
            ) from error
    if (
        len(validation.encryptions) != 1
        or validation.encryptions[0] not in {"nip44_v2", "nip04"}
        or (validation.encryptions[0] == "nip04" and not settings.NWC_ALLOW_LEGACY_NIP04)
    ):
        raise HTTPException(
            status.HTTP_502_BAD_GATEWAY,
            "wallet adapter returned an invalid encryption",
            headers=_NWC_RESPONSE_HEADERS,
        )
    try:
        store_nwc_credential(
            user,
            nwc_uri,
            validation.capabilities,
            validation.encryptions[0],
        )
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "wallet credential encryption is unavailable",
            headers=_NWC_RESPONSE_HEADERS,
        ) from error
    session.add(user)
    if subscription is not None:
        subscription.auto_renew = True
        session.add(subscription)
    session.commit()
    session.refresh(user)
    return _nwc_status(user)


@router.delete("/me/nwc", response_model=NwcStatusResponse)
def clear_nwc(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NwcStatusResponse:
    response.headers.update(_NWC_RESPONSE_HEADERS)
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


def _locked_notification_email_user(session: Session, user: User) -> User:
    if user.id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable")
    return session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()


def _notification_email_enabled() -> bool:
    return settings.REMINDER_EMAIL_ENABLED or settings.ANNOUNCEMENT_EMAIL_ENABLED


async def _read_notification_email_request(request: Request) -> NotificationEmailRequest:
    content_type = request.headers.get("Content-Type", "").partition(";")[0].strip().lower()
    if content_type != "application/json":
        raise ValueError("invalid content type")
    encoded = bytearray()
    async for chunk in request.stream():
        encoded.extend(chunk)
        if len(encoded) > 1024:
            raise ValueError("request body is too large")
    return NotificationEmailRequest.model_validate(json.loads(encoded))


async def _set_notification_email(
    request: Request, user: User, session: Session
) -> NotificationEmailStatusResponse:
    try:
        validated = await _read_notification_email_request(request)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, ValidationError) as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "notification email address is invalid",
            headers={"Cache-Control": "no-store"},
        ) from error
    user = _locked_notification_email_user(session, user)
    try:
        cancel_pending_notification_email_deliveries(session, user)
        store_notification_email(user, validated.email)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "notification email address is invalid",
            headers={"Cache-Control": "no-store"},
        ) from error
    except CredentialError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "notification email encryption is unavailable",
            headers={"Cache-Control": "no-store"},
        ) from error
    session.add(user)
    session.commit()
    session.refresh(user)
    return NotificationEmailStatusResponse(configured=user.has_notification_email)


def _delete_notification_email(user: User, session: Session) -> NotificationEmailStatusResponse:
    user = _locked_notification_email_user(session, user)
    clear_notification_email(user)
    cancel_pending_notification_email_deliveries(session, user)
    session.add(user)
    session.commit()
    session.refresh(user)
    return NotificationEmailStatusResponse(configured=user.has_notification_email)


@router.get("/me/notification-email", response_model=NotificationEmailStatusResponse)
def get_notification_email_status(
    response: Response, user: User = Depends(current_user)
) -> NotificationEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not _notification_email_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    return NotificationEmailStatusResponse(configured=user.has_notification_email)


@router.post("/me/notification-email", response_model=NotificationEmailStatusResponse)
async def set_notification_email(
    response: Response,
    request: Request,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NotificationEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not _notification_email_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    _enforce_public_rate_limit(
        session, RateLimitScope.PAYMENT_CREATE, account_identifier(user.id or 0)
    )
    return await _set_notification_email(request, user, session)


@router.delete("/me/notification-email", response_model=NotificationEmailStatusResponse)
def delete_notification_email(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> NotificationEmailStatusResponse:
    response.headers["Cache-Control"] = "no-store"
    if not _notification_email_enabled():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    _enforce_public_rate_limit(
        session, RateLimitScope.PAYMENT_CREATE, account_identifier(user.id or 0)
    )
    return _delete_notification_email(user, session)


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
    user: User = Depends(current_bearer_user),
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
                relay_hostname_scope=body.relay_hostname_scope,
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
        subscription=_sub_to_response(result.subscription, session=session),
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
            relay_hostname_scope=body.relay_hostname_scope,
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
    return _sub_to_response(sub, session=session)


@router.post(
    "/subscriptions/{source_public_id}/wildcard-upgrade",
    response_model=SubscriptionResponse,
)
def create_wildcard_upgrade(
    source_public_id: UUID,
    body: CreateWildcardUpgradeRequest,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> SubscriptionResponse:
    source = session.exec(
        select(Subscription).where(
            Subscription.public_id == source_public_id,
            Subscription.user_id == user.id,
        )
    ).first()
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    try:
        target = subs_svc.create_wildcard_upgrade(session, user, source, body.billing_term)
    except subs_svc.AccountLimitError as error:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, str(error)) from error
    except (ProductUnavailableError, NoCapacityError) as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _sub_to_response(
        target,
        session=session,
        upgrade_source_public_id=source.public_id,
    )


@router.get("/subscriptions", response_model=list[SubscriptionResponse])
def list_subscriptions(
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[SubscriptionResponse]:
    subs_svc.reap_expired_domain_claims(session)
    rows = session.exec(select(Subscription).where(Subscription.user_id == user.id)).all()
    subs_svc.expire_elapsed_subscriptions(session, rows)
    return [_sub_to_response(s, session=session) for s in rows]


@router.delete("/subscriptions/{public_id}", response_model=SubscriptionResponse)
def cancel_subscription(
    public_id: UUID,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> SubscriptionResponse:
    sub = session.exec(
        select(Subscription).where(
            Subscription.public_id == public_id,
            Subscription.user_id == user.id,
        )
    ).first()
    if sub is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    try:
        cancelled = subs_svc.cancel_pending_subscription(session, sub)
    except subs_svc.SubscriptionCancellationConflict as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except payments_svc.PaymentProviderError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(error)) from error
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _sub_to_response(cancelled, session=session)


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
        subscription=_sub_to_response(sub, session=session),
    )


@router.post("/subscriptions/{public_id}/auto-renew")
def toggle_auto_renew(
    public_id: UUID,
    enable: bool,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> dict:
    if user.id is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable")
    user = session.exec(
        select(User)
        .where(User.id == user.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    sub = session.exec(
        select(Subscription)
        .where(
            Subscription.public_id == public_id,
            Subscription.user_id == user.id,
        )
        .with_for_update()
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
    if enable:
        try:
            subs_svc.require_product_billing_term(sub.product, sub.delivery, sub.billing_term)
        except ValueError as error:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    if enable and subs_svc.has_pending_upgrade(session, sub):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "subscription has a pending wildcard upgrade"
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
    stablecoin_checkout_url = payments_svc.stablecoin_checkout_url(p)
    standard_period_days = subs_svc.billing_period_days(p.billing_term)
    stablecoin_minimum_topup_sats = 0
    if p.method == PaymentMethod.STABLECOIN_SWAP and not (
        p.service_price_sats == 0 and p.stablecoin_surcharge_sats == 0
    ):
        stablecoin_minimum_topup_sats = p.markup_sats - p.stablecoin_surcharge_sats
    return PaymentResponse(
        id=p.id or 0,
        subscription_id=subscription.public_id,
        method=p.method,
        status=p.status,
        amount_sats=p.amount_sats,
        base_amount_sats=p.amount_sats - p.markup_sats,
        markup_sats=p.markup_sats,
        service_price_sats=(
            p.service_price_sats if p.service_price_sats else p.amount_sats - p.markup_sats
        ),
        discount_sats=p.discount_sats,
        standard_period_days=standard_period_days,
        bonus_days=p.period_days - standard_period_days,
        stablecoin_surcharge_sats=p.stablecoin_surcharge_sats,
        stablecoin_minimum_topup_sats=stablecoin_minimum_topup_sats,
        billing_term=p.billing_term,
        period_days=p.period_days,
        invoice=p.invoice,
        payment_hash=p.payment_hash,
        lightning_uri=lightning_uri,
        qr_svg=qr_svg,
        stablecoin_provider=p.stablecoin_provider,
        stablecoin_checkout_url=stablecoin_checkout_url,
        stablecoin_asset=p.stablecoin_asset,
        nwc_state=p.nwc_state,
        nwc_attempt_count=p.nwc_attempt_count,
        nwc_error_code=p.nwc_error_code,
        expires_at=p.expires_at,
    )


@router.post(
    "/payments",
    response_model=PaymentResponse,
    responses={status.HTTP_409_CONFLICT: {"model": PaymentConflictResponse}},
)
def create_payment(
    body: CreatePaymentRequest,
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
    verifier_factory: Callable[[], DomainVerifier] = Depends(_domain_verifier_dependency),
) -> PaymentResponse | JSONResponse:
    response.headers["Cache-Control"] = "no-store"
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
        and (sub.domain_verified_at is None or subs_svc.requires_domain_renewal_verification(sub))
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
    except payments_svc.OpenPaymentConflictError as e:
        conflict = PaymentConflictResponse(
            detail=str(e),
            existing_payment=_payment_to_response(e.payment, sub),
        )
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=conflict.model_dump(mode="json"),
            headers={"Cache-Control": "no-store"},
        )
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


def _require_announcement_email_enabled() -> None:
    if not settings.ANNOUNCEMENT_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")


def _announcement_delivery_counts(
    session: Session, announcement: Announcement
) -> dict[AnnouncementDeliveryState, int]:
    announcement_id = announcement.id or 0
    counts = {
        delivery_state: int(count)
        for delivery_state, count in session.exec(
            select(AnnouncementDelivery.state, func.count())
            .where(AnnouncementDelivery.announcement_id == announcement_id)
            .group_by(AnnouncementDelivery.state)
        ).all()
    }
    for delivery_state, count in session.exec(
        select(NotificationDelivery.state, func.count())
        .where(NotificationDelivery.announcement_id == announcement_id)
        .group_by(NotificationDelivery.state)
    ).all():
        counts[delivery_state] = counts.get(delivery_state, 0) + int(count)
    if announcement.state == AnnouncementState.QUEUED and not announcement.expansion_complete:
        unexpanded = max(0, announcement.recipient_count - sum(counts.values()))
        counts[AnnouncementDeliveryState.QUEUED] = (
            counts.get(AnnouncementDeliveryState.QUEUED, 0) + unexpanded
        )
    return counts


def _announcement_summary(
    session: Session, announcement: Announcement
) -> AnnouncementSummaryResponse:
    return AnnouncementSummaryResponse(
        id=announcement.id or 0,
        state=announcement.state,
        subject=announcement.subject,
        author_marker=announcement.author_marker,
        recipient_count=announcement.recipient_count,
        created_at=announcement.created_at,
        queued_at=announcement.queued_at,
        completed_at=announcement.completed_at,
        cancelled_at=announcement.cancelled_at,
        delivery_counts=_announcement_delivery_counts(session, announcement),
    )


def _announcement_detail(
    session: Session, announcement: Announcement
) -> AnnouncementDetailResponse:
    return AnnouncementDetailResponse(
        **_announcement_summary(session, announcement).model_dump(),
        body=announcement.body,
    )


def _announcement_or_404(session: Session, announcement_id: int) -> Announcement:
    announcement = session.get(Announcement, announcement_id)
    if announcement is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "announcement not found")
    return announcement


@router.get("/admin/announcements", response_model=list[AnnouncementSummaryResponse])
def list_announcements(
    response: Response,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> list[AnnouncementSummaryResponse]:
    response.headers["Cache-Control"] = "no-store"
    _require_announcement_email_enabled()
    announcements = session.exec(
        select(Announcement).order_by(Announcement.created_at.desc())
    ).all()
    return [_announcement_summary(session, announcement) for announcement in announcements]


@router.get("/admin/announcements/{announcement_id}", response_model=AnnouncementDetailResponse)
def get_announcement(
    announcement_id: int,
    response: Response,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AnnouncementDetailResponse:
    response.headers["Cache-Control"] = "no-store"
    _require_announcement_email_enabled()
    return _announcement_detail(session, _announcement_or_404(session, announcement_id))


@router.post(
    "/admin/announcements",
    response_model=AnnouncementDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_service_announcement(
    body: CreateAnnouncementRequest,
    response: Response,
    admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AnnouncementDetailResponse:
    response.headers["Cache-Control"] = "no-store"
    _require_announcement_email_enabled()
    try:
        announcement = create_announcement(session, body.subject, body.body, admin.audience)
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _announcement_detail(session, announcement)


@router.post(
    "/admin/announcements/{announcement_id}/queue",
    response_model=AnnouncementDetailResponse,
)
def queue_service_announcement(
    announcement_id: int,
    response: Response,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AnnouncementDetailResponse:
    response.headers["Cache-Control"] = "no-store"
    _require_announcement_email_enabled()
    _announcement_or_404(session, announcement_id)
    try:
        announcement = queue_announcement(session, announcement_id)
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _announcement_detail(session, announcement)


@router.post(
    "/admin/announcements/{announcement_id}/cancel",
    response_model=AnnouncementDetailResponse,
)
def cancel_service_announcement(
    announcement_id: int,
    response: Response,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> AnnouncementDetailResponse:
    response.headers["Cache-Control"] = "no-store"
    _require_announcement_email_enabled()
    _announcement_or_404(session, announcement_id)
    try:
        announcement = cancel_announcement(session, announcement_id)
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _announcement_detail(session, announcement)


def _set_account_suspension(
    user_id: int,
    suspended: bool,
    session: Session,
) -> AccountStatusResponse:
    target = session.exec(
        select(User)
        .where(User.id == user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    target.is_suspended = suspended
    session.add(target)
    if suspended and target.id is not None:
        ip_leases.revoke_smtp_for_user(session, target.id, reason="account suspended")
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
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> PaymentResponse:
    response.headers["Cache-Control"] = "no-store"
    p = session.get(Payment, payment_id)
    if not p:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    sub = session.get(Subscription, p.subscription_id)
    if not sub or sub.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "payment not found")
    # Lazy settle on read for LND-backed payment methods.
    try:
        p = payments_svc.check_and_settle_payment(session, p)
    except payments_svc.DisabledPaymentMethodError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    except payments_svc.PaymentProviderError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    return _payment_to_response(p, sub)


@router.get("/payments", response_model=list[PaymentResponse])
def list_open_payments(
    response: Response,
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> list[PaymentResponse]:
    response.headers["Cache-Control"] = "no-store"
    rows = session.exec(
        select(Payment)
        .join(Subscription)
        .where(
            Subscription.user_id == user.id,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
        .order_by(Payment.id.desc())  # type: ignore[union-attr]
    ).all()
    responses: list[PaymentResponse] = []
    for payment in rows:
        try:
            payment = payments_svc.check_and_settle_payment(session, payment)
        except payments_svc.DisabledPaymentMethodError:
            continue
        except payments_svc.PaymentProviderError as error:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(error)) from error
        if payment.status not in (PaymentStatus.PENDING, PaymentStatus.PROCESSING):
            continue
        subscription = session.get(Subscription, payment.subscription_id)
        if subscription is not None and subscription.user_id == user.id:
            responses.append(_payment_to_response(payment, subscription))
    return responses


# ---- client provisioning --------------------------------------------------


@router.get("/client/version", response_model=ClientVersionResponse)
def client_version(_: User = Depends(current_bearer_user)) -> ClientVersionResponse:
    """Return the operator-configured agent release for update notifications."""
    return ClientVersionResponse(version=settings.BLINDPORTD_VERSION)


_RELAY_ASSIGNMENTS_CAPABILITY = "relay-assignments-v1"


@router.get(
    "/client/config",
    response_model=list[RelayProvisioningResponse],
    response_model_exclude_unset=True,
)
def client_config(
    user: User = Depends(current_bearer_user),
    session: Session = Depends(get_session),
    blindport_agent_capabilities: str = Header(default="", alias="Blindport-Agent-Capabilities"),
) -> list[RelayProvisioningResponse]:
    """Returned to the Linux daemon. Lists relay endpoints + resource bindings
    for every active subscription the user has.
    """
    subs_svc.reap_expired_domain_claims(session)
    out: list[RelayProvisioningResponse] = []
    agent_capabilities = {
        capability.strip()
        for capability in blindport_agent_capabilities.split(",")
        if capability.strip()
    }
    supports_relay_assignments = _RELAY_ASSIGNMENTS_CAPABILITY in agent_capabilities
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
        if s.product == ProductType.RELAY and s.relay_hostname_scope == RelayHostnameScope.WILDCARD:
            continue
        relay_assignments = []
        if s.product == ProductType.RELAY:
            relay_endpoints = settings.relay_control_urls_list
        elif s.product == ProductType.PORT and s.assigned_ip:
            relay_assignments = relay_routing.port_edges(s.assigned_ip)
            # Older agents must keep using the canonical claim on the primary edge.
            relay_endpoints = [settings.RELAY_CONTROL_URL]
        elif s.product == ProductType.IP and s.assigned_ip:
            relay_assignments = [relay_routing.framed_ip_edge(s.assigned_ip)]
            relay_endpoints = [relay_assignments[0].endpoint]
        else:
            relay_endpoints = [settings.RELAY_CONTROL_URL]
        response = RelayProvisioningResponse(
            relay_endpoint=relay_endpoints[0],
            relay_endpoints=relay_endpoints,
            assigned_ip=s.assigned_ip,
            assigned_port=s.assigned_port,
            transport=s.transport,
            domain=s.domain,
            product=s.product,
            subscription_id=s.public_id,
        )
        if supports_relay_assignments:
            response.relay_assignments = [
                RelayAssignmentResponse(relay_endpoint=edge.endpoint, assigned_ip=edge.ip)
                for edge in relay_assignments
            ]
        out.append(response)
    return out


@router.get("/client/cert", response_model=ClientCertResponse)
def client_cert(
    response: Response,
    user: User = Depends(current_bearer_user),
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
