"""Public REST API endpoints versioned at /api/v2."""

from __future__ import annotations

from datetime import UTC, date, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlmodel import Session, select

from ..config import settings
from ..core import tokens
from ..core.auth import AdminPrincipal, current_admin, current_bearer_user, current_user
from ..core.models import (
    ClientCredential,
    DeliveryMode,
    IPLease,
    ProductType,
    RelayHostnameScope,
    Subscription,
    SubscriptionDailyBandwidth,
    SubscriptionStatus,
    User,
)
from ..core.schemas import (
    AccountMeResponse,
    AccountSignupResponse,
    AnonymousOrderRequest,
    AnonymousOrderResponse,
    ClientCertificateRequest,
    ClientCertificateResponse,
    OfflineEntitlementClaimResponse,
    OfflineEntitlementConfigResponse,
    OfflineEntitlementEdgeResponse,
    OfflineEntitlementProvisioningResponse,
    PublicAccountStatusResponse,
    SMTPApprovalRequest,
    SMTPLeaseResponse,
    SMTPRevocationRequest,
    SubscriptionBandwidthDayResponse,
    SubscriptionBandwidthResponse,
    WireGuardConfigResponse,
    WireGuardKeyRequest,
)
from ..db import get_session
from ..services import ip_leases, relay_routing
from ..services import subscriptions as subs_svc
from ..services.allocator import NoCapacityError
from ..services.browser_sessions import issue_browser_session, set_browser_session_cookies
from ..services.catalog import ProductUnavailableError
from ..services.client_enrollment import (
    ClientEnrollmentConflictError,
    enroll_client_certificate,
)
from ..services.offline_entitlements import (
    OfflineEntitlementError,
    OfflineEntitlementSigner,
    claim_for_subscription,
    deterministic_entitlement_jti,
    enrolled_client_public_key,
    entitlement_issued_at,
    issue_subscription_entitlement,
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


def _canonical_instance_id(value: str) -> str:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "instance_id must be a canonical UUID"
        ) from error
    if str(parsed) != value:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "instance_id must be a canonical UUID"
        )
    return value


def _smtp_response(lease: IPLease, subscription: Subscription) -> SMTPLeaseResponse:
    return SMTPLeaseResponse(
        lease_id=lease.public_id,
        subscription_id=subscription.public_id,
        address=lease.address,
        state=lease.state,
        smtp_enabled=lease.smtp_enabled,
        intended_use=lease.smtp_intended_use,
        fee_paid_sats=lease.smtp_fee_paid_sats,
        reviewed_at=lease.smtp_reviewed_at,
        reviewed_by=lease.smtp_reviewed_by,
        review_reference=lease.smtp_review_reference,
        revoked_at=lease.smtp_revoked_at,
        revocation_reason=lease.smtp_revocation_reason,
    )


def _active_routed_subscription(session: Session, public_id: UUID) -> Subscription:
    subscription = session.exec(
        select(Subscription).where(Subscription.public_id == public_id)
    ).one_or_none()
    if subscription is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "subscription not found")
    account = session.exec(
        select(User)
        .where(User.id == subscription.user_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    subscription = session.exec(
        select(Subscription)
        .where(Subscription.id == subscription.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    subs_svc.expire_elapsed_subscriptions(session, [subscription])
    if (
        account.is_suspended
        or account.is_admin
        or subscription.product != ProductType.IP
        or subscription.delivery != DeliveryMode.WIREGUARD
        or subscription.status != SubscriptionStatus.ACTIVE
    ):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "subscription is not an active routed Blindport IP"
        )
    return subscription


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
    try:
        session.flush()
        issued = issue_browser_session(session, user, "token")
        session.commit()
        session.refresh(user)
    except ValueError:
        session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "account is unavailable") from None
    set_browser_session_cookies(response, request, issued)
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


@router.get(
    "/subscriptions/{public_id}/bandwidth",
    response_model=SubscriptionBandwidthResponse,
)
def subscription_bandwidth(
    public_id: UUID,
    response: Response,
    from_day: date | None = Query(default=None, alias="from"),
    to_day: date | None = Query(default=None, alias="to"),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> SubscriptionBandwidthResponse:
    """Return one owner's aggregate daily bandwidth without relay-level identifiers."""
    response.headers["Cache-Control"] = "no-store"
    if not settings.BANDWIDTH_METRICS_ENABLED:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "not found",
            headers={"Cache-Control": "no-store"},
        )
    today = datetime.now(UTC).date()
    end = to_day or today
    start = from_day or (end - timedelta(days=29))
    if start > end or (end - start).days > 365:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid bandwidth date range")
    subscription = session.exec(
        select(Subscription).where(
            Subscription.public_id == public_id,
            Subscription.user_id == user.id,
        )
    ).one_or_none()
    if subscription is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "subscription not found",
            headers={"Cache-Control": "no-store"},
        )
    if subscription.id is None:  # pragma: no cover, persisted rows always have an ID.
        raise RuntimeError("subscription has no internal ID")
    rows = session.exec(
        select(SubscriptionDailyBandwidth)
        .where(
            SubscriptionDailyBandwidth.subscription_id == subscription.id,
            SubscriptionDailyBandwidth.day >= start,
            SubscriptionDailyBandwidth.day <= end,
        )
        .order_by(SubscriptionDailyBandwidth.day)
    ).all()
    return SubscriptionBandwidthResponse(
        subscription_id=subscription.public_id,
        from_day=start,
        to_day=end,
        rows=[
            SubscriptionBandwidthDayResponse(
                day=row.day,
                ingress_bytes=str(row.ingress_bytes),
                egress_bytes=str(row.egress_bytes),
            )
            for row in rows
        ],
    )


def _set_account_suspension(
    account_id: UUID,
    suspended: bool,
    session: Session,
) -> PublicAccountStatusResponse:
    target = session.exec(
        select(User)
        .where(User.public_id == account_id)
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
    "/admin/subscriptions/{subscription_id}/smtp-egress/approve",
    response_model=SMTPLeaseResponse,
)
def approve_smtp_egress(
    subscription_id: UUID,
    body: SMTPApprovalRequest,
    admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> SMTPLeaseResponse:
    subscription = _active_routed_subscription(session, subscription_id)
    try:
        lease = ip_leases.approve_smtp(
            session,
            subscription,
            intended_use=body.intended_use,
            fee_paid_sats=body.fee_paid_sats,
            review_reference=body.review_reference,
            reviewed_by=admin.audience,
        )
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _smtp_response(lease, subscription)


@router.post(
    "/admin/subscriptions/{subscription_id}/smtp-egress/revoke",
    response_model=SMTPLeaseResponse,
)
def revoke_smtp_egress(
    subscription_id: UUID,
    body: SMTPRevocationRequest,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> SMTPLeaseResponse:
    subscription = _active_routed_subscription(session, subscription_id)
    try:
        lease = ip_leases.revoke_smtp(session, subscription, reason=body.reason)
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    return _smtp_response(lease, subscription)


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
            relay_hostname_scope=body.relay_hostname_scope,
            transport=body.transport,
            delivery=body.delivery,
            billing_term=body.billing_term,
            commit=False,
            reap_domains=False,
        )
        issued = issue_browser_session(session, user, "token")
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
    set_browser_session_cookies(response, request, issued)
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
    user: User = Depends(current_bearer_user),
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


@router.get("/client/config", response_model=OfflineEntitlementConfigResponse)
def offline_client_config(
    response: Response,
    instance_id: str = Query(min_length=36, max_length=36),
    user: User = Depends(current_bearer_user),
    session: Session = Depends(get_session),
) -> OfflineEntitlementConfigResponse:
    """Return v2 framed provisioning with one edge-scoped signed entitlement per claim."""
    response.headers["Cache-Control"] = "no-store"
    if not settings.OFFLINE_ENTITLEMENTS_ENABLED:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "not found",
            headers={"Cache-Control": "no-store"},
        )
    instance_id = _canonical_instance_id(instance_id)
    credential = session.exec(
        select(ClientCredential)
        .where(
            ClientCredential.user_id == user.id,
            ClientCredential.instance_id == instance_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if credential is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "client credential is not enrolled for instance",
            headers={"Cache-Control": "no-store"},
        )
    try:
        client_pk = enrolled_client_public_key(credential, user, instance_id)
    except OfflineEntitlementError as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            str(error),
            headers={"Cache-Control": "no-store"},
        ) from error
    try:
        signer = OfflineEntitlementSigner.from_private_key_file(
            settings.OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE,
            settings.OFFLINE_ENTITLEMENT_KEY_ID,
            settings.OFFLINE_ENTITLEMENT_GRACE_SECONDS,
        )
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "offline entitlement signer unavailable",
            headers={"Cache-Control": "no-store"},
        ) from error
    subs_svc.reap_expired_domain_claims(session)
    subscriptions = session.exec(
        select(Subscription)
        .where(
            Subscription.user_id == user.id,
            Subscription.status == SubscriptionStatus.ACTIVE,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, subscriptions)
    edge_by_endpoint = {edge.endpoint: edge for edge in settings.relay_edges_list}
    rows: list[OfflineEntitlementProvisioningResponse] = []
    for subscription in subscriptions:
        if subscription.status != SubscriptionStatus.ACTIVE:
            continue
        if (
            subscription.product == ProductType.RELAY
            and subscription.relay_hostname_scope == RelayHostnameScope.WILDCARD
        ):
            continue
        if (
            subscription.product == ProductType.IP
            and subscription.delivery == DeliveryMode.WIREGUARD
        ):
            continue
        if subscription.product == ProductType.PORT and subscription.assigned_ip:
            raw_edges = relay_routing.port_edges(subscription.assigned_ip)
        elif subscription.product == ProductType.IP and subscription.assigned_ip:
            raw_edges = [relay_routing.framed_ip_edge(subscription.assigned_ip)]
        elif subscription.product == ProductType.RELAY:
            raw_edges = [
                relay_routing.RelayEdge(endpoint=edge.endpoint, ip="")
                for edge in settings.relay_edges_list
            ]
        else:
            continue
        edges: list[OfflineEntitlementEdgeResponse] = []
        for raw_edge in raw_edges:
            edge = edge_by_endpoint.get(raw_edge.endpoint)
            if edge is None:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "offline edge map is unavailable",
                    headers={"Cache-Control": "no-store"},
                )
            try:
                claim = claim_for_subscription(
                    subscription,
                    account=user.public_id,
                    instance=UUID(instance_id),
                    client_pk=client_pk,
                    edge=edge,
                    relay_edge=raw_edge,
                )
                jti = deterministic_entitlement_jti(claim, credential.generation)
                entitlement, signed_claim = issue_subscription_entitlement(
                    signer,
                    subscription,
                    account=user.public_id,
                    instance=UUID(instance_id),
                    client_pk=client_pk,
                    edge=edge,
                    relay_edge=raw_edge,
                    credential_generation=credential.generation,
                    now=entitlement_issued_at(subscription, credential, now=datetime.now(UTC)),
                    jti_factory=lambda jti=jti: jti,
                    return_payload=True,
                )
            except OfflineEntitlementError as error:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    str(error),
                    headers={"Cache-Control": "no-store"},
                ) from error
            edges.append(
                OfflineEntitlementEdgeResponse(
                    id=edge.id,
                    endpoint=edge.endpoint,
                    claim=OfflineEntitlementClaimResponse(
                        kind=signed_claim["kind"],
                        ip=signed_claim["ip"],
                        port=signed_claim["port"],
                        transport=signed_claim["transport"],
                        domain=signed_claim["domain"],
                    ),
                    entitlement=entitlement,
                    paid_through=signed_claim["paid_through"],
                    grace_through=signed_claim["grace_through"],
                    generation=signed_claim["generation"],
                )
            )
        rows.append(
            OfflineEntitlementProvisioningResponse(
                assigned_ip=subscription.assigned_ip,
                assigned_port=subscription.assigned_port,
                transport=subscription.transport,
                domain=subscription.domain,
                product=subscription.product,
                subscription_id=subscription.public_id,
                edges=edges,
            )
        )
    return OfflineEntitlementConfigResponse(subscriptions=rows)


@router.get("/client/wireguard", response_model=WireGuardConfigResponse)
def wireguard_config(
    response: Response,
    user: User = Depends(current_bearer_user),
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
    user: User = Depends(current_bearer_user),
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
