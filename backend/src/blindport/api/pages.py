"""Server-rendered landing page + admin panel."""

from __future__ import annotations

import json
import shlex
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import Session, select

from ..config import DEFAULT_BRAND_NAME, DEFAULT_BRAND_TAGLINE, settings
from ..core import tokens
from ..core.auth import (
    create_admin_browser_session,
    is_exact_admin_token,
    validate_admin_browser_session,
)
from ..core.models import (
    Announcement,
    AnnouncementDelivery,
    DeliveryMode,
    IPLease,
    IPLeaseState,
    Payment,
    PaymentMethod,
    ProductType,
    ReminderDelivery,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..db import get_session
from ..services import ip_leases
from ..services import subscriptions as subs_svc
from ..services.admin_dashboard import build_operations_summary
from ..services.announcements import (
    AnnouncementError,
    cancel_announcement,
    create_announcement,
    eligible_recipient_count,
    queue_announcement,
)
from ..services.btc_usd_price import approximate_usd, price_cache
from ..services.catalog import get_catalog
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    enforce_direct_rate_limit,
    spec_for,
)

router = APIRouter()

_ADMIN_SESSION_COOKIE = "blindport_admin_session"
_CUSTOMER_COOKIE = "blindport_token"
_LEGACY_ADMIN_COOKIE = "blindport_admin"

templates: Jinja2Templates | None = None


def init_templates(directory: str) -> None:
    global templates
    templates = Jinja2Templates(directory=directory)


def _get_user_by_token(session: Session, raw_token: str) -> User | None:
    if not raw_token:
        return None
    try:
        normalized = tokens.crockford.normalize(raw_token)
    except Exception:
        return None
    hashed = tokens.hash_token(normalized)
    return session.exec(
        select(User).where(
            User.hashed_token == hashed,
            User.is_admin.is_(False),  # type: ignore[union-attr]
            User.is_suspended.is_(False),  # type: ignore[union-attr]
        )
    ).first()


def _is_onion_request(request: Request) -> bool:
    return bool(settings.ONION_HOST) and request.url.hostname == settings.ONION_HOST


def _ctx(request: Request, **extra) -> dict:
    request_origin = f"{request.url.scheme}://{request.url.netloc}"
    backend_flag_shell = (
        ""
        if request_origin == "https://blindport.com"
        else f" -backend={shlex.quote(request_origin)}"
    )
    public_origin = (
        f"http://{settings.ONION_HOST}" if _is_onion_request(request) else settings.PUBLIC_SITE_URL
    )
    share_titles = {
        "/guide": f"Guide | {settings.BRAND_NAME}",
        "/terms": f"Service terms | {settings.BRAND_NAME}",
    }
    share_descriptions = {
        "/guide": (
            f"Install and operate {settings.BRAND_NAME} for public access to self-hosted services."
        ),
        "/terms": f"Service terms for using {settings.BRAND_NAME} public ingress.",
    }
    official_branding = (
        settings.BRAND_NAME == DEFAULT_BRAND_NAME
        and settings.BRAND_TAGLINE == DEFAULT_BRAND_TAGLINE
    )
    btc_usd_snapshot = price_cache.current()
    social_image_name = "brand-social.png" if official_branding else "brand-avatar.png"
    base = {
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
        "official_branding": official_branding,
        "page_description": share_descriptions.get(request.url.path, settings.BRAND_TAGLINE),
        "share_metadata": request.url.path in {"/", "/guide", "/terms"},
        "share_title": share_titles.get(request.url.path, settings.BRAND_NAME),
        "share_description": share_descriptions.get(request.url.path, settings.BRAND_TAGLINE),
        "page_url": f"{public_origin}{request.url.path}",
        "social_image_url": f"{public_origin}/static/{social_image_name}",
        "social_image_width": 1200 if official_branding else 512,
        "social_image_height": 630 if official_branding else 512,
        "social_image_alt": (
            "Blindport. Public reach for self-hosted services. TLS stays on your box."
            if official_branding
            else "Geometric B mark."
        ),
        "twitter_card": "summary_large_image" if official_branding else "summary",
        "ip_price": settings.IP_MONTHLY_SATS,
        "ip_yearly_price": settings.IP_YEARLY_SATS,
        "port_price": settings.PORT_MONTHLY_SATS,
        "port_yearly_price": settings.PORT_YEARLY_SATS,
        "relay_price": settings.RELAY_MONTHLY_SATS,
        "relay_yearly_price": settings.RELAY_YEARLY_SATS,
        "yearly_billing_enabled": settings.BILLING_YEARLY_ENABLED,
        "cookie_secure": settings.ENVIRONMENT.value == "production"
        and not _is_onion_request(request),
        "onion_host": settings.ONION_HOST,
        "blindportd_version": settings.BLINDPORTD_VERSION,
        "btc_usd_price": (
            str(btc_usd_snapshot.usd_per_btc) if btc_usd_snapshot is not None else ""
        ),
        "approximate_usd": approximate_usd,
        "relay_server_name": settings.RELAY_CONTROL_URL.rsplit(":", 1)[0].strip("[]"),
        "nwc_enabled": settings.is_payment_method_enabled(PaymentMethod.NWC),
        "lightning_enabled": settings.is_payment_method_enabled(PaymentMethod.LIGHTNING),
        "stablecoin_enabled": settings.is_payment_method_enabled(PaymentMethod.STABLECOIN_SWAP),
        "reminder_email_enabled": settings.REMINDER_EMAIL_ENABLED,
        "announcement_email_enabled": settings.ANNOUNCEMENT_EMAIL_ENABLED,
        "smtp_egress_fee_sats": settings.WIREGUARD_SMTP_EGRESS_FEE_SATS,
        "request_origin_shell": shlex.quote(request_origin),
        "request_origin_json": json.dumps(request_origin),
        "backend_flag_shell": backend_flag_shell,
        "install_script_url_shell": shlex.quote(f"{request_origin}/downloads/install.sh"),
    }
    base.update(extra)
    return base


def _cookie_secure(request: Request) -> bool:
    return settings.ENVIRONMENT.value == "production" and not _is_onion_request(request)


def _set_admin_session(response: Response, request: Request) -> None:
    response.set_cookie(
        _ADMIN_SESSION_COOKIE,
        create_admin_browser_session(),
        max_age=settings.ADMIN_SESSION_MAX_AGE_SECONDS,
        path="/admin",
        secure=_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )


def _clear_admin_session(response: Response, request: Request) -> None:
    response.delete_cookie(
        _ADMIN_SESSION_COOKIE,
        path="/admin",
        secure=_cookie_secure(request),
        httponly=True,
        samesite="strict",
    )


def _clear_customer_session(response: Response, request: Request) -> None:
    response.delete_cookie(
        _CUSTOMER_COOKIE,
        path="/",
        secure=_cookie_secure(request),
        samesite="lax",
    )


def _clear_legacy_admin_session(response: Response, request: Request) -> None:
    """Expire the retired root-scoped cookie that contained the raw admin token."""
    response.delete_cookie(
        _LEGACY_ADMIN_COOKIE,
        path="/",
        secure=_cookie_secure(request),
        httponly=True,
        samesite="lax",
    )


def _enforce_login_rate_limit(
    request: Request,
    session: Session,
    scope: RateLimitScope,
) -> None:
    try:
        enforce_direct_rate_limit(request, spec_for(scope))
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={"Cache-Control": "no-store", "Retry-After": str(error.retry_after)},
        ) from error


def _invalid_login(request: Request, template_name: str) -> HTMLResponse:
    assert templates is not None
    response = templates.TemplateResponse(
        request,
        template_name,
        _ctx(request, invalid_credentials=True),
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
    response.headers["Cache-Control"] = "no-store"
    _clear_legacy_admin_session(response, request)
    return response


@router.get("/", response_class=HTMLResponse)
def landing(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    assert templates is not None
    catalog = get_catalog(session)
    response = templates.TemplateResponse(
        request,
        "landing.html",
        _ctx(
            request,
            catalog=catalog,
            catalog_by_product={p.product.value: p for p in catalog.products},
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/guide", response_class=HTMLResponse)
def guide(request: Request) -> HTMLResponse:
    assert templates is not None
    response = templates.TemplateResponse(request, "guide.html", _ctx(request))
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/terms", response_class=HTMLResponse)
def terms(request: Request) -> HTMLResponse:
    assert templates is not None
    response = templates.TemplateResponse(request, "terms.html", _ctx(request))
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    """Browser dashboard. Reads token from `blindport_token` cookie (set client-side
    after signup). The cookie is the canonical browser storage of the token.
    """
    assert templates is not None
    raw_token = request.cookies.get("blindport_token", "")
    user = _get_user_by_token(session, raw_token)
    if user is None:
        response = templates.TemplateResponse(request, "login.html", _ctx(request))
        response.headers["Cache-Control"] = "no-store"
        return response
    subs_svc.reap_expired_domain_claims(session)
    subs = session.exec(select(Subscription).where(Subscription.user_id == user.id)).all()
    subs_svc.expire_elapsed_subscriptions(session, subs)
    visible_subscriptions = [
        subscription for subscription in subs if subscription.status != SubscriptionStatus.CANCELLED
    ]
    framed_subscriptions = [
        subscription
        for subscription in subs
        if subscription.delivery == DeliveryMode.FRAMED
        and subscription.status != SubscriptionStatus.CANCELLED
    ]
    wireguard_subscriptions = [
        subscription
        for subscription in subs
        if subscription.delivery == DeliveryMode.WIREGUARD
        and subscription.status != SubscriptionStatus.CANCELLED
    ]
    client_subscriptions = [
        subscription
        for subscription in framed_subscriptions
        if subscription.status == SubscriptionStatus.ACTIVE
    ]
    client_mappings: list[dict[str, str]] = []
    for subscription in client_subscriptions:
        if subscription.product == ProductType.RELAY:
            mapping = {
                "subscription_id": str(subscription.public_id),
                "upstream": "127.0.0.1:8080",
                "tls_mode": "automatic",
                "acme_terms_accepted": False,
            }
        else:
            mapping = {
                "subscription_id": str(subscription.public_id),
                "upstream": "127.0.0.1:8080",
                "tls_mode": "passthrough",
            }
        client_mappings.append(mapping)
    catalog = get_catalog(session)
    response = templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            user=user,
            subscriptions=visible_subscriptions,
            pending_subscriptions=[
                subscription
                for subscription in visible_subscriptions
                if subscription.status == SubscriptionStatus.PENDING
            ],
            active_subscriptions=[
                subscription
                for subscription in visible_subscriptions
                if subscription.status == SubscriptionStatus.ACTIVE
            ],
            framed_subscriptions=framed_subscriptions,
            client_subscriptions=client_subscriptions,
            wireguard_subscriptions=wireguard_subscriptions,
            active_wireguard_subscriptions=[
                subscription
                for subscription in wireguard_subscriptions
                if subscription.status == SubscriptionStatus.ACTIVE
            ],
            client_config_json=(
                json.dumps({"version": 2, "mappings": client_mappings}, indent=2)
                if client_mappings
                else ""
            ),
            token=raw_token,
            catalog=catalog,
            catalog_by_product={p.product.value: p for p in catalog.products},
            port_hostname_suffix=settings.PORT_HOSTNAME_SUFFIX,
            port_ha_ips=[edge.ip for edge in settings.port_ha_edges_list],
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/login")
def login(
    request: Request,
    token: str = Form(...),
    session: Session = Depends(get_session),
) -> Response:
    _enforce_login_rate_limit(request, session, RateLimitScope.BROWSER_LOGIN)

    is_admin = is_exact_admin_token(token)
    user = _get_user_by_token(session, token)
    if is_admin:
        return _invalid_login(request, "login.html")
    if user is not None:
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        _clear_admin_session(response, request)
        _clear_legacy_admin_session(response, request)
        response.set_cookie(
            _CUSTOMER_COOKIE,
            token,
            path="/",
            secure=_cookie_secure(request),
            samesite="lax",
        )
        response.headers["Cache-Control"] = "no-store"
        return response
    return _invalid_login(request, "login.html")


@router.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    assert templates is not None
    admin_cookie = request.cookies.get(_ADMIN_SESSION_COOKIE, "")
    if not validate_admin_browser_session(admin_cookie):
        response = templates.TemplateResponse(request, "admin_login.html", _ctx(request))
        response.headers["Cache-Control"] = "no-store"
        _clear_legacy_admin_session(response, request)
        return response
    users = session.exec(select(User).where(User.is_admin.is_(False))).all()  # type: ignore[union-attr]
    subs_svc.reap_expired_domain_claims(session)
    subs = session.exec(
        select(Subscription).join(User).where(User.is_admin.is_(False))  # type: ignore[union-attr]
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, subs)
    payments = session.exec(
        select(Payment).join(Subscription).join(User).where(User.is_admin.is_(False))  # type: ignore[union-attr]
    ).all()
    reminders = session.exec(
        select(ReminderDelivery).join(Subscription).join(User).where(User.is_admin.is_(False))  # type: ignore[union-attr]
    ).all()
    announcements = (
        session.exec(select(Announcement).order_by(Announcement.created_at.desc())).all()
        if settings.ANNOUNCEMENT_EMAIL_ENABLED
        else []
    )
    announcement_delivery_counts = {
        announcement.id: {
            state.value: count
            for state, count in session.exec(
                select(AnnouncementDelivery.state, func.count())
                .where(AnnouncementDelivery.announcement_id == announcement.id)
                .group_by(AnnouncementDelivery.state)
            ).all()
        }
        for announcement in announcements
    }
    leases = session.exec(
        select(IPLease)
        .join(Subscription)
        .join(User)
        .where(User.is_admin.is_(False))  # type: ignore[union-attr]
        .order_by(IPLease.created_at.desc())
    ).all()
    account_by_user_id = {user.id: user.public_id for user in users}
    subscription_by_pk = {subscription.id: subscription for subscription in subs}
    account_by_payment_id = {
        payment.id: account_by_user_id.get(subscription_by_pk[payment.subscription_id].user_id)
        for payment in payments
        if payment.subscription_id in subscription_by_pk
    }
    subscription_public_id_by_pk = {
        subscription.id: subscription.public_id for subscription in subs
    }
    response = templates.TemplateResponse(
        request,
        "admin.html",
        _ctx(
            request,
            users=users,
            subscriptions=subs,
            payments=payments,
            reminders=reminders,
            announcements=announcements,
            announcement_delivery_counts=announcement_delivery_counts,
            announcement_eligible_count=(
                eligible_recipient_count(session) if settings.ANNOUNCEMENT_EMAIL_ENABLED else 0
            ),
            leases=leases,
            account_by_user_id=account_by_user_id,
            account_by_payment_id=account_by_payment_id,
            subscription_public_id_by_pk=subscription_public_id_by_pk,
            operations=build_operations_summary(session),
            smtp_fee_sats=settings.WIREGUARD_SMTP_EGRESS_FEE_SATS,
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    _clear_legacy_admin_session(response, request)
    return response


def _set_browser_account_suspension(
    request: Request,
    account_id: UUID,
    suspended: bool,
    session: Session,
) -> RedirectResponse:
    if not validate_admin_browser_session(request.cookies.get(_ADMIN_SESSION_COOKIE, "")):
        response = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
        _clear_admin_session(response, request)
        _clear_legacy_admin_session(response, request)
        response.headers["Cache-Control"] = "no-store"
        return response
    target = session.exec(
        select(User)
        .where(
            User.public_id == account_id,
            User.is_admin.is_(False),  # type: ignore[union-attr]
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "account not found")
    target.is_suspended = suspended
    session.add(target)
    if suspended and target.id is not None:
        ip_leases.revoke_smtp_for_user(session, target.id, reason="account suspended")
    session.commit()
    response = RedirectResponse(
        url="/admin#accounts-title",
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/accounts/{account_id}/suspend")
def admin_suspend_account(
    account_id: UUID,
    request: Request,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    return _set_browser_account_suspension(request, account_id, True, session)


@router.post("/admin/accounts/{account_id}/restore")
def admin_restore_account(
    account_id: UUID,
    request: Request,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    return _set_browser_account_suspension(request, account_id, False, session)


def _admin_lease_subscription(session: Session, lease_id: UUID) -> tuple[IPLease, Subscription]:
    lease = session.exec(select(IPLease).where(IPLease.public_id == lease_id)).one_or_none()
    if lease is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "IP lease not found")
    subscription = session.get(Subscription, lease.subscription_id)
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
    lease = session.exec(
        select(IPLease)
        .where(IPLease.id == lease.id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one()
    if (
        account.is_suspended
        or account.is_admin
        or subscription.status != SubscriptionStatus.ACTIVE
        or subscription.product != ProductType.IP
        or subscription.delivery != DeliveryMode.WIREGUARD
        or lease.state != IPLeaseState.ACTIVE
        or lease.released_at is not None
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "lease is not an active routed IP lease")
    return lease, subscription


def _browser_admin_redirect(request: Request) -> RedirectResponse | None:
    if validate_admin_browser_session(request.cookies.get(_ADMIN_SESSION_COOKIE, "")):
        return None
    response = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    _clear_admin_session(response, request)
    _clear_legacy_admin_session(response, request)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/announcements")
def admin_create_announcement(
    request: Request,
    subject: str = Form(..., min_length=1, max_length=160),
    body: str = Form(..., min_length=1, max_length=10_000),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    unauthorized = _browser_admin_redirect(request)
    if unauthorized is not None:
        return unauthorized
    if not settings.ANNOUNCEMENT_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    try:
        create_announcement(session, subject, body, "blindport-admin-browser-v1")
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    response = RedirectResponse(
        url="/admin#announcements-title", status_code=status.HTTP_303_SEE_OTHER
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/announcements/{announcement_id}/queue")
def admin_queue_announcement(
    announcement_id: int,
    request: Request,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    unauthorized = _browser_admin_redirect(request)
    if unauthorized is not None:
        return unauthorized
    if not settings.ANNOUNCEMENT_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    try:
        queue_announcement(session, announcement_id)
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    response = RedirectResponse(
        url="/admin#announcements-title", status_code=status.HTTP_303_SEE_OTHER
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/announcements/{announcement_id}/cancel")
def admin_cancel_announcement(
    announcement_id: int,
    request: Request,
    session: Session = Depends(get_session),
) -> RedirectResponse:
    unauthorized = _browser_admin_redirect(request)
    if unauthorized is not None:
        return unauthorized
    if not settings.ANNOUNCEMENT_EMAIL_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    try:
        cancel_announcement(session, announcement_id)
    except AnnouncementError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    response = RedirectResponse(
        url="/admin#announcements-title", status_code=status.HTTP_303_SEE_OTHER
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/ip-leases/{lease_id}/smtp/approve")
def admin_approve_smtp(
    lease_id: UUID,
    request: Request,
    intended_use: str = Form(..., min_length=1, max_length=500),
    fee_paid_sats: int = Form(..., ge=0),
    review_reference: str = Form(..., min_length=1, max_length=200),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    unauthorized = _browser_admin_redirect(request)
    if unauthorized is not None:
        return unauthorized
    lease, subscription = _admin_lease_subscription(session, lease_id)
    try:
        ip_leases.approve_smtp(
            session,
            subscription,
            intended_use=intended_use,
            fee_paid_sats=fee_paid_sats,
            review_reference=review_reference,
            reviewed_by="blindport-admin-browser-v1",
        )
    except ValueError as error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(error)) from error
    response = RedirectResponse(url="/admin#ip-leases-title", status_code=status.HTTP_303_SEE_OTHER)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/ip-leases/{lease_id}/smtp/revoke")
def admin_revoke_smtp(
    lease_id: UUID,
    request: Request,
    reason: str = Form(..., min_length=1, max_length=255),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    unauthorized = _browser_admin_redirect(request)
    if unauthorized is not None:
        return unauthorized
    _lease, subscription = _admin_lease_subscription(session, lease_id)
    ip_leases.revoke_smtp(session, subscription, reason=reason)
    response = RedirectResponse(url="/admin#ip-leases-title", status_code=status.HTTP_303_SEE_OTHER)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/login")
def admin_login(
    request: Request,
    token: str = Form(...),
    session: Session = Depends(get_session),
) -> Response:
    _enforce_login_rate_limit(request, session, RateLimitScope.ADMIN_LOGIN)
    if not is_exact_admin_token(token):
        return _invalid_login(request, "admin_login.html")
    resp = RedirectResponse(url="/admin", status_code=303)
    _clear_customer_session(resp, request)
    _clear_legacy_admin_session(resp, request)
    _set_admin_session(resp, request)
    resp.headers["Cache-Control"] = "no-store"
    return resp


@router.post("/admin/logout")
def admin_logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse(url="/admin", status_code=303)
    _clear_admin_session(resp, request)
    _clear_legacy_admin_session(resp, request)
    resp.headers["Cache-Control"] = "no-store"
    return resp
