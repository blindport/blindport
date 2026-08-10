"""Server-rendered landing page + admin panel."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from datetime import UTC, datetime
from math import ceil
from uuid import UUID

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func
from sqlmodel import Session, select

from ..config import DEFAULT_BRAND_NAME, DEFAULT_BRAND_TAGLINE, settings
from ..core import tokens
from ..core.auth import (
    create_admin_browser_session,
    is_exact_admin_token,
    optional_browser_session,
    validate_admin_browser_session,
)
from ..core.models import (
    Announcement,
    AnnouncementDelivery,
    AnnouncementDeliveryState,
    AnnouncementState,
    DeliveryMode,
    IPLease,
    IPLeaseState,
    NotificationDelivery,
    Payment,
    PaymentMethod,
    ProductType,
    RelaySubscriptionConnection,
    ReminderDelivery,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..db import get_session
from ..services import ip_leases
from ..services import subscriptions as subs_svc
from ..services.admin_dashboard import build_operations_summary, build_subscription_rows
from ..services.announcements import (
    AnnouncementError,
    cancel_announcement,
    create_announcement,
    eligible_recipient_count,
    queue_announcement,
)
from ..services.browser_sessions import (
    LEGACY_TOKEN_COOKIE,
    LOGIN_CSRF_COOKIE,
    SESSION_COOKIE,
    clear_browser_session_cookies,
    clear_login_csrf_cookie,
    generate_login_csrf_token,
    issue_browser_session,
    revoke_browser_session,
    set_browser_session_cookies,
    set_login_csrf_cookie,
    valid_login_csrf,
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
_LEGACY_ADMIN_COOKIE = "blindport_admin"

templates: Jinja2Templates | None = None


@dataclass(frozen=True, slots=True)
class _PageWindow:
    page: int
    page_size: int
    total_items: int
    total_pages: int
    start: int
    end: int

    @property
    def has_previous(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


def _page_window(requested_page: int, page_size: int, total_items: int) -> _PageWindow:
    total_pages = max(1, ceil(total_items / page_size))
    page = min(requested_page, total_pages)
    offset = (page - 1) * page_size
    return _PageWindow(
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
        start=offset + 1 if total_items else 0,
        end=min(offset + page_size, total_items),
    )


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
        "ip_price": None,
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
        "notification_email_enabled": (
            settings.REMINDER_EMAIL_ENABLED or settings.ANNOUNCEMENT_EMAIL_ENABLED
        ),
        "reminder_email_enabled": settings.REMINDER_EMAIL_ENABLED,
        "announcement_email_enabled": settings.ANNOUNCEMENT_EMAIL_ENABLED,
        "smtp_egress_fee_sats": settings.WIREGUARD_SMTP_EGRESS_FEE_SATS,
        "request_origin_shell": shlex.quote(request_origin),
        "request_origin_json": json.dumps(request_origin),
        "backend_flag_shell": backend_flag_shell,
        "install_script_url_shell": shlex.quote(f"{request_origin}/downloads/install.sh"),
        "passkeys_enabled": settings.PASSKEYS_ENABLED and not _is_onion_request(request),
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
    login_csrf_token = generate_login_csrf_token()
    response = templates.TemplateResponse(
        request,
        template_name,
        _ctx(request, invalid_credentials=True, login_csrf_token=login_csrf_token),
        status_code=status.HTTP_401_UNAUTHORIZED,
    )
    response.headers["Cache-Control"] = "no-store"
    set_login_csrf_cookie(response, request, login_csrf_token)
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
    assert templates is not None
    resolved = optional_browser_session(request, session)
    issued = None
    browser_session = None
    if resolved is not None:
        browser_session, user = resolved
    else:
        user = _get_user_by_token(session, request.cookies.get(LEGACY_TOKEN_COOKIE, ""))
        if user is not None:
            try:
                issued = issue_browser_session(session, user, "token")
                session.commit()
            except ValueError:
                session.rollback()
                user = None
    if user is None:
        login_csrf_token = generate_login_csrf_token()
        response = templates.TemplateResponse(
            request,
            "login.html",
            _ctx(request, login_csrf_token=login_csrf_token),
        )
        clear_browser_session_cookies(response, request)
        set_login_csrf_cookie(response, request, login_csrf_token)
        return response
    if issued is not None:
        browser_session = issued.model
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
            browser_auth_method=browser_session.auth_method if browser_session is not None else "",
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
                json.dumps(
                    {
                        "version": 3,
                        "accounts": [
                            {
                                "name": "default",
                                "token_file": "/home/replace-me/.config/blindport/accounts/default.token",
                                "state_dir": "/home/replace-me/.local/state/blindport/accounts/default",
                                "mappings": client_mappings,
                            }
                        ],
                    },
                    indent=2,
                )
                if client_mappings
                else ""
            ),
            catalog=catalog,
            catalog_by_product={p.product.value: p for p in catalog.products},
            port_hostname_suffix=settings.PORT_HOSTNAME_SUFFIX,
            port_ha_ips=[edge.ip for edge in settings.port_ha_edges_list],
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    if issued is not None:
        set_browser_session_cookies(response, request, issued)
    return response


@router.post("/login")
def login(
    request: Request,
    token: str = Form(...),
    login_csrf_token: str = Form(default="", max_length=128),
    session: Session = Depends(get_session),
) -> Response:
    if not valid_login_csrf(request.cookies.get(LOGIN_CSRF_COOKIE), login_csrf_token):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "login CSRF validation failed",
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    _enforce_login_rate_limit(request, session, RateLimitScope.BROWSER_LOGIN)

    is_admin = is_exact_admin_token(token)
    user = _get_user_by_token(session, token)
    if is_admin:
        return _invalid_login(request, "login.html")
    if user is not None:
        response = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        try:
            issued = issue_browser_session(session, user, "token")
            session.commit()
        except ValueError:
            session.rollback()
        else:
            _clear_admin_session(response, request)
            _clear_legacy_admin_session(response, request)
            clear_login_csrf_cookie(response, request)
            set_browser_session_cookies(response, request, issued)
            return response
    return _invalid_login(request, "login.html")


@router.get("/admin", response_class=HTMLResponse)
def admin_panel(
    request: Request,
    account_page: int = Query(1, ge=1),
    payment_page: int = Query(1, ge=1),
    lease_page: int = Query(1, ge=1),
    reminder_page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=25, le=100),
    session: Session = Depends(get_session),
) -> HTMLResponse:
    assert templates is not None
    admin_cookie = request.cookies.get(_ADMIN_SESSION_COOKIE, "")
    if not validate_admin_browser_session(admin_cookie):
        response = templates.TemplateResponse(request, "admin_login.html", _ctx(request))
        response.headers["Cache-Control"] = "no-store"
        _clear_legacy_admin_session(response, request)
        return response
    if page_size not in {25, 50, 100}:
        page_size = 25
    customer = User.is_admin.is_(False)  # type: ignore[union-attr]
    subs_svc.reap_expired_domain_claims(session)
    elapsed_subscriptions = session.exec(
        select(Subscription)
        .join(User)
        .where(
            customer,
            Subscription.status == SubscriptionStatus.ACTIVE,
            Subscription.current_period_end <= datetime.now(UTC),  # type: ignore[operator]
        )
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, elapsed_subscriptions)

    account_total = int(
        session.exec(select(func.count()).select_from(User).where(customer)).one() or 0
    )
    account_pagination = _page_window(account_page, page_size, account_total)
    account_offset = (account_pagination.page - 1) * page_size
    users = session.exec(
        select(User)
        .where(customer)
        .order_by(User.created_at.desc(), User.id.desc())
        .offset(account_offset)
        .limit(page_size)
    ).all()
    user_ids = [user.id for user in users if user.id is not None]
    subs = (
        session.exec(
            select(Subscription)
            .where(Subscription.user_id.in_(user_ids))  # type: ignore[union-attr]
            .order_by(Subscription.updated_at.desc())
        ).all()
        if user_ids
        else []
    )
    subscription_ids = [subscription.id for subscription in subs if subscription.id is not None]
    latest_payment_ids = (
        select(func.max(Payment.id))
        .where(Payment.subscription_id.in_(subscription_ids))  # type: ignore[union-attr]
        .group_by(Payment.subscription_id)
    )
    subscription_payments = (
        session.exec(
            select(Payment).where(Payment.id.in_(latest_payment_ids))  # type: ignore[union-attr]
        ).all()
        if subscription_ids
        else []
    )
    subscription_connections = (
        session.exec(
            select(RelaySubscriptionConnection).where(
                RelaySubscriptionConnection.subscription_id.in_(subscription_ids)  # type: ignore[union-attr]
            )
        ).all()
        if subscription_ids
        else []
    )

    payment_total = int(
        session.exec(
            select(func.count()).select_from(Payment).join(Subscription).join(User).where(customer)
        ).one()
        or 0
    )
    payment_pagination = _page_window(payment_page, page_size, payment_total)
    payment_offset = (payment_pagination.page - 1) * page_size
    payment_rows = session.exec(
        select(Payment, Subscription.public_id, User.public_id)
        .select_from(Payment)
        .join(Subscription, Payment.subscription_id == Subscription.id)
        .join(User, Subscription.user_id == User.id)
        .where(customer)
        .order_by(Payment.created_at.desc(), Payment.id.desc())
        .offset(payment_offset)
        .limit(page_size)
    ).all()

    reminder_total = int(
        session.exec(
            select(func.count())
            .select_from(ReminderDelivery)
            .join(Subscription)
            .join(User)
            .where(customer)
        ).one()
        or 0
    )
    reminder_pagination = _page_window(reminder_page, page_size, reminder_total)
    reminder_offset = (reminder_pagination.page - 1) * page_size
    reminder_rows = session.exec(
        select(ReminderDelivery, Subscription.public_id)
        .select_from(ReminderDelivery)
        .join(Subscription, ReminderDelivery.subscription_id == Subscription.id)
        .join(User, Subscription.user_id == User.id)
        .where(customer)
        .order_by(ReminderDelivery.updated_at.desc(), ReminderDelivery.id.desc())
        .offset(reminder_offset)
        .limit(page_size)
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
    for announcement in announcements:
        counts = announcement_delivery_counts.setdefault(announcement.id, {})
        for state, count in session.exec(
            select(NotificationDelivery.state, func.count())
            .where(NotificationDelivery.announcement_id == announcement.id)
            .group_by(NotificationDelivery.state)
        ).all():
            counts[state.value] = counts.get(state.value, 0) + count
        if announcement.state == AnnouncementState.QUEUED and not announcement.expansion_complete:
            unexpanded = max(0, announcement.recipient_count - sum(counts.values()))
            counts[AnnouncementDeliveryState.QUEUED.value] = (
                counts.get(AnnouncementDeliveryState.QUEUED.value, 0) + unexpanded
            )
    lease_total = int(
        session.exec(
            select(func.count()).select_from(IPLease).join(Subscription).join(User).where(customer)
        ).one()
        or 0
    )
    lease_pagination = _page_window(lease_page, page_size, lease_total)
    lease_offset = (lease_pagination.page - 1) * page_size
    lease_rows = session.exec(
        select(IPLease, Subscription.public_id)
        .select_from(IPLease)
        .join(Subscription, IPLease.subscription_id == Subscription.id)
        .join(User, Subscription.user_id == User.id)
        .where(customer)
        .order_by(IPLease.created_at.desc(), IPLease.id.desc())
        .offset(lease_offset)
        .limit(page_size)
    ).all()
    response = templates.TemplateResponse(
        request,
        "admin.html",
        _ctx(
            request,
            subscription_rows=build_subscription_rows(
                users, subs, subscription_payments, subscription_connections
            ),
            payment_rows=payment_rows,
            reminder_rows=reminder_rows,
            announcements=announcements,
            announcement_delivery_counts=announcement_delivery_counts,
            announcement_eligible_count=(
                eligible_recipient_count(session) if settings.ANNOUNCEMENT_EMAIL_ENABLED else 0
            ),
            lease_rows=lease_rows,
            operations=build_operations_summary(session),
            account_pagination=account_pagination,
            payment_pagination=payment_pagination,
            lease_pagination=lease_pagination,
            reminder_pagination=reminder_pagination,
            page_size=page_size,
            page_size_options=(25, 50, 100),
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
    revoke_browser_session(session, request.cookies.get(SESSION_COOKIE, ""))
    clear_browser_session_cookies(resp, request)
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
