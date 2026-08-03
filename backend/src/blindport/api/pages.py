"""Server-rendered landing page + admin panel."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlmodel import Session, select

from ..config import settings
from ..core import tokens
from ..core.models import (
    Payment,
    PaymentMethod,
    ReminderDelivery,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..db import get_session
from ..services import subscriptions as subs_svc
from ..services.catalog import get_catalog
from ..services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    direct_client_identifier,
    enforce_rate_limit,
    spec_for,
)

router = APIRouter()

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
        select(User).where(User.hashed_token == hashed, User.is_suspended.is_(False))  # type: ignore[union-attr]
    ).first()


def _is_onion_request(request: Request) -> bool:
    return bool(settings.ONION_HOST) and request.url.hostname == settings.ONION_HOST


def _ctx(request: Request, **extra) -> dict:
    base = {
        "brand_name": settings.BRAND_NAME,
        "brand_tagline": settings.BRAND_TAGLINE,
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
        "relay_server_name": settings.RELAY_CONTROL_URL.rsplit(":", 1)[0].strip("[]"),
        "nwc_enabled": settings.is_payment_method_enabled(PaymentMethod.NWC),
        "lightning_enabled": settings.is_payment_method_enabled(PaymentMethod.LIGHTNING),
        "reminder_email_enabled": settings.REMINDER_EMAIL_ENABLED,
    }
    base.update(extra)
    return base


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
    catalog = get_catalog(session)
    response = templates.TemplateResponse(
        request,
        "dashboard.html",
        _ctx(
            request,
            user=user,
            subscriptions=subs,
            token=raw_token,
            catalog=catalog,
            catalog_by_product={p.product.value: p for p in catalog.products},
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.get("/admin", response_class=HTMLResponse)
def admin_panel(request: Request, session: Session = Depends(get_session)) -> HTMLResponse:
    assert templates is not None
    admin_cookie = request.cookies.get("blindport_admin", "")
    if not hmac.compare_digest(admin_cookie.encode("utf-8"), settings.ADMIN_TOKEN.encode("utf-8")):
        response = templates.TemplateResponse(request, "admin_login.html", _ctx(request))
        response.headers["Cache-Control"] = "no-store"
        return response
    users = session.exec(select(User)).all()
    subs_svc.reap_expired_domain_claims(session)
    subs = session.exec(select(Subscription)).all()
    subs_svc.expire_elapsed_subscriptions(session, subs)
    payments = session.exec(select(Payment)).all()
    reminders = session.exec(select(ReminderDelivery)).all()
    account_by_user_id = {user.id: user.public_id for user in users}
    subscription_by_id = {subscription.id: subscription for subscription in subs}
    account_by_payment_id = {
        payment.id: account_by_user_id.get(subscription_by_id[payment.subscription_id].user_id)
        for payment in payments
        if payment.subscription_id in subscription_by_id
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
            account_by_user_id=account_by_user_id,
            account_by_payment_id=account_by_payment_id,
            active_count=sum(1 for s in subs if s.status == SubscriptionStatus.ACTIVE),
        ),
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@router.post("/admin/login")
def admin_login(
    request: Request,
    token: str = Form(...),
    session: Session = Depends(get_session),
) -> RedirectResponse:
    try:
        enforce_rate_limit(
            session,
            spec_for(RateLimitScope.ADMIN_LOGIN),
            direct_client_identifier(request),
        )
    except RateLimitExceeded as error:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "request rate limit exceeded",
            headers={"Retry-After": str(error.retry_after)},
        ) from error
    if not hmac.compare_digest(token.encode("utf-8"), settings.ADMIN_TOKEN.encode("utf-8")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid admin token")
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie(
        "blindport_admin",
        token,
        httponly=True,
        secure=settings.ENVIRONMENT.value == "production" and not _is_onion_request(request),
        samesite="lax",
    )
    return resp


@router.post("/admin/logout")
def admin_logout(request: Request) -> RedirectResponse:
    resp = RedirectResponse(url="/admin", status_code=303)
    resp.delete_cookie(
        "blindport_admin",
        secure=settings.ENVIRONMENT.value == "production" and not _is_onion_request(request),
        httponly=True,
        samesite="lax",
    )
    return resp
