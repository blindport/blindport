"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from . import __version__
from .adapters.factory import get_lightning_adapter, get_nwc_adapter
from .api import internal, pages, passkeys, v1, v2, v3
from .config import settings
from .core.models import PaymentMethod
from .db import prepare_database
from .services.bandwidth import run_bandwidth_cleanup
from .services.browser_sessions import SESSION_COOKIE
from .services.btc_usd_price import run_btc_usd_price_refresh
from .services.dns_supervision import run_dns_supervisor
from .services.notification_reconciliation import (
    notification_reconciler_health,
    run_notification_reconciler,
)
from .services.payment_reconciliation import reconciler_health, run_payment_reconciler
from .services.rate_limits import DirectRateLimiter
from .services.reminder_reconciliation import get_smtp_adapter

PASSKEY_POST_BODY_LIMIT = 256 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_lightning_adapter()
    notifications_enabled = settings.NOTIFICATION_RECONCILIATION_ENABLED and (
        settings.REMINDER_EMAIL_ENABLED or settings.ANNOUNCEMENT_EMAIL_ENABLED
    )
    if notifications_enabled:
        get_smtp_adapter()
    if settings.is_payment_method_enabled(PaymentMethod.NWC):
        get_nwc_adapter()
    prepare_database()
    reconciler_health.configure(
        enabled=settings.PAYMENT_RECONCILIATION_ENABLED,
        startup_grace_seconds=settings.PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS,
        stale_after_seconds=settings.PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS,
    )
    notification_reconciler_health.configure(
        enabled=notifications_enabled,
        startup_grace_seconds=settings.NOTIFICATION_RECONCILIATION_STARTUP_GRACE_SECONDS,
        stale_after_seconds=settings.NOTIFICATION_RECONCILIATION_STALE_AFTER_SECONDS,
    )
    stop_reconciler = asyncio.Event()
    reconciler_task: asyncio.Task[None] | None = None
    if settings.PAYMENT_RECONCILIATION_ENABLED:
        reconciler_task = asyncio.create_task(
            run_payment_reconciler(stop_reconciler),
            name="payment-reconciler",
        )
    app.state.payment_reconciler_task = reconciler_task
    notification_stop_event = asyncio.Event()
    notification_task: asyncio.Task[None] | None = None
    if notifications_enabled:
        notification_task = asyncio.create_task(
            run_notification_reconciler(notification_stop_event),
            name="notification-reconciler",
        )
    app.state.notification_reconciler_task = notification_task
    price_stop_event = asyncio.Event()
    price_task: asyncio.Task[None] | None = None
    if settings.BTC_USD_PRICE_ENABLED:
        price_task = asyncio.create_task(
            run_btc_usd_price_refresh(price_stop_event),
            name="btc-usd-price-refresh",
        )
    app.state.btc_usd_price_task = price_task
    dns_stop_event = asyncio.Event()
    dns_task: asyncio.Task[None] | None = None
    if settings.DNS_SUPERVISION_ENABLED:
        dns_task = asyncio.create_task(run_dns_supervisor(dns_stop_event), name="dns-supervisor")
    app.state.dns_supervisor_task = dns_task
    bandwidth_stop_event = asyncio.Event()
    bandwidth_task: asyncio.Task[None] | None = None
    if settings.BANDWIDTH_METRICS_ENABLED:
        bandwidth_task = asyncio.create_task(
            run_bandwidth_cleanup(bandwidth_stop_event), name="bandwidth-cleanup"
        )
    app.state.bandwidth_cleanup_task = bandwidth_task
    logger.info("Blindport backend ready")
    try:
        yield
    finally:
        if notification_task is not None:
            notification_stop_event.set()
            try:
                await notification_task
            except asyncio.CancelledError:
                notification_task.cancel()
                raise
        if dns_task is not None:
            dns_stop_event.set()
            await dns_task
        if bandwidth_task is not None:
            bandwidth_stop_event.set()
            await bandwidth_task
        if price_task is not None:
            price_stop_event.set()
            await price_task
        if reconciler_task is not None:
            stop_reconciler.set()
            try:
                await reconciler_task
            except asyncio.CancelledError:
                reconciler_task.cancel()
                raise


def create_app() -> FastAPI:
    app = FastAPI(title=settings.BRAND_NAME, version=__version__, lifespan=lifespan)
    app.state.direct_rate_limiter = DirectRateLimiter(settings.RATE_LIMIT_MAX_BUCKETS)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if _is_limited_passkey_post(request) and not await _cache_bounded_body(request):
            response = JSONResponse(
                status_code=413,
                content={"detail": "request body too large"},
            )
            _set_security_headers(request, response)
            return response
        response = await call_next(request)
        _set_security_headers(request, response)
        return response

    def _set_security_headers(request: Request, response: Response) -> None:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), publickey-credentials-get=(self)"
        )
        if (
            request.url.path.startswith("/api/v1/passkeys")
            or request.url.path.startswith("/api/v1/browser-session")
            or (request.url.path.startswith("/api/") and SESSION_COOKIE in request.cookies)
        ):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        if settings.ENVIRONMENT.value == "production" and not (
            settings.ONION_HOST and request.url.hostname == settings.ONION_HOST
        ):
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if (
            settings.ONION_HOST
            and request.url.hostname != settings.ONION_HOST
            and response.headers.get("content-type", "").lower().startswith("text/html")
        ):
            path_and_query = request.url.path
            if request.url.query:
                path_and_query += f"?{request.url.query}"
            response.headers["Onion-Location"] = f"http://{settings.ONION_HOST}{path_and_query}"

    def _is_limited_passkey_post(request: Request) -> bool:
        return request.method == "POST" and request.url.path.startswith("/api/v1/passkeys/")

    async def _cache_bounded_body(request: Request) -> bool:
        body = bytearray()
        async for chunk in request.stream():
            if len(chunk) > PASSKEY_POST_BODY_LIMIT - len(body):
                return False
            body.extend(chunk)
        request._body = bytes(body)
        return True

    pkg_dir = Path(__file__).parent

    @app.api_route("/release-key.asc", methods=["GET", "HEAD"], include_in_schema=False)
    def release_key() -> FileResponse:
        return FileResponse(
            pkg_dir / "public" / "blindport-release-key.asc",
            media_type="application/pgp-keys",
            filename="blindport-release-key.asc",
            headers={"Cache-Control": "public, max-age=3600, must-revalidate"},
        )

    pages.init_templates(str(pkg_dir / "templates"))
    app.mount("/static", StaticFiles(directory=str(pkg_dir / "static")), name="static")

    app.include_router(v1.router)
    app.include_router(v2.router)
    app.include_router(v3.router)
    app.include_router(passkeys.router)
    app.include_router(internal.legacy_router)
    app.include_router(internal.router)
    app.include_router(internal.v2_router)
    app.include_router(internal.v3_router)
    app.include_router(pages.router)
    return app


app = create_app()
