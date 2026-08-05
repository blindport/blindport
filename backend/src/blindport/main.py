"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger

from . import __version__
from .adapters.factory import get_lightning_adapter, get_nwc_adapter
from .api import internal, pages, v1, v2
from .config import settings
from .core.models import PaymentMethod
from .db import prepare_database
from .services.btc_usd_price import run_btc_usd_price_refresh
from .services.payment_reconciliation import reconciler_health, run_payment_reconciler
from .services.rate_limits import DirectRateLimiter
from .services.reminder_reconciliation import get_smtp_adapter


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_lightning_adapter()
    if settings.REMINDER_EMAIL_ENABLED:
        get_smtp_adapter()
    if settings.is_payment_method_enabled(PaymentMethod.NWC):
        get_nwc_adapter()
    prepare_database()
    reconciler_health.configure(
        enabled=settings.PAYMENT_RECONCILIATION_ENABLED,
        startup_grace_seconds=settings.PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS,
        stale_after_seconds=settings.PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS,
    )
    stop_reconciler = asyncio.Event()
    reconciler_task: asyncio.Task[None] | None = None
    if settings.PAYMENT_RECONCILIATION_ENABLED:
        reconciler_task = asyncio.create_task(
            run_payment_reconciler(stop_reconciler),
            name="payment-reconciler",
        )
    app.state.payment_reconciler_task = reconciler_task
    price_stop_event = asyncio.Event()
    price_task: asyncio.Task[None] | None = None
    if settings.BTC_USD_PRICE_ENABLED:
        price_task = asyncio.create_task(
            run_btc_usd_price_refresh(price_stop_event),
            name="btc-usd-price-refresh",
        )
    app.state.btc_usd_price_task = price_task
    logger.info("Blindport backend ready")
    try:
        yield
    finally:
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
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
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
        return response

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
    app.include_router(internal.router)
    app.include_router(internal.v2_router)
    app.include_router(pages.router)
    return app


app = create_app()
