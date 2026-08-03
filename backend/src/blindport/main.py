"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from loguru import logger
from sqlmodel import select

from .adapters.factory import get_lightning_adapter, get_nwc_adapter
from .api import internal, pages, v1, v2
from .config import settings
from .core import tokens
from .core.models import PaymentMethod, User
from .db import prepare_database, session_scope
from .services.payment_reconciliation import reconciler_health, run_payment_reconciler
from .services.reminder_reconciliation import get_lnemail_adapter


@asynccontextmanager
async def lifespan(app: FastAPI):
    get_lightning_adapter()
    if settings.REMINDER_EMAIL_ENABLED:
        nwc = get_nwc_adapter()
        get_lnemail_adapter()
        nwc.validate_connection(settings.LNEMAIL_ADMIN_NWC_URI)
    elif settings.is_payment_method_enabled(PaymentMethod.NWC):
        get_nwc_adapter()
    prepare_database()
    _bootstrap_admin()
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
    logger.info("Blindport backend ready")
    try:
        yield
    finally:
        if reconciler_task is not None:
            stop_reconciler.set()
            try:
                await reconciler_task
            except asyncio.CancelledError:
                reconciler_task.cancel()
                raise


def create_app() -> FastAPI:
    app = FastAPI(title=settings.BRAND_NAME, version="0.1.0", lifespan=lifespan)

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
        return response

    pkg_dir = Path(__file__).parent
    pages.init_templates(str(pkg_dir / "templates"))
    app.mount("/static", StaticFiles(directory=str(pkg_dir / "static")), name="static")

    app.include_router(v1.router)
    app.include_router(v2.router)
    app.include_router(internal.router)
    app.include_router(internal.v2_router)
    app.include_router(pages.router)
    return app


def _bootstrap_admin() -> None:
    """Ensure the configured ADMIN_TOKEN corresponds to an is_admin=True user.

    This makes the static admin token usable as a normal bearer token for
    admin-only API endpoints (in addition to the cookie-based admin UI).
    """
    normalized = tokens.crockford.normalize(settings.ADMIN_TOKEN)
    hashed = tokens.hash_token(normalized)
    with session_scope() as s:
        existing = s.exec(select(User).where(User.hashed_token == hashed)).first()
        if existing is None:
            s.add(User(hashed_token=hashed, is_admin=True))
            s.commit()
        elif not existing.is_admin:
            existing.is_admin = True
            s.add(existing)
            s.commit()


app = create_app()
