"""Dependency checks used by backend readiness probes."""

from __future__ import annotations

from sqlalchemy import text

from ..adapters.factory import get_lightning_adapter
from ..config import EnvironmentMode, settings
from ..core.models import PaymentMethod
from ..db import engine
from ..migrations import database_revisions
from .payment_reconciliation import reconciler_health

_OK = "ok"
_UNAVAILABLE = "unavailable"


def readiness_status() -> tuple[bool, dict[str, str]]:
    """Check required dependencies without returning provider error details."""
    components: dict[str, str] = {}

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1")).scalar_one()
        components["database"] = _OK
    except Exception:
        components["database"] = _UNAVAILABLE

    try:
        current, head = database_revisions(engine)
        components["migrations"] = _OK if current == head else _UNAVAILABLE
    except Exception:
        components["migrations"] = _UNAVAILABLE

    if any(
        settings.is_payment_method_enabled(method)
        for method in (PaymentMethod.LIGHTNING, PaymentMethod.STABLECOIN_SWAP)
    ):
        try:
            healthy = get_lightning_adapter().health()
            components["lightning"] = _OK if healthy else _UNAVAILABLE
        except Exception:
            components["lightning"] = _UNAVAILABLE
    else:
        components["lightning"] = "disabled"

    if (
        settings.ENVIRONMENT == EnvironmentMode.PRODUCTION
        or settings.PAYMENT_RECONCILIATION_ENABLED
    ):
        components["reconciler"] = reconciler_health.status()

    ready = all(status != _UNAVAILABLE for status in components.values())
    return ready, components
