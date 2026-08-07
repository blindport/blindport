"""Read-only aggregates for the browser administrator operations summary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ..core.models import Payment, PaymentStatus, Subscription, SubscriptionStatus, User
from .catalog import get_catalog


@dataclass(frozen=True, slots=True)
class ProductCapacity:
    """Catalog capacity rendered without exposing assignment details."""

    product: str
    availability: str
    detail: str
    sales_state: str


@dataclass(frozen=True, slots=True)
class OperationsSummary:
    """Authoritative aggregate values available from the current database model."""

    active_subscriptions: int
    active_customers: int
    settled_gross_sats: int
    open_payments: int
    oldest_open_payment_age: str | None
    active_accounts_24h: int
    active_accounts_7d: int
    capacities: tuple[ProductCapacity, ...]


def _scalar_count(session: Session, statement) -> int:
    return int(session.exec(statement).one() or 0)


def _utc_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _format_age(value: timedelta) -> str:
    seconds = max(0, int(value.total_seconds()))
    days, seconds = divmod(seconds, 86_400)
    hours, seconds = divmod(seconds, 3_600)
    minutes = seconds // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _capacity_rows(session: Session) -> tuple[ProductCapacity, ...]:
    rows: list[ProductCapacity] = []
    for catalog_product in get_catalog(session).products:
        capacity = catalog_product.capacity
        product = catalog_product.product.value
        if product == "ip":
            availability = f"{capacity.available or 0} of {capacity.total or 0} addresses available"
            detail = (
                f"Framed {capacity.framed_available or 0}, "
                f"WireGuard {capacity.wireguard_available or 0}"
            )
        elif product == "port":
            availability = f"{capacity.available or 0} of {capacity.total or 0} mappings available"
            detail = f"TCP {capacity.tcp_available or 0}, UDP {capacity.udp_available or 0}"
        else:
            availability = (
                f"{capacity.managed_domains_available or 0} of "
                f"{capacity.total or 0} managed names available"
            )
            detail = (
                "Customer domains available"
                if capacity.customer_domains_available
                else "Customer domains unavailable"
            )
        if not catalog_product.enabled:
            sales_state = "Disabled"
        elif catalog_product.sales_paused:
            sales_state = "Sales paused"
        elif catalog_product.sold_out:
            sales_state = "Sold out"
        else:
            sales_state = "Available"
        rows.append(ProductCapacity(product, availability, detail, sales_state))
    return tuple(rows)


def build_operations_summary(
    session: Session,
    *,
    now: datetime | None = None,
) -> OperationsSummary:
    """Aggregate customer operations without reading detail tables into memory."""
    current = _utc_datetime(now or datetime.now(UTC))
    customer = User.is_admin.is_(False)  # type: ignore[union-attr]
    active_subscription = Subscription.status == SubscriptionStatus.ACTIVE

    active_subscriptions = _scalar_count(
        session,
        select(func.count())
        .select_from(Subscription)
        .join(User)
        .where(customer, active_subscription),
    )
    active_customers = _scalar_count(
        session,
        select(func.count(func.distinct(Subscription.user_id)))
        .select_from(Subscription)
        .join(User)
        .where(customer, active_subscription),
    )
    settled_gross_sats = int(
        session.exec(
            select(func.coalesce(func.sum(Payment.amount_sats), 0))
            .select_from(Payment)
            .join(Subscription)
            .join(User)
            .where(customer, Payment.status == PaymentStatus.PAID)
        ).one()
        or 0
    )
    open_payments, oldest_open_payment = session.exec(
        select(func.count(), func.min(Payment.created_at))
        .select_from(Payment)
        .join(Subscription)
        .join(User)
        .where(
            customer,
            Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
        )
    ).one()
    oldest_open_payment_age = (
        _format_age(current - _utc_datetime(oldest_open_payment))
        if oldest_open_payment is not None
        else None
    )
    active_accounts_24h = _scalar_count(
        session,
        select(func.count())
        .select_from(User)
        .where(customer, User.last_seen_at >= current - timedelta(hours=24)),  # type: ignore[operator]
    )
    active_accounts_7d = _scalar_count(
        session,
        select(func.count())
        .select_from(User)
        .where(customer, User.last_seen_at >= current - timedelta(days=7)),  # type: ignore[operator]
    )
    return OperationsSummary(
        active_subscriptions=active_subscriptions,
        active_customers=active_customers,
        settled_gross_sats=settled_gross_sats,
        open_payments=int(open_payments or 0),
        oldest_open_payment_age=oldest_open_payment_age,
        active_accounts_24h=active_accounts_24h,
        active_accounts_7d=active_accounts_7d,
        capacities=_capacity_rows(session),
    )
