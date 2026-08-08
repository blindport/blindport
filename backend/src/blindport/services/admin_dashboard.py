"""Read-only aggregates for the browser administrator operations summary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ..config import settings
from ..core.models import (
    DnsObservation,
    Payment,
    PaymentStatus,
    RelayHeartbeat,
    Subscription,
    SubscriptionStatus,
    User,
)
from .catalog import get_catalog


@dataclass(frozen=True, slots=True)
class ProductCapacity:
    """Catalog capacity rendered without exposing assignment details."""

    product: str
    availability: str
    detail: str
    sales_state: str


@dataclass(frozen=True, slots=True)
class RelayOperationsState:
    edge_id: str
    endpoint: str
    state: str
    age: str | None
    active_tunnels: int | None
    active_streams: int | None


@dataclass(frozen=True, slots=True)
class DnsOperationsState:
    hostname: str
    state: str
    expected_ips: str
    observed_ips: str | None
    age: str | None


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
    ever_paying_customers: int
    active_paying_customers: int
    lapsed_paying_customers: int
    new_paying_customers_30d: int
    active_relay_tunnels: int
    active_relay_streams: int
    relay_edges: tuple[RelayOperationsState, ...]
    dns_targets: tuple[DnsOperationsState, ...]
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


def _relay_state(heartbeat: RelayHeartbeat | None, current: datetime) -> str:
    if heartbeat is None:
        return "never"
    if _utc_datetime(heartbeat.received_at) < current - timedelta(
        seconds=settings.RELAY_HEARTBEAT_STALE_SECONDS
    ):
        return "stale"
    if (
        not heartbeat.ready
        or heartbeat.authorization == "unavailable"
        or heartbeat.certificate == "unavailable"
        or heartbeat.listeners == "unavailable"
        or heartbeat.wireguard == "unavailable"
    ):
        return "unavailable"
    if (
        heartbeat.authorization in {"degraded", "starting"}
        or heartbeat.lifecycle == "draining"
        or heartbeat.wireguard == "starting"
    ):
        return "degraded"
    return "healthy"


def _relay_rows(session: Session, current: datetime) -> tuple[RelayOperationsState, ...]:
    heartbeats = {row.edge_id: row for row in session.exec(select(RelayHeartbeat)).all()}
    rows: list[RelayOperationsState] = []
    for edge in settings.relay_edges_list:
        heartbeat = heartbeats.get(edge.id)
        state = _relay_state(heartbeat, current)
        rows.append(
            RelayOperationsState(
                edge_id=edge.id,
                endpoint=edge.endpoint,
                state=state,
                age=_format_age(current - _utc_datetime(heartbeat.received_at))
                if heartbeat
                else None,
                active_tunnels=heartbeat.active_tunnels if heartbeat and state != "stale" else None,
                active_streams=heartbeat.active_streams if heartbeat and state != "stale" else None,
            )
        )
    return tuple(rows)


def _dns_rows(session: Session, current: datetime) -> tuple[DnsOperationsState, ...]:
    observations = {row.hostname: row for row in session.exec(select(DnsObservation)).all()}
    rows: list[DnsOperationsState] = []
    for target in settings.dns_supervision_targets_list:
        observation = observations.get(target.hostname)
        if observation is None:
            state = "never"
        elif _utc_datetime(observation.checked_at) < current - timedelta(
            seconds=settings.DNS_SUPERVISION_STALE_SECONDS
        ):
            state = "stale"
        elif observation.healthy:
            state = "healthy"
        else:
            state = "unavailable"
        rows.append(
            DnsOperationsState(
                hostname=target.hostname,
                state=state,
                expected_ips=", ".join(target.expected_ips),
                observed_ips=(observation.observed_ips.replace(",", ", ") if observation else None),
                age=(
                    _format_age(current - _utc_datetime(observation.checked_at))
                    if observation
                    else None
                ),
            )
        )
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
    ever_paid_users = (
        select(Subscription.user_id.label("user_id"))
        .select_from(Payment)
        .join(Subscription)
        .join(User)
        .where(customer, Payment.status == PaymentStatus.PAID)
        .distinct()
        .subquery()
    )
    ever_paying_customers = _scalar_count(
        session, select(func.count()).select_from(ever_paid_users)
    )
    active_paying_customers = _scalar_count(
        session,
        select(func.count(func.distinct(ever_paid_users.c.user_id)))
        .select_from(ever_paid_users)
        .join(Subscription, Subscription.user_id == ever_paid_users.c.user_id)
        .where(Subscription.status == SubscriptionStatus.ACTIVE),
    )
    first_paid_users = (
        select(
            Subscription.user_id.label("user_id"), func.min(Payment.paid_at).label("first_paid_at")
        )
        .select_from(Payment)
        .join(Subscription)
        .join(User)
        .where(customer, Payment.status == PaymentStatus.PAID, Payment.paid_at.is_not(None))
        .group_by(Subscription.user_id)
        .subquery()
    )
    new_paying_customers_30d = _scalar_count(
        session,
        select(func.count())
        .select_from(first_paid_users)
        .where(first_paid_users.c.first_paid_at >= current - timedelta(days=30)),
    )
    relay_edges = _relay_rows(session, current)
    fresh_relay_edges = [row for row in relay_edges if row.state not in {"stale", "never"}]
    return OperationsSummary(
        active_subscriptions=active_subscriptions,
        active_customers=active_customers,
        settled_gross_sats=settled_gross_sats,
        open_payments=int(open_payments or 0),
        oldest_open_payment_age=oldest_open_payment_age,
        active_accounts_24h=active_accounts_24h,
        active_accounts_7d=active_accounts_7d,
        ever_paying_customers=ever_paying_customers,
        active_paying_customers=active_paying_customers,
        lapsed_paying_customers=ever_paying_customers - active_paying_customers,
        new_paying_customers_30d=new_paying_customers_30d,
        active_relay_tunnels=sum(row.active_tunnels or 0 for row in fresh_relay_edges),
        active_relay_streams=sum(row.active_streams or 0 for row in fresh_relay_edges),
        relay_edges=relay_edges,
        dns_targets=_dns_rows(session, current),
        capacities=_capacity_rows(session),
    )
