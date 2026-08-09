"""Read-only aggregates for the browser administrator operations summary."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func
from sqlmodel import Session, select

from ..config import settings
from ..core.models import (
    DnsObservation,
    Payment,
    PaymentStatus,
    ProductType,
    RelayHeartbeat,
    RelayHostnameScope,
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
class StatusBreakdownEntry:
    key: str
    label: str
    value: int
    percent: int


@dataclass(frozen=True, slots=True)
class ActiveProductBreakdownEntry:
    key: str
    label: str
    value: int
    percent: int


@dataclass(frozen=True, slots=True)
class WeeklyActivity:
    label: str
    new_subscriptions: int
    paid_sats: int
    subscription_percent: int
    revenue_percent: int


@dataclass(frozen=True, slots=True)
class AdminSubscriptionRow:
    """A customer-account row for the administrator subscription table."""

    account_public_id: str
    subscription_public_id: str | None
    account_suspended: bool
    product: str | None
    status_key: str
    status_label: str
    status_detail: str
    activity_key: str
    activity_label: str
    nwc_state: str
    latest_payment_status: str | None
    latest_payment_method: str | None
    latest_payment_amount_sats: int | None
    latest_payment_at: datetime | None
    assigned_resource: str | None
    billing_term: str | None
    period_end: datetime | None


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
    total_subscriptions: int
    pending_subscriptions: int
    expired_subscriptions: int
    accounts_without_subscriptions: int
    settled_gross_sats_30d: int
    active_subscription_accounts_7d: int
    status_breakdown: tuple[StatusBreakdownEntry, ...]
    active_product_breakdown: tuple[ActiveProductBreakdownEntry, ...]
    weekly_activity: tuple[WeeklyActivity, ...]
    relay_edges: tuple[RelayOperationsState, ...]
    dns_targets: tuple[DnsOperationsState, ...]
    capacities: tuple[ProductCapacity, ...]


def _scalar_count(session: Session, statement) -> int:
    return int(session.exec(statement).one() or 0)


def _utc_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _enum_key(value: object) -> str:
    return getattr(value, "value", str(value))


def _percentage(value: int, total: int) -> int:
    return round(value * 100 / total) if total else 0


def _weekly_activity(session: Session, current: datetime) -> tuple[WeeklyActivity, ...]:
    current_week = (current - timedelta(days=current.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    first_week = current_week - timedelta(weeks=7)
    customer = User.is_admin.is_(False)  # type: ignore[union-attr]
    new_subscriptions = [0] * 8
    paid_sats = [0] * 8

    subscription_dates = session.exec(
        select(Subscription.created_at)
        .join(User)
        .where(
            customer,
            Subscription.created_at >= first_week,  # type: ignore[operator]
            Subscription.created_at <= current,  # type: ignore[operator]
        )
    ).all()
    paid_payments = session.exec(
        select(Payment.paid_at, Payment.amount_sats)
        .join(Subscription)
        .join(User)
        .where(
            customer,
            Payment.status == PaymentStatus.PAID,
            Payment.paid_at.is_not(None),  # type: ignore[union-attr]
            Payment.paid_at >= first_week,  # type: ignore[operator]
            Payment.paid_at <= current,  # type: ignore[operator]
        )
    ).all()

    def bucket_index(value: datetime) -> int | None:
        offset = (_utc_datetime(value).date() - first_week.date()).days
        index = offset // 7
        return index if 0 <= index < 8 else None

    for created_at in subscription_dates:
        index = bucket_index(created_at)
        if index is not None:
            new_subscriptions[index] += 1
    for paid_at, amount_sats in paid_payments:
        if paid_at is None:
            continue
        index = bucket_index(paid_at)
        if index is not None:
            paid_sats[index] += amount_sats

    max_subscriptions = max(new_subscriptions, default=0)
    max_revenue = max(paid_sats, default=0)
    return tuple(
        WeeklyActivity(
            label=f"{(first_week + timedelta(weeks=index)).strftime('%b')} "
            f"{(first_week + timedelta(weeks=index)).day}",
            new_subscriptions=count,
            paid_sats=revenue,
            subscription_percent=_percentage(count, max_subscriptions),
            revenue_percent=_percentage(revenue, max_revenue),
        )
        for index, (count, revenue) in enumerate(zip(new_subscriptions, paid_sats, strict=True))
    )


def _activity(user: User, current: datetime) -> tuple[str, str]:
    if user.is_suspended:
        return "suspended", "Account suspended"
    if user.last_seen_at is None:
        return "never", "No account activity recorded"
    if _utc_datetime(user.last_seen_at) >= current - timedelta(days=7):
        return "recent", "Recent account activity"
    return "idle", "No account activity in 7 days"


def _status(subscription: Subscription, latest_payment: Payment | None) -> tuple[str, str]:
    if subscription.status == SubscriptionStatus.PENDING:
        if latest_payment is None:
            return "Pending", "Payment needed"
        if latest_payment.status == PaymentStatus.PENDING:
            return "Pending", "Awaiting payment"
        if latest_payment.status == PaymentStatus.PROCESSING:
            return "Pending", "Processing payment"
        if latest_payment.status == PaymentStatus.PAID:
            return "Pending", "Activation pending"
        return "Pending", "Payment needed"
    if subscription.status == SubscriptionStatus.ACTIVE:
        return "Active", "Service active"
    if subscription.status == SubscriptionStatus.EXPIRED:
        return "Expired", "Subscription expired"
    return "Cancelled", "Subscription cancelled"


def _assigned_resource(subscription: Subscription) -> str:
    if subscription.product == ProductType.IP:
        return subscription.assigned_ip or "Unassigned"
    if subscription.product == ProductType.PORT:
        if subscription.assigned_ip is None or subscription.assigned_port is None:
            return "Unassigned"
        return f"{_enum_key(subscription.transport).upper()} {subscription.assigned_ip}:{subscription.assigned_port}"
    if subscription.domain and subscription.relay_hostname_scope == RelayHostnameScope.WILDCARD:
        return f"*.{subscription.domain}"
    return subscription.domain or subscription.relay_pool_domain or "Unassigned"


def _payment_time(payment: Payment) -> datetime:
    return _utc_datetime(payment.paid_at or payment.created_at)


def _payment_created_time(payment: Payment) -> datetime:
    return _utc_datetime(payment.created_at)


def _row_sort_key(row: AdminSubscriptionRow) -> tuple[int, str, str]:
    if row.subscription_public_id is None:
        priority = 5
    elif row.account_suspended:
        priority = 0
    else:
        priority = {
            "pending": 1,
            "expired": 2,
            "cancelled": 3,
            "active": 4,
        }[row.status_key]
    return priority, row.account_public_id, row.subscription_public_id or ""


def build_subscription_rows(
    users: Iterable[User],
    subscriptions: Iterable[Subscription],
    payments: Iterable[Payment],
    *,
    now: datetime | None = None,
) -> tuple[AdminSubscriptionRow, ...]:
    """Build administrator rows without inferring subscription activity from traffic."""
    current = _utc_datetime(now or datetime.now(UTC))
    customer_by_id = {user.id: user for user in users if not user.is_admin and user.id is not None}
    customer_subscriptions = [
        subscription for subscription in subscriptions if subscription.user_id in customer_by_id
    ]
    subscriptions_by_user: dict[int, list[Subscription]] = {}
    for subscription in customer_subscriptions:
        subscriptions_by_user.setdefault(subscription.user_id, []).append(subscription)
    payments_by_subscription: dict[int, list[Payment]] = {}
    subscription_ids = {
        subscription.id for subscription in customer_subscriptions if subscription.id is not None
    }
    for payment in payments:
        if payment.subscription_id in subscription_ids:
            payments_by_subscription.setdefault(payment.subscription_id, []).append(payment)

    rows: list[AdminSubscriptionRow] = []
    for subscription in customer_subscriptions:
        assert subscription.id is not None
        user = customer_by_id[subscription.user_id]
        latest_payment = max(
            payments_by_subscription.get(subscription.id, []),
            key=_payment_created_time,
            default=None,
        )
        status_label, status_detail = _status(subscription, latest_payment)
        if user.is_suspended:
            status_detail = "Account access suspended"
        activity_key, activity_label = _activity(user, current)
        rows.append(
            AdminSubscriptionRow(
                account_public_id=str(user.public_id),
                subscription_public_id=str(subscription.public_id),
                account_suspended=user.is_suspended,
                product=_enum_key(subscription.product),
                status_key=_enum_key(subscription.status),
                status_label=status_label,
                status_detail=status_detail,
                activity_key=activity_key,
                activity_label=activity_label,
                nwc_state="configured" if user.has_nwc else "not_configured",
                latest_payment_status=(
                    _enum_key(latest_payment.status) if latest_payment is not None else None
                ),
                latest_payment_method=(
                    _enum_key(latest_payment.method) if latest_payment is not None else None
                ),
                latest_payment_amount_sats=(
                    latest_payment.amount_sats if latest_payment is not None else None
                ),
                latest_payment_at=(
                    _payment_time(latest_payment) if latest_payment is not None else None
                ),
                assigned_resource=_assigned_resource(subscription),
                billing_term=_enum_key(subscription.billing_term),
                period_end=(
                    _utc_datetime(subscription.current_period_end)
                    if subscription.current_period_end is not None
                    else None
                ),
            )
        )
    for user_id, user in customer_by_id.items():
        if user_id in subscriptions_by_user:
            continue
        activity_key, activity_label = _activity(user, current)
        rows.append(
            AdminSubscriptionRow(
                account_public_id=str(user.public_id),
                subscription_public_id=None,
                account_suspended=user.is_suspended,
                product=None,
                status_key="account_only",
                status_label="No subscriptions",
                status_detail=(
                    "Account access suspended" if user.is_suspended else "No subscriptions"
                ),
                activity_key=activity_key,
                activity_label=activity_label,
                nwc_state="configured" if user.has_nwc else "not_configured",
                latest_payment_status=None,
                latest_payment_method=None,
                latest_payment_amount_sats=None,
                latest_payment_at=None,
                assigned_resource=None,
                billing_term=None,
                period_end=None,
            )
        )
    return tuple(sorted(rows, key=_row_sort_key))


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
    subscription_status_counts = {
        _enum_key(status): int(count)
        for status, count in session.exec(
            select(Subscription.status, func.count())
            .select_from(Subscription)
            .join(User)
            .where(customer)
            .group_by(Subscription.status)
        ).all()
    }
    total_subscriptions = sum(subscription_status_counts.values())
    status_labels = {
        "active": "Active",
        "pending": "Pending",
        "expired": "Expired",
        "cancelled": "Cancelled",
    }
    status_breakdown = tuple(
        StatusBreakdownEntry(
            key=key,
            label=status_labels[key],
            value=subscription_status_counts.get(key, 0),
            percent=_percentage(subscription_status_counts.get(key, 0), total_subscriptions),
        )
        for key in ("active", "pending", "expired", "cancelled")
    )
    active_product_counts = {
        _enum_key(product): int(count)
        for product, count in session.exec(
            select(Subscription.product, func.count())
            .select_from(Subscription)
            .join(User)
            .where(customer, active_subscription)
            .group_by(Subscription.product)
        ).all()
    }
    product_labels = {"ip": "Dedicated IP", "port": "Port mapping", "relay": "Relay"}
    active_product_breakdown = tuple(
        ActiveProductBreakdownEntry(
            key=key,
            label=product_labels[key],
            value=active_product_counts.get(key, 0),
            percent=_percentage(active_product_counts.get(key, 0), active_subscriptions),
        )
        for key in ("ip", "port", "relay")
    )
    accounts_without_subscriptions = _scalar_count(
        session,
        select(func.count())
        .select_from(User)
        .outerjoin(Subscription)
        .where(customer, Subscription.id.is_(None)),  # type: ignore[union-attr]
    )
    settled_gross_sats_30d = int(
        session.exec(
            select(func.coalesce(func.sum(Payment.amount_sats), 0))
            .select_from(Payment)
            .join(Subscription)
            .join(User)
            .where(
                customer,
                Payment.status == PaymentStatus.PAID,
                Payment.paid_at.is_not(None),  # type: ignore[union-attr]
                Payment.paid_at >= current - timedelta(days=30),  # type: ignore[operator]
            )
        ).one()
        or 0
    )
    active_subscription_accounts_7d = _scalar_count(
        session,
        select(func.count(func.distinct(Subscription.user_id)))
        .select_from(Subscription)
        .join(User)
        .where(
            customer,
            active_subscription,
            User.last_seen_at >= current - timedelta(days=7),  # type: ignore[operator]
        ),
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
        total_subscriptions=total_subscriptions,
        pending_subscriptions=subscription_status_counts.get("pending", 0),
        expired_subscriptions=subscription_status_counts.get("expired", 0),
        accounts_without_subscriptions=accounts_without_subscriptions,
        settled_gross_sats_30d=settled_gross_sats_30d,
        active_subscription_accounts_7d=active_subscription_accounts_7d,
        status_breakdown=status_breakdown,
        active_product_breakdown=active_product_breakdown,
        weekly_activity=_weekly_activity(session, current),
        relay_edges=relay_edges,
        dns_targets=_dns_rows(session, current),
        capacities=_capacity_rows(session),
    )
