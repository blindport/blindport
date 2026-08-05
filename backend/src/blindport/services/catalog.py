"""Public product catalog backed by configured and currently held inventory."""

from __future__ import annotations

from sqlmodel import Session, select

from ..config import settings
from ..core.models import DeliveryMode, ProductType, Subscription, Transport
from ..core.schemas import (
    CatalogCapacityResponse,
    CatalogProductResponse,
    CatalogResponse,
)


class ProductUnavailableError(ValueError):
    """The requested product or inventory variant cannot currently be sold."""


def _available_product(
    product: ProductType,
    enabled: bool,
    sales_paused: bool,
    monthly_price: int,
    yearly_price: int,
    capacity: CatalogCapacityResponse,
    has_capacity: bool,
) -> CatalogProductResponse:
    available = enabled and not sales_paused and has_capacity
    return CatalogProductResponse(
        product=product,
        enabled=enabled,
        sales_paused=sales_paused,
        monthly_price_sats=monthly_price,
        yearly_price_sats=yearly_price,
        available=available,
        sold_out=enabled and not sales_paused and not has_capacity,
        capacity=capacity,
    )


def get_catalog(session: Session) -> CatalogResponse:
    """Return a conservative snapshot without releasing or reallocating resources."""
    assigned = session.exec(
        select(Subscription).where(Subscription.assigned_ip.is_not(None))  # type: ignore[union-attr]
    ).all()

    framed_inventory = set(settings.relay_public_ips_list)
    wireguard_inventory = set(settings.wireguard_public_ips_list)
    used_framed = {
        row.assigned_ip
        for row in assigned
        if row.product == ProductType.IP
        and row.delivery == DeliveryMode.FRAMED
        and row.assigned_ip in framed_inventory
    }
    used_wireguard = {
        row.assigned_ip
        for row in assigned
        if row.product == ProductType.IP
        and row.delivery == DeliveryMode.WIREGUARD
        and row.assigned_ip in wireguard_inventory
    }
    framed_available = max(0, len(framed_inventory) - len(used_framed))
    wireguard_available = (
        max(0, len(wireguard_inventory) - len(used_wireguard))
        if settings.BILLING_YEARLY_ENABLED
        else 0
    )
    ip_available = framed_available + wireguard_available
    ip = _available_product(
        ProductType.IP,
        settings.IP_ENABLED,
        settings.IP_SALES_PAUSED,
        settings.IP_MONTHLY_SATS,
        settings.IP_YEARLY_SATS,
        CatalogCapacityResponse(
            total=len(framed_inventory) + len(wireguard_inventory),
            available=ip_available,
            framed_available=framed_available,
            wireguard_available=wireguard_available,
        ),
        ip_available > 0,
    )

    shared_ips = set(settings.relay_shared_ips_list)
    tcp_ports = set(settings.relay_shared_tcp_ports_list)
    udp_ports = set(settings.relay_shared_udp_ports_list)
    used_tcp = {
        (row.assigned_ip, row.assigned_port)
        for row in assigned
        if row.product == ProductType.PORT
        and row.transport == Transport.TCP
        and row.assigned_ip in shared_ips
        and row.assigned_port in tcp_ports
    }
    used_udp = {
        (row.assigned_ip, row.assigned_port)
        for row in assigned
        if row.product == ProductType.PORT
        and row.transport == Transport.UDP
        and row.assigned_ip in shared_ips
        and row.assigned_port in udp_ports
    }
    tcp_total = len(shared_ips) * len(tcp_ports)
    udp_total = len(shared_ips) * len(udp_ports)
    tcp_available = max(0, tcp_total - len(used_tcp))
    udp_available = max(0, udp_total - len(used_udp))
    port_available = tcp_available + udp_available
    port = _available_product(
        ProductType.PORT,
        settings.PORT_ENABLED,
        settings.PORT_SALES_PAUSED,
        settings.PORT_MONTHLY_SATS,
        settings.PORT_YEARLY_SATS,
        CatalogCapacityResponse(
            total=tcp_total + udp_total,
            available=port_available,
            tcp_available=tcp_available,
            udp_available=udp_available,
        ),
        port_available > 0,
    )

    managed_held = len(
        session.exec(
            select(Subscription).where(
                Subscription.product == ProductType.RELAY,
                Subscription.domain_is_managed.is_(True),  # type: ignore[union-attr]
                Subscription.domain.is_not(None),  # type: ignore[union-attr]
            )
        ).all()
    )
    managed_available = max(0, settings.RELAY_MANAGED_DOMAIN_CAP - managed_held)
    relay_pool_available = bool(settings.relay_pool_domains_list)
    managed_sale_available = bool(settings.relay_managed_suffixes_list) and (managed_available > 0)
    customer_available = settings.RELAY_CUSTOMER_DOMAINS_ENABLED and relay_pool_available
    relay = _available_product(
        ProductType.RELAY,
        settings.RELAY_ENABLED,
        settings.RELAY_SALES_PAUSED,
        settings.RELAY_MONTHLY_SATS,
        settings.RELAY_YEARLY_SATS,
        CatalogCapacityResponse(
            total=settings.RELAY_MANAGED_DOMAIN_CAP,
            available=managed_available,
            managed_domains_available=managed_available,
            customer_domains_available=customer_available,
        ),
        relay_pool_available and (managed_sale_available or customer_available),
    )
    return CatalogResponse(
        products=[ip, port, relay],
        managed_suffixes=settings.relay_managed_suffixes_list,
        yearly_billing_enabled=settings.BILLING_YEARLY_ENABLED,
    )


def require_product_available(
    session: Session,
    product: ProductType,
    *,
    delivery: DeliveryMode,
    transport: Transport,
    domain_is_managed: bool,
) -> None:
    entry = next(item for item in get_catalog(session).products if item.product == product)
    if not entry.enabled:
        raise ProductUnavailableError(f"{product.value} is disabled")
    if entry.sales_paused:
        raise ProductUnavailableError(f"{product.value} sales are paused")
    capacity = entry.capacity
    if product == ProductType.IP:
        available = (
            capacity.wireguard_available
            if delivery == DeliveryMode.WIREGUARD
            else capacity.framed_available
        )
        if not available:
            raise ProductUnavailableError(f"no {delivery.value} Blindport IP capacity")
    elif product == ProductType.PORT:
        available = capacity.udp_available if transport == Transport.UDP else capacity.tcp_available
        if not available:
            raise ProductUnavailableError(f"no {transport.value.upper()} Blindport Port capacity")
    elif domain_is_managed:
        if not capacity.managed_domains_available:
            raise ProductUnavailableError("no managed Blindport Relay domain capacity")
    elif not capacity.customer_domains_available:
        raise ProductUnavailableError(
            "customer-domain Blindport Relay subscriptions are unavailable"
        )
