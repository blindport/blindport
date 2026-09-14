"""Service for reserving scarce relay resources.

This is the in-process control plane. In production the relay nodes would
poll an API (or receive pushes) to learn which IPs/domains are allocated
to which bearer-token-authenticated clients.
"""

from __future__ import annotations

import secrets

from sqlmodel import Session, select

from ..config import settings
from ..core.models import ProductType, Subscription, SubscriptionStatus, Transport


class NoCapacityError(RuntimeError):
    """No dedicated IP or shared transport socket is available."""


class ResourceAllocator:
    """Reserve dedicated IPs, shared sockets, and relay pool domains."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def allocate_ip(self) -> str:
        """Pick an unused IP from the configured pool. Raises NoCapacityError if
        exhausted.
        """
        used = {
            s.assigned_ip
            for s in self.session.exec(
                select(Subscription).where(
                    Subscription.product == ProductType.IP,
                    Subscription.assigned_ip.is_not(None),  # type: ignore[union-attr]
                )
            ).all()
            if s.assigned_ip
        }
        for ip in settings.relay_public_ips_list:
            if ip not in used:
                return ip
        raise NoCapacityError("no Blindport IP capacity")

    def allocate_port(self, transport: Transport = Transport.TCP) -> tuple[str, int]:
        """Pick an unused socket from the dedicated shared-IP inventory."""
        used = {
            (s.assigned_ip, s.assigned_port, s.transport)
            for s in self.session.exec(
                select(Subscription).where(
                    Subscription.product == ProductType.PORT,
                    Subscription.assigned_ip.is_not(None),  # type: ignore[union-attr]
                    Subscription.assigned_port.is_not(None),  # type: ignore[union-attr]
                )
            ).all()
        }
        ports = (
            settings.relay_shared_udp_ports_list
            if transport == Transport.UDP
            else settings.relay_shared_tcp_ports_list
        )
        for ip in settings.relay_shared_ips_list:
            for port in ports:
                if (ip, port, transport) not in used:
                    return ip, port
        raise NoCapacityError("no Blindport Port capacity")

    def allocate_relay_pool_domain(self) -> str:
        """Round-robin pick across the configured relay pool domains."""
        domains = settings.relay_pool_domains_list
        if not domains:
            raise NoCapacityError("no Blindport Relay pool configured")
        # Load-balance both managed apex assignments and customer CNAME targets.
        counts: dict[str, int] = dict.fromkeys(domains, 0)
        for s in self.session.exec(
            select(Subscription).where(
                Subscription.product == ProductType.RELAY,
                Subscription.status != SubscriptionStatus.CANCELLED,
                Subscription.domain.is_not(None),  # type: ignore[union-attr]
                Subscription.relay_pool_domain.is_not(None),  # type: ignore[union-attr]
            )
        ).all():
            target = s.relay_pool_domain or ""
            base = next(
                (
                    domain
                    for domain in sorted(domains, key=len, reverse=True)
                    if target == domain or target.endswith(f".{domain}")
                ),
                None,
            )
            if base is not None:
                counts[base] += 1
        return min(counts, key=lambda d: counts[d])

    def allocate_relay_cname_target(self) -> str:
        """Create a random, unused customer CNAME target under one relay pool."""
        base = self.allocate_relay_pool_domain()
        for _ in range(16):
            target = f"{secrets.token_hex(16)}.{base}"
            existing = self.session.exec(
                select(Subscription.id).where(Subscription.relay_pool_domain == target)
            ).first()
            if existing is None:
                return target
        raise NoCapacityError("could not allocate a unique Blindport Relay CNAME target")
