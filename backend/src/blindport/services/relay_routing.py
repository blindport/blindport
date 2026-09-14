"""Provider-edge routing plans for framed customer tunnels."""

from __future__ import annotations

from uuid import UUID

from ..config import RelayEdge, settings


def port_edges(assigned_ip: str) -> list[RelayEdge]:
    edges = settings.port_ha_edges_list
    if edges and assigned_ip in settings.relay_shared_ips_list:
        return edges
    return [RelayEdge(endpoint=settings.RELAY_CONTROL_URL, ip=assigned_ip)]


def framed_ip_edge(assigned_ip: str) -> RelayEdge:
    endpoint = settings.framed_ip_endpoints_map.get(assigned_ip, settings.RELAY_CONTROL_URL)
    return RelayEdge(endpoint=endpoint, ip=assigned_ip)


def port_hostname(subscription_id: UUID) -> str | None:
    if not settings.PORT_HOSTNAME_SUFFIX:
        return None
    return f"{subscription_id}.{settings.PORT_HOSTNAME_SUFFIX}"
