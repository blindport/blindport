"""Internal control-plane API consumed by relay nodes.

Relay nodes call these endpoints to authenticate connecting clients and look
up the resource bindings (IP, domain) they're entitled to use. This endpoint
is protected by a shared secret (`X-Relay-Secret` header) configured per
relay.
"""

from __future__ import annotations

import hmac
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session, select

from ..config import settings
from ..core import tokens
from ..core.ca import issue_server_cert
from ..core.hostnames import canonicalize_hostname
from ..core.models import (
    DeliveryMode,
    ProductType,
    RelayHeartbeat,
    Subscription,
    SubscriptionStatus,
    Transport,
    User,
)
from ..db import get_session
from ..services import relay_routing
from ..services import subscriptions as subs_svc
from ..services.wireguard import desired_state as wireguard_desired_state
from ..services.wireguard import desired_state_v2 as wireguard_desired_state_v2

router = APIRouter(prefix="/internal/v1")
v2_router = APIRouter(prefix="/internal/v2")


def _require_relay_secret(x_relay_secret: str = Header(default="")) -> None:
    if not x_relay_secret or not hmac.compare_digest(
        x_relay_secret.encode("utf-8"), settings.relay_secret.encode("utf-8")
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid relay secret")


class ResolveRequest(BaseModel):
    token: str


class RelayHealthComponents(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    authorization: Literal["ok", "degraded", "starting", "unavailable"]
    certificate: Literal["ok", "disabled", "unavailable"]
    lifecycle: Literal["serving", "draining"]
    listeners: Literal["ok", "unavailable"]
    wireguard: Literal["ok", "disabled", "starting", "unavailable"]


class RelayHeartbeatRequest(BaseModel):
    """Strict relay process health emitted by the Go relay daemon."""

    model_config = ConfigDict(extra="forbid", strict=True)

    edge_id: str = Field(min_length=1, max_length=63)
    ready: bool
    components: RelayHealthComponents
    active_tunnels: int = Field(ge=0, le=9_223_372_036_854_775_807)
    active_streams: int = Field(ge=0, le=9_223_372_036_854_775_807)
    accepted_connections_total: int = Field(ge=0, le=9_223_372_036_854_775_807)
    forwarded_bytes_total: int = Field(ge=0, le=9_223_372_036_854_775_807)


class RelayHeartbeatResponse(BaseModel):
    status: Literal["accepted"] = "accepted"


def _relay_heartbeat_insert(session: Session) -> Any:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        return postgresql_insert(RelayHeartbeat)
    if dialect == "sqlite":
        return sqlite_insert(RelayHeartbeat)
    raise RuntimeError(f"relay heartbeat storage does not support database dialect {dialect!r}")


def persist_relay_heartbeat(
    session: Session,
    body: RelayHeartbeatRequest,
    *,
    received_at: datetime,
) -> None:
    """Atomically retain the newest server-received heartbeat for one edge."""
    values = body.model_dump(exclude={"edge_id", "components"}) | body.components.model_dump()
    values["received_at"] = received_at
    insert = _relay_heartbeat_insert(session).values(edge_id=body.edge_id, **values)
    session.execute(
        insert.on_conflict_do_update(
            index_elements=["edge_id"],
            set_=values,
            where=RelayHeartbeat.received_at < received_at,  # type: ignore[arg-type]
        )
    )


class AuthorizedPortLease(BaseModel):
    assigned_ip: str
    assigned_port: int = Field(ge=1, le=65535)
    transport: Transport


class ResolveResponse(BaseModel):
    user_id: int
    ip_ips: list[str]
    relay_domains: list[str]
    port_leases: list[AuthorizedPortLease]


class ResolveV2Response(ResolveResponse):
    account_id: UUID


class WireGuardDesiredPeerResponse(BaseModel):
    public_key: str
    allowed_prefixes: list[str]


class WireGuardDesiredStateResponse(BaseModel):
    revision: str
    generated_at: datetime
    managed_prefixes: list[str]
    peers: list[WireGuardDesiredPeerResponse]


class WireGuardDesiredStateV2Response(WireGuardDesiredStateResponse):
    smtp_allowed_prefixes: list[str]


def _resolve(
    body: ResolveRequest, session: Session
) -> tuple[User, list[str], list[str], list[AuthorizedPortLease]]:
    subs_svc.reap_expired_domain_claims(session)
    normalized = tokens.crockford.normalize(body.token)
    hashed = tokens.hash_token(normalized)
    user = session.exec(
        select(User).where(User.hashed_token == hashed, User.is_admin.is_(False))  # type: ignore[union-attr]
    ).first()
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no such user")
    if user.is_suspended:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "account suspended")
    rows = session.exec(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status == SubscriptionStatus.ACTIVE,
        )
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, rows)
    ips: list[str] = []
    domains: list[str] = []
    port_leases: list[AuthorizedPortLease] = []
    for s in rows:
        if s.status != SubscriptionStatus.ACTIVE:
            continue
        if s.product == ProductType.IP and s.delivery == DeliveryMode.FRAMED and s.assigned_ip:
            ips.append(s.assigned_ip)
        elif s.product == ProductType.RELAY and s.domain:
            domains.append(s.domain)
        elif s.product == ProductType.PORT and s.assigned_ip and s.assigned_port:
            port_leases.extend(
                AuthorizedPortLease(
                    assigned_ip=edge.ip,
                    assigned_port=s.assigned_port,
                    transport=s.transport,
                )
                for edge in relay_routing.port_edges(s.assigned_ip)
            )
    return user, ips, domains, port_leases


@router.post(
    "/resolve",
    response_model=ResolveResponse,
    dependencies=[Depends(_require_relay_secret)],
)
def resolve(body: ResolveRequest, session: Session = Depends(get_session)) -> ResolveResponse:
    """Resolve a user token using the rollout-stable legacy identity contract."""
    user, ips, domains, port_leases = _resolve(body, session)
    return ResolveResponse(
        user_id=user.id or 0,
        ip_ips=ips,
        relay_domains=domains,
        port_leases=port_leases,
    )


@router.post(
    "/relay/heartbeat",
    response_model=RelayHeartbeatResponse,
    dependencies=[Depends(_require_relay_secret)],
)
def relay_heartbeat(
    body: RelayHeartbeatRequest,
    session: Session = Depends(get_session),
    x_relay_heartbeat_token: str = Header(default=""),
) -> RelayHeartbeatResponse:
    """Store the latest authenticated health report for one configured relay edge."""
    expected_token = settings.relay_heartbeat_keys.get(body.edge_id)
    if (
        not x_relay_heartbeat_token
        or expected_token is None
        or not hmac.compare_digest(
            x_relay_heartbeat_token.encode("utf-8"), expected_token.encode("utf-8")
        )
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid relay heartbeat token")
    persist_relay_heartbeat(session, body, received_at=datetime.now(UTC))
    session.commit()
    return RelayHeartbeatResponse()


@v2_router.post(
    "/resolve",
    response_model=ResolveV2Response,
    dependencies=[Depends(_require_relay_secret)],
)
def resolve_v2(body: ResolveRequest, session: Session = Depends(get_session)) -> ResolveV2Response:
    """Resolve a token to both public and rollout-era account identities."""
    user, ips, domains, port_leases = _resolve(body, session)
    return ResolveV2Response(
        user_id=user.id or 0,
        account_id=user.public_id,
        ip_ips=ips,
        relay_domains=domains,
        port_leases=port_leases,
    )


@router.get(
    "/wireguard/peers",
    response_model=WireGuardDesiredStateResponse,
    dependencies=[Depends(_require_relay_secret)],
)
def wireguard_peers(session: Session = Depends(get_session)) -> WireGuardDesiredStateResponse:
    snapshot = wireguard_desired_state(session)
    return WireGuardDesiredStateResponse(
        revision=snapshot.revision,
        generated_at=snapshot.generated_at,
        managed_prefixes=snapshot.managed_prefixes,
        peers=[WireGuardDesiredPeerResponse(**vars(peer)) for peer in snapshot.peers],
    )


@v2_router.get(
    "/wireguard/peers",
    response_model=WireGuardDesiredStateV2Response,
    dependencies=[Depends(_require_relay_secret)],
)
def wireguard_peers_v2(session: Session = Depends(get_session)) -> WireGuardDesiredStateV2Response:
    snapshot = wireguard_desired_state_v2(session)
    return WireGuardDesiredStateV2Response(
        revision=snapshot.revision,
        generated_at=snapshot.generated_at,
        managed_prefixes=snapshot.managed_prefixes,
        peers=[WireGuardDesiredPeerResponse(**vars(peer)) for peer in snapshot.peers],
        smtp_allowed_prefixes=snapshot.smtp_allowed_prefixes,
    )


class RelayCertRequest(BaseModel):
    """Hostnames and/or public IPs the relay terminates TLS on.

    The backend mini-CA issues a server cert with these as SubjectAltNames so
    clients (blindportd) can validate the relay just like any normal TLS peer.
    """

    hostnames: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)


class RelayCertResponse(BaseModel):
    ca_cert_pem: str
    server_cert_pem: str
    server_key_pem: str
    not_after: str


@router.post(
    "/relay/cert",
    response_model=RelayCertResponse,
    dependencies=[Depends(_require_relay_secret)],
)
def relay_cert(body: RelayCertRequest) -> RelayCertResponse:
    """Issue a server cert for a relay node. Relay calls this at startup."""
    if not body.hostnames and not body.ips:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "must provide at least one hostname or IP for SAN",
        )
    try:
        hostnames = [canonicalize_hostname(hostname) for hostname in body.hostnames]
        ips = [str(ip_address(address)) for address in body.ips]
    except ValueError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"invalid relay SAN: {e}") from e
    disallowed_hostnames = set(hostnames) - settings.relay_certificate_hostnames
    disallowed_ips = set(ips) - settings.relay_certificate_ips
    if disallowed_hostnames or disallowed_ips:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "relay certificate SAN is not present in configured endpoints or inventory",
        )
    issued = issue_server_cert(hostnames, ips)
    return RelayCertResponse(
        ca_cert_pem=issued.ca_cert_pem,
        server_cert_pem=issued.server_cert_pem,
        server_key_pem=issued.server_key_pem,
        not_after=issued.not_after.isoformat(),
    )
