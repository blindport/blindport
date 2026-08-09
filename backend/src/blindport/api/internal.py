"""Internal control-plane API consumed by relay nodes.

Relay nodes call these endpoints to authenticate connecting clients and look
up the resource bindings (IP, domain) they're entitled to use. This endpoint
is protected by a shared secret (`X-Relay-Secret` header) configured per
relay.
"""

from __future__ import annotations

import hmac
from datetime import UTC, date, datetime, timedelta
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
    RelayHostnameScope,
    Subscription,
    SubscriptionStatus,
    Transport,
    User,
)
from ..db import get_session
from ..services import relay_routing
from ..services import subscriptions as subs_svc
from ..services.bandwidth import (
    BandwidthAggregateOverflowError,
    BandwidthCounterDecreaseError,
    BandwidthReport,
    BandwidthUnknownSubscriptionError,
    ingest_daily_bandwidth,
)
from ..services.wireguard import desired_state as wireguard_desired_state
from ..services.wireguard import desired_state_v2 as wireguard_desired_state_v2
from ..services.wireguard import desired_state_v3 as wireguard_desired_state_v3

legacy_router = APIRouter(prefix="/internal")
router = APIRouter(prefix="/internal/v1")
v2_router = APIRouter(prefix="/internal/v2")
v3_router = APIRouter(prefix="/internal/v3")


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


class RelayBandwidthReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subscription_id: UUID
    day: date
    ingress_bytes: int = Field(strict=True, ge=0, le=9_223_372_036_854_775_807)
    egress_bytes: int = Field(strict=True, ge=0, le=9_223_372_036_854_775_807)


class RelayDailyBandwidthRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    edge_id: str = Field(min_length=1, max_length=63)
    boot_id: UUID
    sequence: int = Field(strict=True, ge=0, le=9_223_372_036_854_775_807)
    reports: list[RelayBandwidthReport] = Field(min_length=1, max_length=1000)


class RelayDailyBandwidthResponse(BaseModel):
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


class ResolveClaimRequest(BaseModel):
    """Optional tunnel claim supplied by a rollout-era relay."""

    model_config = ConfigDict(extra="forbid", strict=True)

    kind: ProductType = Field(strict=False)
    ip: str = Field(default="", max_length=45)
    domain: str = Field(default="", max_length=253)
    port: int = Field(default=0, ge=0, le=65535)
    transport: Literal["", "tcp", "udp"] = ""
    scope: RelayHostnameScope = Field(default=RelayHostnameScope.EXACT, strict=False)

    def validate_binding(self) -> None:
        try:
            canonical_ip = str(ip_address(self.ip)) if self.ip else ""
        except ValueError as error:
            raise ValueError("requested claim IP is invalid") from error
        if canonical_ip and canonical_ip != self.ip:
            raise ValueError("requested claim IP is invalid")
        if self.kind == ProductType.IP:
            valid = (
                bool(canonical_ip)
                and not self.domain
                and self.port == 0
                and self.transport in {"", "tcp"}
                and self.scope == RelayHostnameScope.EXACT
            )
        elif self.kind == ProductType.PORT:
            valid = (
                bool(canonical_ip)
                and not self.domain
                and self.port > 0
                and self.transport in {"tcp", "udp"}
                and self.scope == RelayHostnameScope.EXACT
            )
        elif self.kind == ProductType.RELAY:
            try:
                canonical_domain = canonicalize_hostname(self.domain)
            except ValueError:
                canonical_domain = ""
            valid = (
                bool(canonical_domain)
                and canonical_domain == self.domain
                and not self.ip
                and self.port == 0
                and self.transport in {"", "tcp"}
                and self.scope in {RelayHostnameScope.EXACT, RelayHostnameScope.WILDCARD}
            )
        else:  # pragma: no cover, ProductType rejects unknown enum values.
            valid = False
        if not valid:
            raise ValueError("requested claim has an invalid field combination")


class ResolveV3Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    token: str = Field(min_length=1, max_length=256)
    claim: ResolveClaimRequest | None = None

    def validate_binding(self) -> None:
        if self.claim is not None:
            self.claim.validate_binding()


class AuthorizedRelayClaim(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    domain: str
    scope: RelayHostnameScope = Field(strict=False)


class ResolveV3Response(ResolveV2Response):
    relay_claims: list[AuthorizedRelayClaim]
    subscription_id: UUID | None = None


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


class WireGuardPrefixBindingResponse(BaseModel):
    prefix: str
    subscription_id: UUID


class WireGuardDesiredStateV3Response(WireGuardDesiredStateV2Response):
    prefix_bindings: list[WireGuardPrefixBindingResponse]


def _resolve(
    body: ResolveRequest, session: Session
) -> tuple[User, list[str], list[str], list[AuthorizedRelayClaim], list[AuthorizedPortLease]]:
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
    relay_claims: list[AuthorizedRelayClaim] = []
    port_leases: list[AuthorizedPortLease] = []
    for s in rows:
        if s.status != SubscriptionStatus.ACTIVE:
            continue
        if s.product == ProductType.IP and s.delivery == DeliveryMode.FRAMED and s.assigned_ip:
            ips.append(s.assigned_ip)
        elif s.product == ProductType.RELAY and s.domain:
            relay_claims.append(AuthorizedRelayClaim(domain=s.domain, scope=s.relay_hostname_scope))
            if s.relay_hostname_scope == RelayHostnameScope.EXACT:
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
    return user, ips, domains, relay_claims, port_leases


def _claim_subscription_id(session: Session, user: User, claim: ResolveClaimRequest) -> UUID | None:
    """Return one exact active subscription match, rejecting authorization ambiguity."""
    subscriptions = session.exec(
        select(Subscription).where(
            Subscription.user_id == user.id,
            Subscription.status == SubscriptionStatus.ACTIVE,
        )
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, subscriptions)
    matches: list[Subscription] = []
    for subscription in subscriptions:
        if subscription.status != SubscriptionStatus.ACTIVE:
            continue
        matches_claim = (
            (
                claim.kind == ProductType.IP
                and subscription.product == ProductType.IP
                and subscription.delivery == DeliveryMode.FRAMED
                and subscription.assigned_ip == claim.ip
            )
            or (
                claim.kind == ProductType.PORT
                and subscription.product == ProductType.PORT
                and subscription.assigned_ip is not None
                and subscription.assigned_port == claim.port
                and subscription.transport.value == claim.transport
                and any(
                    edge.ip == claim.ip
                    for edge in relay_routing.port_edges(subscription.assigned_ip)
                )
            )
            or (
                claim.kind == ProductType.RELAY
                and subscription.product == ProductType.RELAY
                and subscription.domain == claim.domain
                and subscription.relay_hostname_scope == claim.scope
            )
        )
        if matches_claim:
            matches.append(subscription)
    if len(matches) > 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "ambiguous subscription claim")
    return matches[0].public_id if matches else None


@legacy_router.post(
    "/resolve",
    response_model=ResolveResponse,
    dependencies=[Depends(_require_relay_secret)],
)
@router.post(
    "/resolve",
    response_model=ResolveResponse,
    dependencies=[Depends(_require_relay_secret)],
)
def resolve(body: ResolveRequest, session: Session = Depends(get_session)) -> ResolveResponse:
    """Resolve a user token using the rollout-stable legacy identity contract."""
    user, ips, domains, _relay_claims, port_leases = _resolve(body, session)
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


@router.post(
    "/relay/bandwidth/daily",
    response_model=RelayDailyBandwidthResponse,
)
def relay_daily_bandwidth(
    body: RelayDailyBandwidthRequest,
    session: Session = Depends(get_session),
    x_relay_secret: str = Header(default=""),
    x_relay_heartbeat_token: str = Header(default=""),
) -> RelayDailyBandwidthResponse:
    """Ingest a bounded batch of daily cumulative subscription bandwidth totals."""
    if not settings.BANDWIDTH_METRICS_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not found")
    _require_relay_secret(x_relay_secret)
    expected_token = settings.relay_heartbeat_keys.get(body.edge_id)
    if (
        not x_relay_heartbeat_token
        or expected_token is None
        or not hmac.compare_digest(
            x_relay_heartbeat_token.encode("utf-8"), expected_token.encode("utf-8")
        )
    ):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid relay heartbeat token")
    keys = [(report.subscription_id, report.day) for report in body.reports]
    if len(keys) != len(set(keys)):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "duplicate subscription day report"
        )
    today = datetime.now(UTC).date()
    oldest_allowed = today - timedelta(days=settings.BANDWIDTH_INGEST_MAX_AGE_DAYS)
    if any(report.day > today for report in body.reports):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "bandwidth report day is in the future"
        )
    if any(report.day < oldest_allowed for report in body.reports):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "bandwidth report day is too old")
    try:
        with session.begin():
            ingest_daily_bandwidth(
                session,
                edge_id=body.edge_id,
                boot_id=body.boot_id,
                sequence=body.sequence,
                reports=[
                    BandwidthReport(
                        subscription_id=report.subscription_id,
                        day=report.day,
                        ingress_bytes=report.ingress_bytes,
                        egress_bytes=report.egress_bytes,
                    )
                    for report in body.reports
                ],
            )
    except BandwidthUnknownSubscriptionError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
    except BandwidthCounterDecreaseError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except BandwidthAggregateOverflowError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    return RelayDailyBandwidthResponse()


@v2_router.post(
    "/resolve",
    response_model=ResolveV2Response,
    dependencies=[Depends(_require_relay_secret)],
)
def resolve_v2(body: ResolveRequest, session: Session = Depends(get_session)) -> ResolveV2Response:
    """Resolve a token to both public and rollout-era account identities."""
    user, ips, domains, _relay_claims, port_leases = _resolve(body, session)
    return ResolveV2Response(
        user_id=user.id or 0,
        account_id=user.public_id,
        ip_ips=ips,
        relay_domains=domains,
        port_leases=port_leases,
    )


@v3_router.post(
    "/resolve",
    response_model=ResolveV3Response,
    response_model_exclude_none=True,
    dependencies=[Depends(_require_relay_secret)],
)
def resolve_v3(
    body: ResolveV3Request, session: Session = Depends(get_session)
) -> ResolveV3Response:
    """Resolve scope-aware Relay authorizations for rollout-era relays."""
    try:
        body.validate_binding()
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error
    legacy_body = ResolveRequest(token=body.token)
    user, ips, domains, relay_claims, port_leases = _resolve(legacy_body, session)
    subscription_id = (
        _claim_subscription_id(session, user, body.claim) if body.claim is not None else None
    )
    return ResolveV3Response(
        user_id=user.id or 0,
        account_id=user.public_id,
        ip_ips=ips,
        relay_domains=domains,
        relay_claims=relay_claims,
        port_leases=port_leases,
        subscription_id=subscription_id,
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


@v3_router.get(
    "/wireguard/peers",
    response_model=WireGuardDesiredStateV3Response,
    dependencies=[Depends(_require_relay_secret)],
)
def wireguard_peers_v3(session: Session = Depends(get_session)) -> WireGuardDesiredStateV3Response:
    snapshot = wireguard_desired_state_v3(session)
    return WireGuardDesiredStateV3Response(
        revision=snapshot.revision,
        generated_at=snapshot.generated_at,
        managed_prefixes=snapshot.managed_prefixes,
        peers=[WireGuardDesiredPeerResponse(**vars(peer)) for peer in snapshot.peers],
        smtp_allowed_prefixes=snapshot.smtp_allowed_prefixes,
        prefix_bindings=[
            WireGuardPrefixBindingResponse(**vars(binding)) for binding in snapshot.prefix_bindings
        ],
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
