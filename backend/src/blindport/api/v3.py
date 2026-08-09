"""Scope-aware offline provisioning endpoints versioned at /api/v3."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlmodel import Session, select

from ..config import settings
from ..core.auth import current_user
from ..core.models import (
    ClientCredential,
    DeliveryMode,
    ProductType,
    RelayHostnameScope,
    Subscription,
    SubscriptionStatus,
    User,
)
from ..core.schemas import (
    OfflineEntitlementV3ClaimResponse,
    OfflineEntitlementV3ConfigResponse,
    OfflineEntitlementV3EdgeResponse,
    OfflineEntitlementV3ProvisioningResponse,
)
from ..db import get_session
from ..services import relay_routing
from ..services import subscriptions as subs_svc
from ..services.offline_entitlements import (
    OfflineEntitlementError,
    OfflineEntitlementSigner,
    claim_for_subscription,
    deterministic_entitlement_jti,
    enrolled_client_public_key,
    entitlement_issued_at,
    issue_subscription_entitlement,
)
from .v2 import _canonical_instance_id

router = APIRouter(prefix="/api/v3")


@router.get("/client/config", response_model=OfflineEntitlementV3ConfigResponse)
def offline_client_config(
    response: Response,
    instance_id: str = Query(min_length=36, max_length=36),
    user: User = Depends(current_user),
    session: Session = Depends(get_session),
) -> OfflineEntitlementV3ConfigResponse:
    """Return v3 framed provisioning with explicit exact or wildcard scopes."""
    response.headers["Cache-Control"] = "no-store"
    if not settings.OFFLINE_ENTITLEMENTS_ENABLED:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "not found",
            headers={"Cache-Control": "no-store"},
        )
    instance_id = _canonical_instance_id(instance_id)
    credential = session.exec(
        select(ClientCredential)
        .where(
            ClientCredential.user_id == user.id,
            ClientCredential.instance_id == instance_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if credential is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "client credential is not enrolled for instance",
            headers={"Cache-Control": "no-store"},
        )
    try:
        client_pk = enrolled_client_public_key(credential, user, instance_id)
    except OfflineEntitlementError as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            str(error),
            headers={"Cache-Control": "no-store"},
        ) from error
    try:
        signer = OfflineEntitlementSigner.from_private_key_file(
            settings.OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE,
            settings.OFFLINE_ENTITLEMENT_KEY_ID,
            settings.OFFLINE_ENTITLEMENT_GRACE_SECONDS,
        )
    except ValueError as error:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "offline entitlement signer unavailable",
            headers={"Cache-Control": "no-store"},
        ) from error
    subs_svc.reap_expired_domain_claims(session)
    subscriptions = session.exec(
        select(Subscription)
        .where(
            Subscription.user_id == user.id,
            Subscription.status == SubscriptionStatus.ACTIVE,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).all()
    subs_svc.expire_elapsed_subscriptions(session, subscriptions)
    edge_by_endpoint = {edge.endpoint: edge for edge in settings.relay_edges_list}
    rows: list[OfflineEntitlementV3ProvisioningResponse] = []
    for subscription in subscriptions:
        if subscription.status != SubscriptionStatus.ACTIVE:
            continue
        if (
            subscription.product == ProductType.IP
            and subscription.delivery == DeliveryMode.WIREGUARD
        ):
            continue
        if subscription.product == ProductType.PORT and subscription.assigned_ip:
            raw_edges = relay_routing.port_edges(subscription.assigned_ip)
        elif subscription.product == ProductType.IP and subscription.assigned_ip:
            raw_edges = [relay_routing.framed_ip_edge(subscription.assigned_ip)]
        elif subscription.product == ProductType.RELAY:
            raw_edges = [
                relay_routing.RelayEdge(endpoint=edge.endpoint, ip="")
                for edge in settings.relay_edges_list
            ]
        else:
            continue
        relay_hostname_scope = (
            subscription.relay_hostname_scope
            if subscription.product == ProductType.RELAY
            else RelayHostnameScope.EXACT
        )
        edges: list[OfflineEntitlementV3EdgeResponse] = []
        for raw_edge in raw_edges:
            edge = edge_by_endpoint.get(raw_edge.endpoint)
            if edge is None:
                raise HTTPException(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "offline edge map is unavailable",
                    headers={"Cache-Control": "no-store"},
                )
            try:
                claim = claim_for_subscription(
                    subscription,
                    account=user.public_id,
                    instance=UUID(instance_id),
                    client_pk=client_pk,
                    edge=edge,
                    relay_edge=raw_edge,
                )
                jti = deterministic_entitlement_jti(claim, credential.generation)
                entitlement, signed_claim = issue_subscription_entitlement(
                    signer,
                    subscription,
                    account=user.public_id,
                    instance=UUID(instance_id),
                    client_pk=client_pk,
                    edge=edge,
                    relay_edge=raw_edge,
                    credential_generation=credential.generation,
                    now=entitlement_issued_at(subscription, credential, now=datetime.now(UTC)),
                    jti_factory=lambda jti=jti: jti,
                    return_payload=True,
                )
            except OfflineEntitlementError as error:
                raise HTTPException(
                    status.HTTP_409_CONFLICT,
                    str(error),
                    headers={"Cache-Control": "no-store"},
                ) from error
            edges.append(
                OfflineEntitlementV3EdgeResponse(
                    id=edge.id,
                    endpoint=edge.endpoint,
                    claim=OfflineEntitlementV3ClaimResponse(
                        kind=signed_claim["kind"],
                        ip=signed_claim["ip"],
                        port=signed_claim["port"],
                        transport=signed_claim["transport"],
                        domain=signed_claim["domain"],
                        scope=relay_hostname_scope,
                    ),
                    entitlement=entitlement,
                    paid_through=signed_claim["paid_through"],
                    grace_through=signed_claim["grace_through"],
                    generation=signed_claim["generation"],
                )
            )
        rows.append(
            OfflineEntitlementV3ProvisioningResponse(
                assigned_ip=subscription.assigned_ip,
                assigned_port=subscription.assigned_port,
                transport=subscription.transport,
                domain=subscription.domain,
                product=subscription.product,
                subscription_id=subscription.public_id,
                relay_hostname_scope=relay_hostname_scope,
                edges=edges,
            )
        )
    return OfflineEntitlementV3ConfigResponse(subscriptions=rows)
