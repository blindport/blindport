"""Client-owned WireGuard enrollment and relay desired-state snapshots."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from ..config import settings
from ..core.models import (
    ClientCredential,
    DeliveryMode,
    IPLease,
    IPLeaseDelivery,
    IPLeaseState,
    ProductType,
    Subscription,
    SubscriptionStatus,
    User,
    WireGuardPeer,
)
from ..core.wireguard import wireguard_enrollment_message
from .subscriptions import expire_elapsed_subscriptions


class WireGuardEnrollmentConflictError(ValueError):
    """The requested peer key conflicts with the account's enrolled key."""


@dataclass(frozen=True)
class WireGuardClientConfig:
    instance_id: str
    generation: int
    public_key: str | None
    assigned_prefixes: list[str]
    relay_public_key: str
    endpoint: str
    mtu: int
    persistent_keepalive_seconds: int


@dataclass(frozen=True)
class WireGuardDesiredPeer:
    public_key: str
    allowed_prefixes: list[str]


@dataclass(frozen=True)
class WireGuardDesiredState:
    revision: str
    generated_at: datetime
    managed_prefixes: list[str]
    peers: list[WireGuardDesiredPeer]


@dataclass(frozen=True)
class WireGuardDesiredStateV2(WireGuardDesiredState):
    smtp_allowed_prefixes: list[str]


@dataclass(frozen=True)
class WireGuardPrefixBinding:
    prefix: str
    subscription_id: UUID


@dataclass(frozen=True)
class WireGuardDesiredStateV3(WireGuardDesiredStateV2):
    prefix_bindings: list[WireGuardPrefixBinding]


def _active_routed_subscriptions(
    session: Session, user_id: int | None = None
) -> list[Subscription]:
    statement = (
        select(Subscription)
        .join(User, User.id == Subscription.user_id)
        .where(
            Subscription.product == ProductType.IP,
            Subscription.delivery == DeliveryMode.WIREGUARD,
            Subscription.status == SubscriptionStatus.ACTIVE,
            User.is_suspended.is_(False),  # type: ignore[union-attr]
        )
    )
    if user_id is not None:
        statement = statement.where(Subscription.user_id == user_id)
    rows = list(session.exec(statement).all())
    expire_elapsed_subscriptions(session, rows)
    return [
        row
        for row in rows
        if row.status == SubscriptionStatus.ACTIVE and row.assigned_ip is not None
    ]


def client_config(session: Session, user_id: int) -> WireGuardClientConfig:
    """Return active routed prefixes and the account's enrolled peer metadata."""
    rows = _active_routed_subscriptions(session, user_id)
    if not rows:
        raise ValueError("account has no active WireGuard Blindport IP subscription")
    credential = session.get(ClientCredential, user_id, populate_existing=True)
    if credential is None:
        raise WireGuardEnrollmentConflictError("client identity must be enrolled first")
    peer = session.get(WireGuardPeer, user_id, populate_existing=True)
    if peer is not None and peer.instance_id != credential.instance_id:
        peer = None
    return WireGuardClientConfig(
        instance_id=credential.instance_id,
        generation=peer.generation if peer else 0,
        public_key=peer.public_key if peer else None,
        assigned_prefixes=sorted(f"{row.assigned_ip}/32" for row in rows),
        relay_public_key=settings.WIREGUARD_RELAY_PUBLIC_KEY,
        endpoint=settings.WIREGUARD_ENDPOINT,
        mtu=settings.WIREGUARD_MTU,
        persistent_keepalive_seconds=settings.WIREGUARD_PERSISTENT_KEEPALIVE_SECONDS,
    )


def _verify_identity_signature(
    credential: ClientCredential,
    instance_id: str,
    generation: int,
    public_key: str,
    signature: str,
) -> None:
    if credential.instance_id != instance_id:
        raise WireGuardEnrollmentConflictError("instance_id does not match enrolled identity")
    certificate = x509.load_pem_x509_certificate(credential.client_cert_pem.encode("ascii"))
    identity_key = certificate.public_key()
    if not isinstance(identity_key, Ed25519PublicKey):  # pragma: no cover - CA only issues Ed25519
        raise ValueError("enrolled identity key is not Ed25519")
    try:
        identity_key.verify(
            base64.b64decode(signature, validate=True),
            wireguard_enrollment_message(instance_id, generation, public_key),
        )
    except InvalidSignature as error:
        raise ValueError("WireGuard key signature is invalid") from error


def _raise_conflict(current: WireGuardPeer | None, instance_id: str, generation: int) -> None:
    if current is None:
        raise WireGuardEnrollmentConflictError("WireGuard public key is already enrolled")
    if current.instance_id != instance_id:
        raise WireGuardEnrollmentConflictError("a different instance_id owns the WireGuard key")
    if generation < current.generation:
        raise WireGuardEnrollmentConflictError("generation is stale")
    raise WireGuardEnrollmentConflictError("generation must advance by exactly one")


def enroll_key(
    session: Session,
    user_id: int,
    instance_id: str,
    generation: int,
    public_key: str,
    signature: str,
) -> WireGuardClientConfig:
    """Enroll or rotate one account peer with signed, retry-safe generations."""
    config = client_config(session, user_id)
    credential = session.get(ClientCredential, user_id, populate_existing=True)
    if credential is None:  # pragma: no cover - client_config already guards this
        raise WireGuardEnrollmentConflictError("client identity must be enrolled first")
    _verify_identity_signature(credential, instance_id, generation, public_key, signature)
    current = session.get(WireGuardPeer, user_id, populate_existing=True)
    if current is not None and current.instance_id != instance_id:
        if generation != 1:
            raise WireGuardEnrollmentConflictError(
                "first enrollment after an identity reset requires generation 1"
            )
        result = session.execute(
            update(WireGuardPeer)
            .where(
                WireGuardPeer.user_id == user_id,
                WireGuardPeer.instance_id == current.instance_id,
                WireGuardPeer.generation == current.generation,
            )
            .values(
                instance_id=instance_id,
                public_key=public_key,
                generation=generation,
                updated_at=datetime.now(UTC),
            )
            .execution_options(synchronize_session=False)
        )
        try:
            session.commit()
        except IntegrityError as error:
            session.rollback()
            raise WireGuardEnrollmentConflictError(
                "WireGuard public key is already enrolled"
            ) from error
        if result.rowcount != 1:
            winner = session.get(WireGuardPeer, user_id, populate_existing=True)
            if (
                winner is None
                or winner.instance_id != instance_id
                or winner.public_key != public_key
                or winner.generation != generation
            ):
                _raise_conflict(winner, instance_id, generation)
        return client_config(session, user_id)
    if current is None:
        if generation != 1:
            raise WireGuardEnrollmentConflictError("first enrollment requires generation 1")
        now = datetime.now(UTC)
        session.add(
            WireGuardPeer(
                user_id=user_id,
                instance_id=instance_id,
                public_key=public_key,
                generation=generation,
                created_at=now,
                updated_at=now,
            )
        )
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            winner = session.get(WireGuardPeer, user_id, populate_existing=True)
            if winner is None or winner.public_key != public_key or winner.generation != generation:
                _raise_conflict(winner, instance_id, generation)
        return client_config(session, user_id)

    if (
        current.instance_id == instance_id
        and current.public_key == public_key
        and current.generation == generation
    ):
        return config
    if current.instance_id != instance_id or generation != current.generation + 1:
        _raise_conflict(current, instance_id, generation)
    result = session.execute(
        update(WireGuardPeer)
        .where(
            WireGuardPeer.user_id == user_id,
            WireGuardPeer.instance_id == instance_id,
            WireGuardPeer.generation == current.generation,
        )
        .values(public_key=public_key, generation=generation, updated_at=datetime.now(UTC))
        .execution_options(synchronize_session=False)
    )
    try:
        session.commit()
    except IntegrityError as error:
        session.rollback()
        raise WireGuardEnrollmentConflictError(
            "WireGuard public key is already enrolled"
        ) from error
    if result.rowcount != 1:
        winner = session.get(WireGuardPeer, user_id, populate_existing=True)
        if winner is None or winner.public_key != public_key or winner.generation != generation:
            _raise_conflict(winner, instance_id, generation)
    return client_config(session, user_id)


def desired_state(session: Session) -> WireGuardDesiredState:
    """Build a deterministic complete relay snapshot without tenant identifiers."""
    rows = _active_routed_subscriptions(session)
    prefixes_by_user: dict[int, list[str]] = {}
    for row in rows:
        prefixes_by_user.setdefault(row.user_id, []).append(f"{row.assigned_ip}/32")
    peers: list[WireGuardDesiredPeer] = []
    for user_id, prefixes in prefixes_by_user.items():
        peer = session.get(WireGuardPeer, user_id, populate_existing=True)
        credential = session.get(ClientCredential, user_id, populate_existing=True)
        if (
            peer is not None
            and credential is not None
            and peer.instance_id == credential.instance_id
        ):
            peers.append(
                WireGuardDesiredPeer(
                    public_key=peer.public_key,
                    allowed_prefixes=sorted(prefixes),
                )
            )
    peers.sort(key=lambda peer: peer.public_key)
    managed = sorted(f"{address}/32" for address in settings.wireguard_public_ips_list)
    canonical = json.dumps(
        {
            "managed_prefixes": managed,
            "peers": [vars(peer) for peer in peers],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return WireGuardDesiredState(
        revision=hashlib.sha256(canonical).hexdigest(),
        generated_at=datetime.now(UTC),
        managed_prefixes=managed,
        peers=peers,
    )


def desired_state_v2(session: Session) -> WireGuardDesiredStateV2:
    """Build the v2 snapshot with default-deny outbound SMTP exceptions."""
    base = desired_state(session)
    active_prefixes = {prefix for peer in base.peers for prefix in peer.allowed_prefixes}
    approved = session.exec(
        select(IPLease).where(
            IPLease.delivery == IPLeaseDelivery.WIREGUARD,
            IPLease.state == IPLeaseState.ACTIVE,
            IPLease.released_at.is_(None),  # type: ignore[union-attr]
            IPLease.smtp_enabled.is_(True),  # type: ignore[union-attr]
            IPLease.smtp_reviewed_at.is_not(None),  # type: ignore[union-attr]
            IPLease.smtp_revoked_at.is_(None),  # type: ignore[union-attr]
        )
    ).all()
    smtp_prefixes = sorted(
        prefix for lease in approved if (prefix := f"{lease.address}/32") in active_prefixes
    )
    canonical = json.dumps(
        {
            "managed_prefixes": base.managed_prefixes,
            "peers": [vars(peer) for peer in base.peers],
            "smtp_allowed_prefixes": smtp_prefixes,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return WireGuardDesiredStateV2(
        revision=hashlib.sha256(canonical).hexdigest(),
        generated_at=base.generated_at,
        managed_prefixes=base.managed_prefixes,
        peers=base.peers,
        smtp_allowed_prefixes=smtp_prefixes,
    )


def desired_state_v3(session: Session) -> WireGuardDesiredStateV3:
    """Build the v3 snapshot with per-routed-prefix subscription attribution."""
    base = desired_state_v2(session)
    bindings = sorted(
        (
            WireGuardPrefixBinding(
                prefix=f"{subscription.assigned_ip}/32",
                subscription_id=subscription.public_id,
            )
            for subscription in _active_routed_subscriptions(session)
        ),
        key=lambda binding: binding.prefix,
    )
    canonical = json.dumps(
        {
            "managed_prefixes": base.managed_prefixes,
            "peers": [vars(peer) for peer in base.peers],
            "smtp_allowed_prefixes": base.smtp_allowed_prefixes,
            "prefix_bindings": [
                {"prefix": binding.prefix, "subscription_id": str(binding.subscription_id)}
                for binding in bindings
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return WireGuardDesiredStateV3(
        revision=hashlib.sha256(canonical).hexdigest(),
        generated_at=base.generated_at,
        managed_prefixes=base.managed_prefixes,
        peers=base.peers,
        smtp_allowed_prefixes=base.smtp_allowed_prefixes,
        prefix_bindings=bindings,
    )
