"""Canonical signed offline framed-entitlement artifacts."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

from ..config import StableRelayEdge, load_offline_entitlement_private_key
from ..core.ca import parse_client_certificate_common_name
from ..core.hostnames import canonicalize_hostname
from ..core.models import ClientCredential, ProductType, Subscription, Transport, User
from .relay_routing import RelayEdge

_ARTIFACT_PREFIX = "v1"
_ARTIFACT_MAX_BYTES = 2048
_GENERATION_BITS = 31
_MAX_GENERATION = (1 << _GENERATION_BITS) - 1
_MAX_UNIX_SECONDS = ((1 << 63) - 1) >> _GENERATION_BITS
_JTI_SCOPE_DOMAIN = b"blindport-offline-entitlement-jti-v1"


class OfflineEntitlementError(ValueError):
    """An entitlement cannot safely be issued from the supplied state."""


@dataclass(frozen=True)
class EntitlementClaim:
    account: UUID
    subscription: UUID
    instance: UUID
    client_pk: bytes
    edge: StableRelayEdge
    relay_edge: RelayEdge
    kind: ProductType
    ip: str = ""
    port: int = 0
    transport: str = ""
    domain: str = ""
    paid_through: int = 0


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unix_seconds(value: datetime) -> int:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return int(value.astimezone(UTC).timestamp())


def _normalized_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _canonical_claim_fields(claim: EntitlementClaim) -> tuple[str, str, int, str, str]:
    if claim.kind == ProductType.PORT:
        if not 1 <= claim.port <= 65535 or claim.transport not in {"tcp", "udp"}:
            raise OfflineEntitlementError("Port claim is invalid")
        try:
            return claim.kind.value, str(ip_address(claim.ip)), claim.port, claim.transport, ""
        except ValueError as error:
            raise OfflineEntitlementError("Port claim is invalid") from error
    if claim.kind == ProductType.IP:
        if claim.port != 0 or claim.transport or claim.domain:
            raise OfflineEntitlementError("Blindport IP claim is invalid")
        try:
            return claim.kind.value, str(ip_address(claim.ip)), 0, "", ""
        except ValueError as error:
            raise OfflineEntitlementError("Blindport IP claim is invalid") from error
    if claim.kind == ProductType.RELAY:
        if claim.ip or claim.port != 0 or claim.transport:
            raise OfflineEntitlementError("Blindport Relay claim is invalid")
        try:
            return claim.kind.value, "", 0, "", canonicalize_hostname(claim.domain)
        except ValueError as error:
            raise OfflineEntitlementError("Blindport Relay claim is invalid") from error
    raise OfflineEntitlementError("claim kind is invalid")


def _scope_digest(claim: EntitlementClaim, credential_generation: int) -> bytes:
    if len(claim.client_pk) != 32:
        raise OfflineEntitlementError("client public key must be 32 raw bytes")
    entitlement_generation(claim.paid_through, credential_generation)
    kind, claim_ip, port, transport, domain = _canonical_claim_fields(claim)
    fields = (
        (b"account", claim.account.bytes),
        (b"subscription", claim.subscription.bytes),
        (b"instance", claim.instance.bytes),
        (b"credential_generation", credential_generation.to_bytes(4, "big")),
        (b"client_pk", claim.client_pk),
        (b"edge", claim.edge.id.encode("utf-8")),
        (b"kind", kind.encode("ascii")),
        (b"ip", claim_ip.encode("ascii")),
        (b"port", port.to_bytes(2, "big")),
        (b"transport", transport.encode("ascii")),
        (b"domain", domain.encode("ascii")),
        (b"paid_through", claim.paid_through.to_bytes(8, "big")),
    )
    encoded = bytearray()
    for name, value in ((_JTI_SCOPE_DOMAIN, b""), *fields):
        encoded.extend(len(name).to_bytes(2, "big"))
        encoded.extend(name)
        encoded.extend(len(value).to_bytes(4, "big"))
        encoded.extend(value)
    return hashlib.sha256(encoded).digest()


def deterministic_entitlement_jti(claim: EntitlementClaim, credential_generation: int) -> bytes:
    """Return the fixed 16-byte identifier for one authorization scope."""
    return _scope_digest(claim, credential_generation)[:16]


def entitlement_issued_at(
    subscription: Subscription,
    credential: ClientCredential,
    *,
    now: datetime | None = None,
) -> datetime:
    """Choose a stable, currently valid issue time for a subscription entitlement."""
    if subscription.current_period_end is None:
        raise OfflineEntitlementError("subscription has no active paid-through time")
    current = _normalized_utc(now or datetime.now(UTC))
    starts = [_normalized_utc(credential.not_before)]
    if subscription.current_period_start is not None:
        starts.append(_normalized_utc(subscription.current_period_start))
    issued_at = max(starts)
    if issued_at > current:
        raise OfflineEntitlementError("entitlement issue time is in the future")
    paid_through = _unix_seconds(subscription.current_period_end)
    issued_at_seconds = _unix_seconds(issued_at)
    if issued_at_seconds > paid_through:
        raise OfflineEntitlementError("entitlement issue time is after paid-through")
    return datetime.fromtimestamp(issued_at_seconds, UTC)


def entitlement_generation(paid_through: int, credential_generation: int) -> int:
    """Bind certificate rotation to the subscription period in one integer generation."""
    if not 0 <= paid_through <= _MAX_UNIX_SECONDS:
        raise OfflineEntitlementError("paid_through is outside the entitlement generation range")
    if not 1 <= credential_generation <= _MAX_GENERATION:
        raise OfflineEntitlementError(
            "credential generation is outside the entitlement generation range"
        )
    return (paid_through << _GENERATION_BITS) | credential_generation


def enrolled_client_public_key(
    credential: ClientCredential,
    user: User,
    instance_id: str,
    *,
    now: datetime | None = None,
) -> bytes:
    """Return the exact raw enrolled Ed25519 key after validating its certificate binding."""
    if credential.user_id != user.id or credential.instance_id != instance_id:
        raise OfflineEntitlementError("client credential does not match this account and instance")
    try:
        instance = UUID(instance_id)
    except ValueError as error:
        raise OfflineEntitlementError("client credential instance is invalid") from error
    if str(instance) != instance_id:
        raise OfflineEntitlementError("client credential instance is invalid")
    if not 1 <= credential.generation <= _MAX_GENERATION:
        raise OfflineEntitlementError("client credential generation is invalid")
    try:
        certificate = x509.load_pem_x509_certificate(credential.client_cert_pem.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise OfflineEntitlementError("client credential certificate is invalid") from error
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    current = current.astimezone(UTC)
    if not (certificate.not_valid_before_utc <= current < certificate.not_valid_after_utc):
        raise OfflineEntitlementError("client credential certificate is not currently valid")
    not_before = (
        credential.not_before.replace(tzinfo=UTC)
        if credential.not_before.tzinfo is None
        else credential.not_before
    )
    not_after = (
        credential.not_after.replace(tzinfo=UTC)
        if credential.not_after.tzinfo is None
        else credential.not_after
    )
    if not (not_before <= current < not_after):
        raise OfflineEntitlementError("client credential certificate is not currently valid")
    try:
        common_name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        identity = parse_client_certificate_common_name(common_name)
        san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (IndexError, ValueError, x509.ExtensionNotFound) as error:
        raise OfflineEntitlementError("client credential certificate binding is invalid") from error
    if identity.account_id != user.public_id or identity.legacy_user_id is not None:
        raise OfflineEntitlementError("client credential certificate account binding is invalid")
    if san.get_values_for_type(x509.UniformResourceIdentifier) != [
        f"urn:blindport:client:{instance_id}"
    ]:
        raise OfflineEntitlementError("client credential certificate instance binding is invalid")
    public_key = certificate.public_key()
    if not isinstance(public_key, Ed25519PublicKey):
        raise OfflineEntitlementError("client credential certificate key is not Ed25519")
    raw_key = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if hashlib.sha256(raw_key).hexdigest() != credential.public_key_fingerprint:
        raise OfflineEntitlementError("client credential certificate key does not match enrollment")
    if credential.serial != f"{certificate.serial_number:x}":
        raise OfflineEntitlementError(
            "client credential certificate serial does not match enrollment"
        )
    return raw_key


def claim_for_subscription(
    subscription: Subscription,
    *,
    account: UUID,
    instance: UUID,
    client_pk: bytes,
    edge: StableRelayEdge,
    relay_edge: RelayEdge,
) -> EntitlementClaim:
    """Create one exact edge-local framed claim from an active subscription."""
    if subscription.current_period_end is None:
        raise OfflineEntitlementError("subscription has no active paid-through time")
    paid_through = _unix_seconds(subscription.current_period_end)
    if subscription.product == ProductType.PORT:
        if not subscription.assigned_port or not subscription.assigned_ip:
            raise OfflineEntitlementError("Port subscription has no assigned tuple")
        return EntitlementClaim(
            account=account,
            subscription=subscription.public_id,
            instance=instance,
            client_pk=client_pk,
            edge=edge,
            relay_edge=relay_edge,
            kind=subscription.product,
            ip=str(ip_address(relay_edge.ip)),
            port=subscription.assigned_port,
            transport=Transport(subscription.transport).value,
            paid_through=paid_through,
        )
    if subscription.product == ProductType.IP:
        if not subscription.assigned_ip:
            raise OfflineEntitlementError("Blindport IP subscription has no assigned address")
        return EntitlementClaim(
            account=account,
            subscription=subscription.public_id,
            instance=instance,
            client_pk=client_pk,
            edge=edge,
            relay_edge=relay_edge,
            kind=subscription.product,
            ip=str(ip_address(subscription.assigned_ip)),
            paid_through=paid_through,
        )
    if subscription.product == ProductType.RELAY:
        if not subscription.domain:
            raise OfflineEntitlementError("Blindport Relay subscription has no domain")
        return EntitlementClaim(
            account=account,
            subscription=subscription.public_id,
            instance=instance,
            client_pk=client_pk,
            edge=edge,
            relay_edge=relay_edge,
            kind=subscription.product,
            domain=canonicalize_hostname(subscription.domain),
            paid_through=paid_through,
        )
    raise OfflineEntitlementError("subscription product is not framed")


class OfflineEntitlementSigner:
    """Signs bounded canonical v1 artifacts with the dedicated Ed25519 key."""

    def __init__(self, key: Ed25519PrivateKey, key_id: str, grace_seconds: int) -> None:
        self._key = key
        self._key_id = key_id
        self._grace_seconds = grace_seconds

    @classmethod
    def from_private_key_file(
        cls, path: str, key_id: str, grace_seconds: int
    ) -> OfflineEntitlementSigner:
        return cls(load_offline_entitlement_private_key(path), key_id, grace_seconds)

    def issue(
        self,
        claim: EntitlementClaim,
        *,
        credential_generation: int,
        now: datetime | None = None,
        jti: bytes | None = None,
    ) -> tuple[str, dict[str, object]]:
        if len(claim.client_pk) != 32:
            raise OfflineEntitlementError("client public key must be 32 raw bytes")
        paid_through = claim.paid_through
        payload_generation = entitlement_generation(paid_through, credential_generation)
        issued_at = _unix_seconds(now or datetime.now(UTC))
        if not 0 <= issued_at <= _MAX_UNIX_SECONDS:
            raise OfflineEntitlementError("iat and nbf are outside the entitlement range")
        token_id = secrets.token_bytes(16) if jti is None else jti
        if len(token_id) != 16:
            raise OfflineEntitlementError("jti must contain 16 raw bytes")
        kind, claim_ip, port, transport, claim_domain = _canonical_claim_fields(claim)
        grace_through = paid_through + self._grace_seconds
        if grace_through > _MAX_UNIX_SECONDS:
            raise OfflineEntitlementError("grace_through is outside the entitlement range")
        payload = {
            "typ": "blindport-offline-entitlement",
            "v": 1,
            "kid": self._key_id,
            "account": str(claim.account),
            "subscription": str(claim.subscription),
            "instance": str(claim.instance),
            "client_pk": _b64url(claim.client_pk),
            "edge": claim.edge.id,
            "kind": kind,
            "ip": claim_ip,
            "port": port,
            "transport": transport,
            "domain": claim_domain,
            "iat": issued_at,
            "nbf": issued_at,
            "paid_through": paid_through,
            "grace_through": grace_through,
            "generation": payload_generation,
            "jti": _b64url(token_id),
        }
        raw_payload = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        signature = self._key.sign(raw_payload)
        artifact = f"{_ARTIFACT_PREFIX}.{_b64url(raw_payload)}.{_b64url(signature)}"
        if len(artifact.encode("ascii")) > _ARTIFACT_MAX_BYTES:
            raise OfflineEntitlementError("entitlement artifact exceeds 2048 bytes")
        return artifact, payload


def issue_subscription_entitlement(
    signer: OfflineEntitlementSigner,
    subscription: Subscription,
    *,
    account: UUID,
    instance: UUID,
    client_pk: bytes,
    edge: StableRelayEdge,
    relay_edge: RelayEdge,
    credential_generation: int,
    now: datetime | None = None,
    jti_factory: Callable[[], bytes] | None = None,
    return_payload: bool = False,
) -> str | tuple[str, dict[str, object]]:
    """Issue the one signed artifact for an active subscription edge claim."""
    claim = claim_for_subscription(
        subscription,
        account=account,
        instance=instance,
        client_pk=client_pk,
        edge=edge,
        relay_edge=relay_edge,
    )
    artifact, payload = signer.issue(
        claim,
        credential_generation=credential_generation,
        now=now,
        jti=None if jti_factory is None else jti_factory(),
    )
    if return_payload:
        return artifact, payload
    return artifact
