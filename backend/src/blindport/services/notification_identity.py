"""Encrypted, event-bound resource identities for account notifications."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from uuid import UUID

from .. import config
from ..core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from ..core.models import NotificationDelivery, ProductType, RelayHostnameScope, Subscription, User

_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


def store_resource_identity(
    delivery: NotificationDelivery,
    user: User,
    subscription: Subscription,
    *,
    cipher: CredentialCipher | None = None,
) -> None:
    """Capture an encrypted identity after a delivery has a durable ID.

    Failures intentionally leave the snapshot absent, so notification queueing
    cannot roll back a settled payment or subscription transition.
    """
    if delivery.id is None or delivery.subscription_id != subscription.id:
        return
    identity = resource_identity(subscription)
    if identity is None:
        return
    payload = {
        "v": 1,
        "delivery": delivery.id,
        "subscription": subscription.id,
        "subscription_public_id": str(subscription.public_id),
        "event_at": _event_time(delivery.event_at),
        "product": subscription.product.value,
        "identity": identity,
    }
    try:
        encrypted = (cipher or CredentialCipher(config.settings.CREDENTIAL_ENCRYPTION_KEY)).encrypt(
            user.public_id,
            json.dumps(payload, separators=(",", ":"), sort_keys=True),
            purpose=CredentialPurpose.NOTIFICATION_IDENTITY,
        )
    except CredentialError:
        return
    delivery.resource_identity_ciphertext = encrypted.ciphertext
    delivery.resource_identity_key_version = encrypted.key_version


def snapshot_resource_identity(
    delivery: NotificationDelivery, user: User | None, *, cipher: CredentialCipher | None = None
) -> tuple[str, str] | None:
    """Return an authenticated snapshot, never an unbound or malformed value."""
    if (
        user is None
        or not delivery.resource_identity_ciphertext
        or not delivery.resource_identity_key_version
        or delivery.id is None
    ):
        return None
    try:
        plaintext = (cipher or CredentialCipher(config.settings.CREDENTIAL_ENCRYPTION_KEY)).decrypt(
            user.public_id,
            EncryptedCredential(
                delivery.resource_identity_ciphertext, delivery.resource_identity_key_version
            ),
            purpose=CredentialPurpose.NOTIFICATION_IDENTITY,
        )
        payload = json.loads(plaintext)
    except (CredentialError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict) or payload != {
        "v": 1,
        "delivery": delivery.id,
        "subscription": delivery.subscription_id,
        "subscription_public_id": payload.get("subscription_public_id"),
        "event_at": _event_time(delivery.event_at),
        "product": payload.get("product"),
        "identity": payload.get("identity"),
    }:
        return None
    product = payload["product"]
    identity = payload["identity"]
    public_id = payload["subscription_public_id"]
    if (
        not isinstance(product, str)
        or not isinstance(identity, str)
        or len(identity) > 512
        or not isinstance(public_id, str)
    ):
        return None
    try:
        valid = _valid_identity(ProductType(product), identity)
        UUID(public_id)
    except ValueError:
        return None
    return (identity, public_id) if valid else None


def resource_identity(subscription: Subscription) -> str | None:
    """Render the minimal safe resource value, without any user-controlled formatting."""
    if subscription.product == ProductType.RELAY:
        if not _domain(subscription.domain):
            return None
        if subscription.relay_hostname_scope == RelayHostnameScope.WILDCARD:
            return f"Relay domain: *.{subscription.domain} (also {subscription.domain})"
        return f"Relay domain: {subscription.domain}"
    if subscription.product == ProductType.PORT:
        if not _address(subscription.assigned_ip) or not _port(subscription.assigned_port):
            return None
        transport = subscription.transport.value.upper()
        return f"Port: {subscription.assigned_ip}:{subscription.assigned_port} ({transport})"
    if subscription.product == ProductType.IP:
        if not _address(subscription.assigned_ip):
            return None
        return f"IP address: {subscription.assigned_ip} ({subscription.delivery.value})"
    return None


def _valid_identity(product: ProductType, identity: str) -> bool:
    # Rebuild from parsed data only through the same strict output grammar.
    if product == ProductType.RELAY:
        match = re.fullmatch(
            r"Relay domain: (\*\.)?([a-z0-9.-]+)(?: \(also [a-z0-9.-]+\))?", identity
        )
        return bool(match and _domain(match.group(2)))
    if product == ProductType.PORT:
        match = re.fullmatch(r"Port: ([0-9a-fA-F:.]+):(\d+) \((TCP|UDP)\)", identity)
        return bool(match and _address(match.group(1)) and _port(int(match.group(2))))
    if product == ProductType.IP:
        match = re.fullmatch(r"IP address: ([0-9a-fA-F:.]+) \((framed|wireguard)\)", identity)
        return bool(match and _address(match.group(1)))
    return False


def _domain(value: object) -> bool:
    return isinstance(value, str) and bool(_DOMAIN.fullmatch(value))


def _address(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 45:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _port(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _event_time(value: datetime | None) -> str | None:
    if value is None:
        return None
    return (
        value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    ).isoformat()
