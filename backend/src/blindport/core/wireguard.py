"""Canonical WireGuard key validation and enrollment messages."""

from __future__ import annotations

import base64


def canonical_wireguard_key(value: str, field_name: str = "WireGuard key") -> str:
    """Validate one canonical base64-encoded 32-byte WireGuard key."""
    if not value or value.strip() != value:
        raise ValueError(f"{field_name} must be canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except ValueError as error:
        raise ValueError(f"{field_name} must be canonical base64") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError(f"{field_name} must encode exactly 32 bytes")
    if decoded == bytes(32):
        raise ValueError(f"{field_name} must not be the all-zero key")
    return value


def wireguard_enrollment_message(instance_id: str, generation: int, public_key: str) -> bytes:
    """Return the stable message signed by the enrolled Ed25519 client key."""
    return (
        "blindport-wireguard-key-v1\n"
        f"instance_id={instance_id}\n"
        f"generation={generation}\n"
        f"public_key={public_key}\n"
    ).encode("ascii")
