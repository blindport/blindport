"""Token generation and verification."""

from __future__ import annotations

import hashlib
import os

from ..config import settings
from . import crockford


def generate_token() -> tuple[str, str]:
    """Generate a new bearer token.

    Returns:
        (display_token, normalized_token): `display_token` is the human-friendly
            grouped form to show the user once. `normalized_token` is what we
            persist (hashed) and compare against.
    """
    raw = os.urandom(settings.TOKEN_BYTES)
    encoded = crockford.encode(raw)
    display = crockford.format_grouped(encoded, settings.TOKEN_GROUP_SIZE)
    normalized = crockford.normalize(encoded)
    return display, normalized


def hash_token(normalized_token: str) -> str:
    """Hash a normalized token for storage with the dedicated token key."""
    h = hashlib.sha256()
    h.update(settings.token_hash_key.encode("utf-8"))
    h.update(b"|")
    h.update(normalized_token.encode("utf-8"))
    return h.hexdigest()


def verify_token(provided: str, stored_hash: str) -> bool:
    """Verify a user-provided token against a stored hash."""
    try:
        normalized = crockford.normalize(provided)
    except Exception:
        return False
    return hash_token(normalized) == stored_hash
