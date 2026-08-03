"""Account-scoped encrypted NWC credential lifecycle."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from ..config import settings
from ..core.credentials import CredentialCipher, CredentialError, EncryptedCredential
from ..core.models import User


def _cipher() -> CredentialCipher:
    return CredentialCipher(settings.CREDENTIAL_ENCRYPTION_KEY)


def store_nwc_credential(user: User, nwc_uri: str, capabilities: tuple[str, ...]) -> None:
    encrypted = _cipher().encrypt(user.public_id, nwc_uri)
    user.nwc_ciphertext = encrypted.ciphertext
    user.nwc_key_version = encrypted.key_version
    user.nwc_generation += 1
    user.nwc_capabilities = json.dumps(sorted(capabilities), separators=(",", ":"))
    user.nwc_last_validated_at = datetime.now(UTC)
    user.has_nwc = True


def decrypt_nwc_credential(user: User, expected_generation: int | None = None) -> str:
    if expected_generation is not None and user.nwc_generation != expected_generation:
        raise CredentialError("wallet credential generation changed")
    if not user.has_nwc or not user.nwc_ciphertext or not user.nwc_key_version:
        raise CredentialError("wallet credential is unavailable")
    return _cipher().decrypt(
        user.public_id,
        EncryptedCredential(user.nwc_ciphertext, user.nwc_key_version),
    )


def clear_nwc_credential(user: User) -> None:
    user.has_nwc = False
    user.nwc_ciphertext = None
    user.nwc_key_version = None
    user.nwc_capabilities = None
    user.nwc_last_validated_at = None
    user.nwc_generation += 1


def nwc_capabilities(user: User) -> tuple[str, ...]:
    if not user.has_nwc or not user.nwc_capabilities:
        return ()
    try:
        value = json.loads(user.nwc_capabilities)
    except (TypeError, ValueError):
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return ()
    return tuple(value)
