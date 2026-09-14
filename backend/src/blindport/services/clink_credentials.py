"""Account-scoped encrypted CLINK credential lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime

from ..config import settings
from ..core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from ..core.models import User


def _cipher() -> CredentialCipher:
    return CredentialCipher(settings.CREDENTIAL_ENCRYPTION_KEY)


def store_clink_credential(user: User, ndebit: str) -> None:
    encrypted = _cipher().encrypt(user.public_id, ndebit, purpose=CredentialPurpose.CLINK)
    user.clink_ciphertext = encrypted.ciphertext
    user.clink_key_version = encrypted.key_version
    user.clink_generation += 1
    user.clink_last_validated_at = datetime.now(UTC)
    user.has_clink = True


def decrypt_clink_credential(user: User, expected_generation: int | None = None) -> str:
    if expected_generation is not None and user.clink_generation != expected_generation:
        raise CredentialError("wallet credential generation changed")
    if not user.has_clink or not user.clink_ciphertext or not user.clink_key_version:
        raise CredentialError("wallet credential is unavailable")
    return _cipher().decrypt(
        user.public_id,
        EncryptedCredential(user.clink_ciphertext, user.clink_key_version),
        purpose=CredentialPurpose.CLINK,
    )


def clear_clink_credential(user: User) -> None:
    user.has_clink = False
    user.clink_ciphertext = None
    user.clink_key_version = None
    user.clink_last_validated_at = None
    user.clink_generation += 1
