"""Versioned AES-GCM protection for account-scoped wallet credentials."""

from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_PREFIX = "v1."
_MAX_CIPHERTEXT_LENGTH = 8192


class CredentialPurpose(StrEnum):
    """Closed set of AAD domains for encrypted account-scoped values."""

    NWC = "nwc"
    NOTIFICATION_EMAIL = "notification-email"


class CredentialError(ValueError):
    """Credential configuration or authentication failed without exposing material."""


def parse_credential_keyring(value: str) -> tuple[bytes, ...]:
    if not value or value.strip() != value:
        raise CredentialError("credential encryption keyring is not configured")
    encoded = value.split(",")
    if any(len(key) != 64 or key.lower() != key for key in encoded):
        raise CredentialError("credential encryption keys must be 64 lowercase hex characters")
    try:
        keys = tuple(bytes.fromhex(key) for key in encoded)
    except ValueError as error:
        raise CredentialError(
            "credential encryption keys must be 64 lowercase hex characters"
        ) from error
    if any(len(key) != 32 for key in keys) or len(set(keys)) != len(keys):
        raise CredentialError("credential encryption keys must be distinct 32-byte values")
    return keys


def _key_version(key: bytes) -> str:
    return hashlib.sha256(b"blindport:credential-key:v1:" + key).hexdigest()[:32]


def _aad(account_id: UUID, purpose: str) -> bytes:
    return f"blindport:credential:v1:{account_id}:{purpose}".encode("ascii")


@dataclass(frozen=True)
class EncryptedCredential:
    ciphertext: str
    key_version: str


class CredentialCipher:
    def __init__(self, keyring: str) -> None:
        keys = parse_credential_keyring(keyring)
        self._keys = {_key_version(key): key for key in keys}
        self._primary = keys[0]

    def encrypt(
        self,
        account_id: UUID,
        plaintext: str,
        *,
        purpose: CredentialPurpose = CredentialPurpose.NWC,
    ) -> EncryptedCredential:
        raw = plaintext.encode("utf-8")
        if not raw or len(raw) > 4096:
            raise CredentialError("credential is empty or too large")
        nonce = os.urandom(12)
        encrypted = AESGCM(self._primary).encrypt(nonce, raw, _aad(account_id, purpose.value))
        envelope = base64.urlsafe_b64encode(nonce + encrypted).rstrip(b"=").decode("ascii")
        return EncryptedCredential(_PREFIX + envelope, _key_version(self._primary))

    def decrypt(
        self,
        account_id: UUID,
        credential: EncryptedCredential,
        *,
        purpose: CredentialPurpose = CredentialPurpose.NWC,
    ) -> str:
        if (
            not credential.ciphertext.startswith(_PREFIX)
            or len(credential.ciphertext) > _MAX_CIPHERTEXT_LENGTH
        ):
            raise CredentialError("credential envelope is invalid")
        key = self._keys.get(credential.key_version)
        if key is None:
            raise CredentialError("credential key version is unavailable")
        encoded = credential.ciphertext[len(_PREFIX) :]
        try:
            payload = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True
            )
        except (ValueError, base64.binascii.Error) as error:
            raise CredentialError("credential envelope is invalid") from error
        if len(payload) < 12 + 16:
            raise CredentialError("credential envelope is invalid")
        canonical = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
        if canonical != encoded:
            raise CredentialError("credential envelope is invalid")
        try:
            plaintext = AESGCM(key).decrypt(
                payload[:12], payload[12:], _aad(account_id, purpose.value)
            )
        except InvalidTag as error:
            raise CredentialError("credential authentication failed") from error
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError as error:
            raise CredentialError("credential plaintext is invalid") from error
