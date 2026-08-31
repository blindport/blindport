"""Account-scoped encrypted CLINK credential lifecycle tests."""

from __future__ import annotations

from datetime import UTC

import pytest

from blindport.core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from blindport.core.models import User
from blindport.services import clink_credentials

_KEY = "ab" * 32
_NDEBIT = "ndebit1testpointer"


def test_store_decrypt_and_clear_clink_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clink_credentials.settings, "CREDENTIAL_ENCRYPTION_KEY", _KEY)
    user = User(hashed_token="clink-credential")

    clink_credentials.store_clink_credential(user, _NDEBIT)

    assert user.has_clink is True
    assert user.clink_ciphertext is not None
    assert _NDEBIT not in user.clink_ciphertext
    assert user.clink_key_version is not None
    assert user.clink_generation == 1
    assert user.clink_last_validated_at is not None
    assert user.clink_last_validated_at.tzinfo == UTC
    assert clink_credentials.decrypt_clink_credential(user, expected_generation=1) == _NDEBIT

    clink_credentials.clear_clink_credential(user)

    assert user.has_clink is False
    assert user.clink_ciphertext is None
    assert user.clink_key_version is None
    assert user.clink_last_validated_at is None
    assert user.clink_generation == 2
    with pytest.raises(CredentialError, match="unavailable"):
        clink_credentials.decrypt_clink_credential(user)


def test_clink_credential_uses_aad_separate_from_nwc(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clink_credentials.settings, "CREDENTIAL_ENCRYPTION_KEY", _KEY)
    user = User(hashed_token="clink-aad")
    cipher = CredentialCipher(_KEY)

    clink_credentials.store_clink_credential(user, _NDEBIT)

    assert user.clink_ciphertext is not None
    assert user.clink_key_version is not None
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(
            user.public_id,
            EncryptedCredential(user.clink_ciphertext, user.clink_key_version),
            purpose=CredentialPurpose.NWC,
        )

    nwc = cipher.encrypt(
        user.public_id, "nostr+walletconnect://wallet", purpose=CredentialPurpose.NWC
    )
    user.clink_ciphertext = nwc.ciphertext
    user.clink_key_version = nwc.key_version
    with pytest.raises(CredentialError, match="authentication failed"):
        clink_credentials.decrypt_clink_credential(user)


def test_clink_credential_generation_is_pinned(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(clink_credentials.settings, "CREDENTIAL_ENCRYPTION_KEY", _KEY)
    user = User(hashed_token="clink-generation")

    clink_credentials.store_clink_credential(user, _NDEBIT)
    clink_credentials.store_clink_credential(user, "ndebit1replacement")

    assert user.clink_generation == 2
    with pytest.raises(CredentialError, match="generation changed"):
        clink_credentials.decrypt_clink_credential(user, expected_generation=1)
    assert (
        clink_credentials.decrypt_clink_credential(user, expected_generation=2)
        == "ndebit1replacement"
    )
