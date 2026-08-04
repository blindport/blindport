"""At-rest NWC credential protection and disclosure boundaries."""

from __future__ import annotations

import base64
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlmodel import Session, select

from blindport.core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_aes_gcm_round_trip_tamper_and_aad_binding() -> None:
    account_id = uuid4()
    plaintext = "nostr+walletconnect://wallet?relay=wss%3A%2F%2Frelay&secret=" + "11" * 32
    cipher = CredentialCipher("aa" * 32)

    encrypted = cipher.encrypt(account_id, plaintext)

    assert plaintext not in encrypted.ciphertext
    assert cipher.decrypt(account_id, encrypted) == plaintext
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(uuid4(), encrypted)
    encoded = encrypted.ciphertext.removeprefix("v1.")
    payload = bytearray(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    payload[-1] ^= 1
    tampered_text = base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")
    tampered = EncryptedCredential("v1." + tampered_text, encrypted.key_version)
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(account_id, tampered)


def test_key_rotation_encrypts_with_first_key_and_decrypts_old_versions() -> None:
    account_id = uuid4()
    old_cipher = CredentialCipher("11" * 32)
    old = old_cipher.encrypt(account_id, "old credential")
    rotated = CredentialCipher(f"{'22' * 32},{'11' * 32}")

    assert rotated.decrypt(account_id, old) == "old credential"
    new = rotated.encrypt(account_id, "new credential")
    assert new.key_version != old.key_version
    with pytest.raises(CredentialError, match="unavailable"):
        old_cipher.decrypt(account_id, new)


def test_credential_purposes_are_cryptographically_separated() -> None:
    account_id = uuid4()
    cipher = CredentialCipher("33" * 32)
    encrypted = cipher.encrypt(
        account_id,
        "person@example.com",
        purpose=CredentialPurpose.REMINDER_EMAIL,
    )

    assert (
        cipher.decrypt(
            account_id,
            encrypted,
            purpose=CredentialPurpose.REMINDER_EMAIL,
        )
        == "person@example.com"
    )
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(account_id, encrypted)

    nwc = cipher.encrypt(account_id, "nostr+walletconnect://wallet")
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(
            account_id,
            nwc,
            purpose=CredentialPurpose.REMINDER_EMAIL,
        )


def test_nwc_api_and_database_never_disclose_plaintext(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://private-wallet?secret=private-secret"

    response = client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token))

    assert response.status_code == 200
    assert response.json() == {
        "has_nwc": True,
        "capabilities": ["lookup_invoice", "pay_invoice"],
        "last_validated_at": response.json()["last_validated_at"],
    }
    assert uri not in response.text
    assert "private-secret" not in response.text
    assert uri not in client.get("/api/v1/me/nwc", headers=_auth(token)).text
    assert uri not in client.get("/api/v1/me", headers=_auth(token)).text

    from blindport.db import engine

    with Session(engine) as session:
        row = session.execute(
            text(
                'SELECT nwc_uri, nwc_ciphertext, nwc_key_version, has_nwc FROM "user" '
                "WHERE is_admin = 0"
            )
        ).one()
    assert row.nwc_uri is None
    assert uri not in row.nwc_ciphertext
    assert row.nwc_key_version
    assert bool(row.has_nwc) is True


def test_invalid_nwc_uri_is_not_reflected_by_api(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    oversized = "nostr+walletconnect://" + "private-secret" * 400

    response = client.post("/api/v1/me/nwc", json={"nwc_uri": oversized}, headers=_auth(token))

    assert response.status_code == 400
    assert oversized not in response.text
    assert "private-secret" not in response.text


def test_nwc_delete_revokes_and_disables_auto_renew(app_client) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://delete-test"},
        headers=_auth(token),
    )
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()
    initial = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(initial["payment_hash"])
    client.get(f"/api/v1/payments/{initial['id']}", headers=_auth(token))
    enabled = client.post(
        f"/api/v1/subscriptions/{subscription['id']}/auto-renew?enable=true",
        headers=_auth(token),
    )
    assert enabled.json()["auto_renew"] is True

    revoked = client.delete("/api/v1/me/nwc", headers=_auth(token))

    assert revoked.json() == {
        "has_nwc": False,
        "capabilities": [],
        "last_validated_at": None,
    }
    current = client.get("/api/v1/me", headers=_auth(token)).json()
    assert current["subscriptions"][0]["auto_renew"] is False


def test_nwc_rotation_and_deletion_are_blocked_during_open_payment(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://open-payment"},
        headers=_auth(token),
    )
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "port"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "nwc"},
        headers=_auth(token),
    )
    assert payment.status_code == 200
    assert payment.json()["status"] == "pending"

    rotated = client.post(
        "/api/v1/me/nwc",
        json={"nwc_uri": "nostr+walletconnect://replacement"},
        headers=_auth(token),
    )
    deleted = client.delete("/api/v1/me/nwc", headers=_auth(token))

    assert rotated.status_code == 409
    assert deleted.status_code == 409
    assert "while an NWC payment is open" in rotated.json()["detail"]


def test_locked_wallet_row_refreshes_generation_after_lock_wait(app_client) -> None:
    client, _ = app_client
    client.post("/api/v1/signup")

    from blindport.api.v1 import _locked_nwc_user
    from blindport.core.models import User
    from blindport.db import engine

    with Session(engine) as stale_session:
        stale = stale_session.exec(select(User).where(User.is_admin.is_(False))).one()
        original_generation = stale.nwc_generation
        with Session(engine) as winning_session:
            winner = winning_session.get(User, stale.id)
            assert winner is not None
            winner.nwc_generation += 1
            winning_session.add(winner)
            winning_session.commit()

        locked = _locked_nwc_user(stale_session, stale)

        assert locked.nwc_generation == original_generation + 1
