"""At-rest NWC credential protection and disclosure boundaries."""

from __future__ import annotations

import base64
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlmodel import Session, select

from blindport.adapters.base import (
    NwcAdapterError,
    NwcBudgetResult,
    NwcBudgetState,
    NwcValidationResult,
)
from blindport.core.credentials import (
    CredentialCipher,
    CredentialError,
    CredentialPurpose,
    EncryptedCredential,
)
from blindport.core.models import User
from blindport.services.nwc_credentials import nwc_capabilities, nwc_encryption


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


def test_nwc_metadata_reader_preserves_legacy_capability_lists() -> None:
    user = User(
        hashed_token="hash",
        has_nwc=True,
        nwc_capabilities='["lookup_invoice","pay_invoice"]',
    )

    assert nwc_capabilities(user) == ("lookup_invoice", "pay_invoice")
    assert nwc_encryption(user) == "nip44_v2"


@pytest.mark.parametrize(
    "metadata",
    [
        "not-json",
        '{"capabilities":["pay_invoice"],"encryption":"unknown"}',
        '{"capabilities":"pay_invoice","encryption":"nip44_v2"}',
        '{"capabilities":["pay_invoice"],"encryption":"nip44_v2","extra":true}',
    ],
)
def test_nwc_metadata_reader_rejects_malformed_metadata(metadata: str) -> None:
    user = User(hashed_token="hash", has_nwc=True, nwc_capabilities=metadata)

    assert nwc_capabilities(user) == ()
    assert nwc_encryption(user) is None


def test_credential_purposes_are_cryptographically_separated() -> None:
    account_id = uuid4()
    cipher = CredentialCipher("33" * 32)
    encrypted = cipher.encrypt(
        account_id,
        "person@example.com",
        purpose=CredentialPurpose.NOTIFICATION_EMAIL,
    )

    assert (
        cipher.decrypt(
            account_id,
            encrypted,
            purpose=CredentialPurpose.NOTIFICATION_EMAIL,
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
            purpose=CredentialPurpose.NOTIFICATION_EMAIL,
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
        "encryption": "nip44_v2",
        "last_validated_at": response.json()["last_validated_at"],
    }
    assert uri not in response.text
    assert "private-secret" not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    status_response = client.get("/api/v1/me/nwc", headers=_auth(token))
    assert status_response.headers["Cache-Control"] == "no-store"
    assert uri not in status_response.text
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


def test_legacy_capability_metadata_is_reported_as_nip44(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://private-wallet?secret=private-secret"
    assert (
        client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token)).status_code
        == 200
    )

    from blindport.db import engine

    with Session(engine) as session:
        session.execute(
            text(
                'UPDATE "user" SET nwc_capabilities = '
                '\'["lookup_invoice","pay_invoice"]\' WHERE is_admin = 0'
            )
        )
        session.commit()

    status_response = client.get("/api/v1/me/nwc", headers=_auth(token))
    assert status_response.status_code == 200
    assert status_response.json()["encryption"] == "nip44_v2"
    client.cookies.set("blindport_token", token)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Connected (NIP-44)" in dashboard.text
    assert uri not in dashboard.text


def test_legacy_nwc_encryption_is_stored_and_shown_without_disclosing_uri(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    from blindport.api import v1 as v1_mod

    monkeypatch.setattr(v1_mod.settings, "NWC_ALLOW_LEGACY_NIP04", True)
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://legacy-private-secret"
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "validate_connection",
        lambda nwc_uri: NwcValidationResult(
            ("pay_invoice", "lookup_invoice"),
            ("nip04",),
        ),
    )

    connected = client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token))

    assert connected.status_code == 200
    assert connected.json()["encryption"] == "nip04"
    assert uri not in connected.text
    client.cookies.set("blindport_token", token)
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    assert "Connected (legacy NIP-04)" in dashboard.text
    assert "does not authenticate ciphertext" in dashboard.text
    assert uri not in dashboard.text


def test_nwc_api_rejects_legacy_adapter_selection_when_disabled(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://legacy-private-secret"
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "validate_connection",
        lambda nwc_uri: NwcValidationResult(
            ("pay_invoice", "lookup_invoice"),
            ("nip04",),
        ),
    )

    response = client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token))

    assert response.status_code == 502
    assert response.json() == {"detail": "wallet adapter returned an invalid encryption"}
    assert uri not in response.text
    assert client.get("/api/v1/me/nwc", headers=_auth(token)).json()["has_nwc"] is False


def test_nwc_budget_api_returns_only_strict_budget_metadata(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://budget-private-secret"
    assert (
        client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token)).status_code
        == 200
    )
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "get_budget",
        lambda nwc_uri: NwcBudgetResult(
            NwcBudgetState.AVAILABLE,
            used_budget_msats=1_250_000,
            total_budget_msats=5_000_000,
            renews_at=1_800_000_000,
            renewal_period="monthly",
        ),
    )

    response = client.get("/api/v1/me/nwc/budget", headers=_auth(token))

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json() == {
        "state": "available",
        "used_budget_msats": 1_250_000,
        "total_budget_msats": 5_000_000,
        "renews_at": 1_800_000_000,
        "renewal_period": "monthly",
    }
    assert uri not in response.text
    assert "private-secret" not in response.text


def test_nwc_budget_api_requires_a_connection(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.get("/api/v1/me/nwc/budget", headers=_auth(token))

    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"] == "wallet connection is unavailable"


def test_nwc_budget_api_rejects_invalid_adapter_metadata(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    uri = "nostr+walletconnect://invalid-budget-private-secret"
    assert (
        client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token)).status_code
        == 200
    )
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "get_budget",
        lambda nwc_uri: NwcBudgetResult(
            NwcBudgetState.AVAILABLE,
            used_budget_msats=2_000,
            total_budget_msats=1_000,
            renewal_period="monthly",
        ),
    )

    response = client.get("/api/v1/me/nwc/budget", headers=_auth(token))

    assert response.status_code == 502
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"] == "wallet adapter returned an invalid budget"
    assert uri not in response.text
    assert "private-secret" not in response.text


def test_nwc_budget_api_treats_protocol_failure_as_upstream(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    assert (
        client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://protocol-failure"},
            headers=_auth(token),
        ).status_code
        == 200
    )
    monkeypatch.setattr(
        factory.get_nwc_adapter(),
        "get_budget",
        lambda nwc_uri: (_ for _ in ()).throw(
            NwcAdapterError(
                "protocol", "wallet helper returned an invalid response", retryable=False
            )
        ),
    )

    response = client.get("/api/v1/me/nwc/budget", headers=_auth(token))

    assert response.status_code == 502
    assert response.headers["Cache-Control"] == "no-store"
    assert response.json()["detail"] == "wallet helper returned an invalid response"


def test_nwc_budget_api_is_rate_limited_before_wallet_access(app_client, monkeypatch) -> None:
    client, factory = app_client
    token = client.post("/api/v1/signup").json()["token"]
    assert (
        client.post(
            "/api/v1/me/nwc",
            json={"nwc_uri": "nostr+walletconnect://budget-rate-limit"},
            headers=_auth(token),
        ).status_code
        == 200
    )
    from blindport.services import rate_limits

    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_PAYMENT_CREATE_REQUESTS", 2)
    budget_calls = 0

    def get_budget(nwc_uri: str) -> NwcBudgetResult:
        nonlocal budget_calls
        budget_calls += 1
        return NwcBudgetResult(NwcBudgetState.UNSUPPORTED)

    monkeypatch.setattr(factory.get_nwc_adapter(), "get_budget", get_budget)

    assert client.get("/api/v1/me/nwc/budget", headers=_auth(token)).status_code == 200
    limited = client.get("/api/v1/me/nwc/budget", headers=_auth(token))

    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "no-store"
    assert "Retry-After" in limited.headers
    assert budget_calls == 1


def test_invalid_nwc_uri_is_not_reflected_by_api(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    oversized = "nostr+walletconnect://" + "private-secret" * 400

    response = client.post("/api/v1/me/nwc", json={"nwc_uri": oversized}, headers=_auth(token))

    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert oversized not in response.text
    assert "private-secret" not in response.text


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        ('{"nwc_uri":', "application/json"),
        ('{"nwc_uri":7}', "application/json"),
        ('{"nwc_uri":"nostr+walletconnect://private","private-secret":true}', "application/json"),
        ('{"nwc_uri":"nostr+walletconnect://private-secret"}', "text/plain"),
    ],
)
def test_malformed_nwc_requests_are_bounded_non_cacheable_and_do_not_reflect_input(
    app_client, content: str, content_type: str
) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post(
        "/api/v1/me/nwc",
        content=content,
        headers={**_auth(token), "Content-Type": content_type},
    )

    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert "private" not in response.text
    assert content not in response.text


def test_oversized_nwc_request_body_is_rejected_without_reflection(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    secret = "private-secret" * 2_000

    response = client.post(
        "/api/v1/me/nwc",
        content=f'{{"nwc_uri":"{secret}"}}',
        headers={**_auth(token), "Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
    assert secret not in response.text


def test_nwc_request_accepts_application_json_suffix_media_type(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post(
        "/api/v1/me/nwc",
        content='{"nwc_uri":"nostr+walletconnect://vendor-json"}',
        headers={**_auth(token), "Content-Type": "application/vnd.blindport+json"},
    )

    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_nwc_rate_limit_response_is_not_cacheable(app_client, monkeypatch) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    from blindport.services import rate_limits

    monkeypatch.setattr(rate_limits.settings, "RATE_LIMIT_PAYMENT_CREATE_REQUESTS", 1)
    body = {"nwc_uri": "nostr+walletconnect://rate-limited"}

    assert client.post("/api/v1/me/nwc", json=body, headers=_auth(token)).status_code == 200
    limited = client.post("/api/v1/me/nwc", json=body, headers=_auth(token))

    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "no-store"
    assert "Retry-After" in limited.headers


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

    assert revoked.headers["Cache-Control"] == "no-store"
    assert revoked.json() == {
        "has_nwc": False,
        "capabilities": [],
        "encryption": None,
        "last_validated_at": None,
    }
    current = client.get("/api/v1/me", headers=_auth(token)).json()
    assert current["subscriptions"][0]["auto_renew"] is False


def test_nwc_setup_atomically_enables_automatic_renewal(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "transport": "tcp"},
        headers=_auth(token),
    ).json()

    connected = client.post(
        "/api/v1/me/nwc",
        json={
            "nwc_uri": "nostr+walletconnect://automatic-renewal",
            "auto_renew_subscription_id": subscription["id"],
        },
        headers=_auth(token),
    )

    assert connected.status_code == 200
    current = client.get("/api/v1/me", headers=_auth(token)).json()
    assert current["subscriptions"][0]["auto_renew"] is True


def test_nwc_setup_rejects_another_accounts_subscription_without_storing_credential(
    app_client,
) -> None:
    client, _ = app_client
    first_token = client.post("/api/v1/signup").json()["token"]
    second_token = client.post("/api/v1/signup").json()["token"]
    second_subscription = client.post(
        "/api/v1/subscriptions",
        json={"product": "port", "transport": "tcp"},
        headers=_auth(second_token),
    ).json()

    rejected = client.post(
        "/api/v1/me/nwc",
        json={
            "nwc_uri": "nostr+walletconnect://must-not-be-stored",
            "auto_renew_subscription_id": second_subscription["id"],
        },
        headers=_auth(first_token),
    )

    assert rejected.status_code == 404
    assert rejected.headers["Cache-Control"] == "no-store"
    assert client.get("/api/v1/me/nwc", headers=_auth(first_token)).json()["has_nwc"] is False


def test_nwc_payments_use_each_accounts_own_decrypted_connection(app_client, monkeypatch) -> None:
    client, factory = app_client
    adapter = factory.get_nwc_adapter()
    original_pay_invoice = adapter.pay_invoice
    observed_uris: list[str] = []

    def capture_uri(nwc_uri: str, bolt11: str):
        observed_uris.append(nwc_uri)
        return original_pay_invoice(nwc_uri, bolt11)

    monkeypatch.setattr(adapter, "pay_invoice", capture_uri)
    expected: list[str] = []
    for marker in ("first", "second"):
        token = client.post("/api/v1/signup").json()["token"]
        uri = f"nostr+walletconnect://{marker}-account"
        expected.append(uri)
        client.post("/api/v1/me/nwc", json={"nwc_uri": uri}, headers=_auth(token))
        subscription = client.post(
            "/api/v1/subscriptions",
            json={"product": "port", "transport": "tcp"},
            headers=_auth(token),
        ).json()
        payment = client.post(
            "/api/v1/payments",
            json={"subscription_id": subscription["id"], "method": "nwc"},
            headers=_auth(token),
        )
        assert payment.status_code == 200

    assert observed_uris == expected


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
