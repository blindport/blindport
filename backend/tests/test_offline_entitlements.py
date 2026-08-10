"""Offline entitlement artifact and v2 provisioning tests."""

from __future__ import annotations

import base64
import json
import multiprocessing
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

from blindport.config import RelayEdge, StableRelayEdge, load_offline_entitlement_private_key
from blindport.core.models import ProductType, RelayHostnameScope
from blindport.services.offline_entitlements import (
    _MAX_UNIX_SECONDS,
    EntitlementClaim,
    OfflineEntitlementError,
    OfflineEntitlementSigner,
    deterministic_entitlement_jti,
    entitlement_generation,
    entitlement_issued_at,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "offline_entitlement_v1.json"
FIXED_PRIVATE_SEED = bytes(range(1, 33))
FIXED_NOW = datetime(2025, 1, 1, tzinfo=UTC)


def _fixture_claim() -> EntitlementClaim:
    return EntitlementClaim(
        account=UUID("12345678-1234-4234-8234-123456789abc"),
        subscription=UUID("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"),
        instance=UUID("11111111-2222-4333-8444-555555555555"),
        client_pk=bytes(range(32)),
        edge=StableRelayEdge("edge-a", "relay-a.example:5443"),
        relay_edge=RelayEdge("relay-a.example:5443", "198.51.100.30"),
        kind=ProductType.PORT,
        ip="198.51.100.30",
        port=10000,
        transport="tcp",
        paid_through=1_735_689_600,
    )


def _decode_part(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _reject_fifo_private_key(path: str) -> None:
    with pytest.raises(ValueError, match="regular file"):
        load_offline_entitlement_private_key(path)


def _csr() -> str:
    key = Ed25519PrivateKey.generate()
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored")]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )


def _activate(client, factory, token: str, product: str, **extra: str) -> dict[str, object]:
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": product, **extra}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    assert client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).status_code == 200
    return subscription


def test_deterministic_artifact_matches_language_neutral_fixture() -> None:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="ascii"))
    key = Ed25519PrivateKey.from_private_bytes(FIXED_PRIVATE_SEED)
    signer = OfflineEntitlementSigner(key, "offline-a", 604800)

    artifact, payload = signer.issue(
        _fixture_claim(), credential_generation=7, now=FIXED_NOW, jti=bytes(range(16, 32))
    )

    prefix, encoded_payload, encoded_signature = artifact.split(".")
    raw_payload = _decode_part(encoded_payload)
    assert prefix == "v1"
    assert artifact == fixture["artifact"]
    assert payload == fixture["claims"]
    assert encoded_signature == fixture["signature_b64url"]
    assert _decode_part(encoded_payload) == _decode_part(fixture["canonical_payload_b64url"])
    assert raw_payload == json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    assert b" " not in raw_payload and b"\n" not in raw_payload
    assert list(payload) == [
        "typ",
        "v",
        "kid",
        "account",
        "subscription",
        "instance",
        "client_pk",
        "edge",
        "kind",
        "ip",
        "port",
        "transport",
        "domain",
        "iat",
        "nbf",
        "paid_through",
        "grace_through",
        "generation",
        "jti",
    ]
    key.public_key().verify(_decode_part(encoded_signature), raw_payload)
    assert _decode_part(fixture["public_key_b64url"]) == key.public_key().public_bytes_raw()


def test_signer_uses_random_jti_by_default() -> None:
    signer = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1)
    first_artifact, first_payload = signer.issue(
        _fixture_claim(), credential_generation=1, now=FIXED_NOW
    )
    second_artifact, second_payload = signer.issue(
        _fixture_claim(), credential_generation=1, now=FIXED_NOW
    )
    assert first_artifact != second_artifact
    assert first_payload["jti"] != second_payload["jti"]


def test_deterministic_scope_values_change_for_every_scope_input() -> None:
    claim = _fixture_claim()
    baseline = (
        deterministic_entitlement_jti(claim, 7),
        entitlement_generation(claim.paid_through, 7),
    )
    changed_scopes = [
        (replace(claim, account=uuid4()), 7),
        (replace(claim, subscription=uuid4()), 7),
        (replace(claim, instance=uuid4()), 7),
        (replace(claim, client_pk=bytes(reversed(range(32)))), 7),
        (replace(claim, edge=StableRelayEdge("edge-b", claim.edge.endpoint)), 7),
        (replace(claim, ip="198.51.100.31"), 7),
        (replace(claim, port=10001), 7),
        (replace(claim, transport="udp"), 7),
        (replace(claim, paid_through=claim.paid_through + 1), 7),
        (claim, 8),
    ]
    for changed_claim, credential_generation in changed_scopes:
        assert len(deterministic_entitlement_jti(changed_claim, credential_generation)) == 16
        assert (
            deterministic_entitlement_jti(changed_claim, credential_generation),
            entitlement_generation(changed_claim.paid_through, credential_generation),
        ) != baseline


def test_wildcard_relay_entitlement_has_distinct_scope_digest_and_v2_payload() -> None:
    key = Ed25519PrivateKey.generate()
    signer = OfflineEntitlementSigner(key, "offline-a", 604800)
    exact = replace(
        _fixture_claim(),
        kind=ProductType.RELAY,
        ip="",
        port=0,
        transport="",
        domain="public.example",
    )
    wildcard = replace(exact, relay_hostname_scope=RelayHostnameScope.WILDCARD)

    exact_artifact, exact_payload = signer.issue(
        exact, credential_generation=7, now=FIXED_NOW, jti=bytes(range(16))
    )
    wildcard_artifact, wildcard_payload = signer.issue(
        wildcard, credential_generation=7, now=FIXED_NOW, jti=bytes(range(16))
    )

    assert deterministic_entitlement_jti(exact, 7) != deterministic_entitlement_jti(wildcard, 7)
    assert exact_payload["v"] == 1 and "scope" not in exact_payload
    assert wildcard_payload["v"] == 2 and wildcard_payload["scope"] == "wildcard"
    assert exact_artifact != wildcard_artifact
    tampered = {**wildcard_payload, "scope": "exact"}
    with pytest.raises(InvalidSignature):
        key.public_key().verify(
            _decode_part(wildcard_artifact.split(".")[2]),
            json.dumps(tampered, separators=(",", ":"), ensure_ascii=True).encode("ascii"),
        )


def test_signer_rejects_wildcard_scope_for_non_relay_claims() -> None:
    signer = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1)
    with pytest.raises(OfflineEntitlementError, match="IP claim"):
        signer.issue(
            replace(
                _fixture_claim(),
                kind=ProductType.IP,
                port=0,
                transport="",
                relay_hostname_scope="wildcard",
            ),
            credential_generation=1,
            now=FIXED_NOW,
            jti=bytes(16),
        )


def test_entitlement_issued_at_uses_latest_state_time_and_stays_within_term() -> None:
    current = datetime(2025, 1, 10, 12, tzinfo=UTC)
    subscription = SimpleNamespace(
        current_period_start=datetime(2025, 1, 5, 9, tzinfo=timezone(timedelta(hours=-5))),
        current_period_end=datetime(2025, 2, 1, tzinfo=UTC),
    )
    credential = SimpleNamespace(not_before=datetime(2025, 1, 5, 15, tzinfo=UTC))
    assert entitlement_issued_at(subscription, credential, now=current) == datetime(
        2025, 1, 5, 15, tzinfo=UTC
    )


def test_entitlement_issued_at_handles_missing_period_start_without_weakening_validity() -> None:
    current = datetime(2025, 1, 10, tzinfo=UTC)
    subscription = SimpleNamespace(
        current_period_start=None,
        current_period_end=datetime(2025, 1, 20, tzinfo=UTC),
    )
    credential = SimpleNamespace(not_before=datetime(2025, 1, 5, tzinfo=UTC))
    assert entitlement_issued_at(subscription, credential, now=current) == credential.not_before

    with pytest.raises(OfflineEntitlementError, match="future"):
        entitlement_issued_at(
            subscription,
            SimpleNamespace(not_before=current + timedelta(seconds=1)),
            now=current,
        )
    with pytest.raises(OfflineEntitlementError, match="after paid-through"):
        entitlement_issued_at(
            SimpleNamespace(
                current_period_start=None,
                current_period_end=datetime(2025, 1, 4, tzinfo=UTC),
            ),
            credential,
            now=current,
        )


@pytest.mark.parametrize(
    "claim",
    [
        EntitlementClaim(
            UUID(int=1),
            UUID(int=2),
            UUID(int=3),
            bytes(32),
            StableRelayEdge("a", "a.test:1"),
            RelayEdge("a.test:1", "192.0.2.1"),
            ProductType.PORT,
            "192.0.2.1",
            0,
            "tcp",
            "",
            1,
        ),
        EntitlementClaim(
            UUID(int=1),
            UUID(int=2),
            UUID(int=3),
            bytes(32),
            StableRelayEdge("a", "a.test:1"),
            RelayEdge("a.test:1", "192.0.2.1"),
            ProductType.PORT,
            "not-an-ip",
            1,
            "tcp",
            "",
            1,
        ),
        EntitlementClaim(
            UUID(int=1),
            UUID(int=2),
            UUID(int=3),
            bytes(32),
            StableRelayEdge("a", "a.test:1"),
            RelayEdge("a.test:1", "192.0.2.1"),
            ProductType.IP,
            "192.0.2.1",
            1,
            "tcp",
            "",
            1,
        ),
        EntitlementClaim(
            UUID(int=1),
            UUID(int=2),
            UUID(int=3),
            bytes(32),
            StableRelayEdge("a", "a.test:1"),
            RelayEdge("a.test:1", "192.0.2.1"),
            ProductType.RELAY,
            "",
            0,
            "",
            "bad_",
            1,
        ),
    ],
)
def test_signer_rejects_malformed_exact_claims(claim: EntitlementClaim) -> None:
    signer = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1)
    with pytest.raises(OfflineEntitlementError):
        signer.issue(claim, credential_generation=1, now=FIXED_NOW, jti=bytes(16))


def test_signer_bounds_generation_time_jti_and_artifact_length() -> None:
    signer = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1)
    claim = _fixture_claim()
    with pytest.raises(OfflineEntitlementError, match="jti"):
        signer.issue(claim, credential_generation=1, now=FIXED_NOW, jti=b"short")
    with pytest.raises(OfflineEntitlementError, match="generation"):
        entitlement_generation(1, 0)
    with pytest.raises(OfflineEntitlementError, match="grace_through"):
        signer.issue(
            EntitlementClaim(**{**claim.__dict__, "paid_through": ((1 << 63) - 1) >> 31}),
            credential_generation=1,
            now=FIXED_NOW,
            jti=bytes(16),
        )
    oversized = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "a" * 4096, 1)
    with pytest.raises(OfflineEntitlementError, match="2048"):
        oversized.issue(claim, credential_generation=1, now=FIXED_NOW, jti=bytes(16))


def test_private_key_loader_requires_bounded_canonical_owner_only_regular_pem(tmp_path) -> None:
    key_path = tmp_path / "offline.pem"
    raw = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(raw)
    key_path.chmod(0o600)
    assert isinstance(load_offline_entitlement_private_key(str(key_path)), Ed25519PrivateKey)

    for content in (b"", raw + b"\n", raw + b"trailing", b"x" * 16385):
        key_path.write_bytes(content)
        key_path.chmod(0o600)
        with pytest.raises(ValueError):
            load_offline_entitlement_private_key(str(key_path))
    key_path.write_bytes(raw)
    key_path.chmod(0o644)
    with pytest.raises(ValueError, match="group or others"):
        load_offline_entitlement_private_key(str(key_path))
    link = tmp_path / "link.pem"
    link.symlink_to(key_path)
    with pytest.raises(ValueError):
        load_offline_entitlement_private_key(str(link))


def test_private_key_loader_rejects_fifo_without_blocking(tmp_path) -> None:
    fifo_path = tmp_path / "offline.fifo"
    os.mkfifo(fifo_path, 0o600)
    process = multiprocessing.get_context("fork").Process(
        target=_reject_fifo_private_key, args=(str(fifo_path),)
    )
    process.start()
    process.join(timeout=1)
    if process.is_alive():
        process.terminate()
        process.join()
        pytest.fail("private key loader blocked while opening a FIFO")
    assert process.exitcode == 0


@pytest.mark.parametrize(
    ("now", "expected"),
    [
        (datetime(1970, 1, 1, tzinfo=UTC), 0),
        (datetime.fromtimestamp(_MAX_UNIX_SECONDS, UTC), _MAX_UNIX_SECONDS),
    ],
)
def test_signer_accepts_exact_iat_nbf_boundaries(now: datetime, expected: int) -> None:
    _, payload = OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1).issue(
        _fixture_claim(), credential_generation=1, now=now, jti=bytes(16)
    )
    assert payload["iat"] == payload["nbf"] == expected


@pytest.mark.parametrize(
    "now",
    [
        datetime(1969, 12, 31, 23, 59, 59, tzinfo=UTC),
        datetime.fromtimestamp(_MAX_UNIX_SECONDS + 1, UTC),
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC),
    ],
)
def test_signer_rejects_iat_nbf_outside_entitlement_range(now: datetime) -> None:
    with pytest.raises(OfflineEntitlementError, match="iat and nbf"):
        OfflineEntitlementSigner(Ed25519PrivateKey.generate(), "key-a", 1).issue(
            _fixture_claim(), credential_generation=1, now=now, jti=bytes(16)
        )


def test_v2_offline_config_returns_signed_exact_provider_local_claims(
    app_client, monkeypatch, tmp_path
) -> None:
    from blindport.api import v2
    from blindport.services import relay_routing

    client, factory = app_client
    token = client.post("/api/v2/signup").json()["token"]
    instance_id = str(uuid4())
    assert (
        client.get(
            f"/api/v2/client/config?instance_id={instance_id}", headers=_auth(token)
        ).status_code
        == 404
    )

    key_path = tmp_path / "offline.pem"
    key_path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    for module in (v2, relay_routing):
        monkeypatch.setattr(module.settings, "RELAY_CONTROL_URL", "primary.example:5443")
        monkeypatch.setattr(
            module.settings, "RELAY_CONTROL_URLS", "primary.example:5443,secondary.example:5443"
        )
        monkeypatch.setattr(
            module.settings,
            "PORT_HA_EDGES",
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"},'
            '{"endpoint":"secondary.example:5443","ip":"203.0.113.21"}]',
        )
        monkeypatch.setattr(
            module.settings,
            "FRAMED_IP_ENDPOINTS",
            '{"203.0.113.10":"secondary.example:5443","203.0.113.11":"secondary.example:5443"}',
        )
        monkeypatch.setattr(
            module.settings,
            "RELAY_EDGES",
            '[{"id":"edge-a","endpoint":"primary.example:5443"},'
            '{"id":"edge-b","endpoint":"secondary.example:5443"}]',
        )
    monkeypatch.setattr(v2.settings, "OFFLINE_ENTITLEMENTS_ENABLED", True)
    monkeypatch.setattr(v2.settings, "OFFLINE_ENTITLEMENT_KEY_ID", "offline-a")
    monkeypatch.setattr(v2.settings, "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE", str(key_path))

    enrolled = client.post(
        "/api/v2/client/certificate",
        headers=_auth(token),
        json={"instance_id": instance_id, "generation": 1, "csr_pem": _csr()},
    )
    assert enrolled.status_code == 200
    port = _activate(client, factory, token, "port")
    relay = _activate(client, factory, token, "relay", domain="node.relay.test")

    response = client.get(f"/api/v2/client/config?instance_id={instance_id}", headers=_auth(token))
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert "PRIVATE KEY" not in response.text and "client_cert_pem" not in response.text
    repeated_response = client.get(
        f"/api/v2/client/config?instance_id={instance_id}", headers=_auth(token)
    )
    assert repeated_response.status_code == 200
    assert repeated_response.content == response.content
    rows = {row["subscription_id"]: row for row in response.json()["subscriptions"]}
    assert rows[port["id"]]["edges"] and {
        edge["claim"]["ip"] for edge in rows[port["id"]]["edges"]
    } == {"203.0.113.20", "203.0.113.21"}
    assert {edge["claim"]["domain"] for edge in rows[relay["id"]]["edges"]} == {"node.relay.test"}
    assert all(
        edge["claim"]
        == {
            key: json.loads(_decode_part(edge["entitlement"].split(".")[1]))[key]
            for key in edge["claim"]
        }
        for row in rows.values()
        for edge in row["edges"]
    )
    assert all(
        {key: edge[key] for key in ("paid_through", "grace_through", "generation")}
        == {
            key: json.loads(_decode_part(edge["entitlement"].split(".")[1]))[key]
            for key in ("paid_through", "grace_through", "generation")
        }
        for row in rows.values()
        for edge in row["edges"]
    )


def test_v2_offline_config_sanitizes_unavailable_signer(app_client, monkeypatch, tmp_path) -> None:
    from blindport.api import v2

    client, _ = app_client
    token = client.post("/api/v2/signup").json()["token"]
    instance_id = str(uuid4())
    monkeypatch.setattr(v2.settings, "OFFLINE_ENTITLEMENTS_ENABLED", True)
    monkeypatch.setattr(v2.settings, "OFFLINE_ENTITLEMENT_KEY_ID", "offline-a")
    monkeypatch.setattr(
        v2.settings, "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE", str(tmp_path / "missing.pem")
    )
    assert (
        client.post(
            "/api/v2/client/certificate",
            headers=_auth(token),
            json={"instance_id": instance_id, "generation": 1, "csr_pem": _csr()},
        ).status_code
        == 200
    )
    response = client.get(f"/api/v2/client/config?instance_id={instance_id}", headers=_auth(token))
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert "missing.pem" not in response.text
