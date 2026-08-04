"""Tests for the backend mini-CA endpoint at /api/v1/client/cert."""

from __future__ import annotations

import multiprocessing

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from blindport.core.ca import parse_client_certificate_common_name


def _load_ca_in_process(ca_dir: str, start, results) -> None:
    from blindport.core import ca

    ca.settings.CA_DIR = ca_dir
    ca._CACHE.clear()
    start.wait(timeout=10)
    try:
        results.put((ca.get_ca_cert_pem(), None))
    except Exception as error:  # pragma: no cover - asserted in the parent process
        results.put((None, repr(error)))


def _signup(client) -> tuple[str, int]:
    r = client.post("/api/v1/signup")
    assert r.status_code == 200, r.text
    return r.json()["token"], r.json()["user_id"]


def test_client_cert_requires_auth(app_client):
    client, _ = app_client
    r = client.get("/api/v1/client/cert")
    assert r.status_code == 401


def test_client_cert_issues_valid_chain(app_client):
    client, _ = app_client
    token, user_id = _signup(client)

    r = client.get("/api/v1/client/cert", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert r.headers["Cache-Control"] == "no-store"
    body = r.json()

    # All three PEMs must be present and parseable.
    ca_cert = x509.load_pem_x509_certificate(body["ca_cert_pem"].encode())
    client_cert = x509.load_pem_x509_certificate(body["client_cert_pem"].encode())
    client_key = load_pem_private_key(body["client_key_pem"].encode(), password=None)
    assert isinstance(client_key, Ed25519PrivateKey)
    assert isinstance(client_cert.public_key(), Ed25519PublicKey)

    # Chain: client cert is issued by the CA cert.
    assert client_cert.issuer == ca_cert.subject
    # The CA is self-signed: subject == issuer.
    assert ca_cert.subject == ca_cert.issuer

    # The v1 endpoint retains its legacy integer identity for rollout compatibility.
    cn = client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == f"user:{user_id}"
    assert parse_client_certificate_common_name(cn).legacy_user_id == user_id

    # The serial in the JSON matches the cert's serial (lowercase hex).
    assert body["serial"] == f"{client_cert.serial_number:x}"


def test_client_cert_two_users_have_distinct_cns(app_client):
    client, _ = app_client
    t1, _ = _signup(client)
    t2, _ = _signup(client)
    r1 = client.get("/api/v1/client/cert", headers={"Authorization": f"Bearer {t1}"})
    r2 = client.get("/api/v1/client/cert", headers={"Authorization": f"Bearer {t2}"})
    c1 = x509.load_pem_x509_certificate(r1.json()["client_cert_pem"].encode())
    c2 = x509.load_pem_x509_certificate(r2.json()["client_cert_pem"].encode())
    cn1 = c1.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    cn2 = c2.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn1 != cn2
    # Same CA issued both.
    assert c1.issuer == c2.issuer


def test_client_certificate_identity_parser_distinguishes_legacy_user_cn() -> None:
    identity = parse_client_certificate_common_name("user:42")

    assert identity.legacy_user_id == 42
    assert identity.account_id is None


def test_client_cert_ca_is_stable_across_requests(app_client):
    """Reissuing certs must reuse the same CA (else relay trust would break)."""
    client, _ = app_client
    token, _ = _signup(client)
    r1 = client.get("/api/v1/client/cert", headers={"Authorization": f"Bearer {token}"})
    r2 = client.get("/api/v1/client/cert", headers={"Authorization": f"Bearer {token}"})
    assert r1.json()["ca_cert_pem"] == r2.json()["ca_cert_pem"]
    # But the client cert itself rotates (different serial each time).
    assert r1.json()["serial"] != r2.json()["serial"]


def test_ca_initialization_is_safe_across_processes(tmp_path) -> None:
    context = multiprocessing.get_context("fork")
    start = context.Barrier(6)
    results = context.Queue()
    ca_dir = str(tmp_path / "shared-ca")
    processes = [
        context.Process(target=_load_ca_in_process, args=(ca_dir, start, results)) for _ in range(6)
    ]

    for process in processes:
        process.start()
    outcomes = [results.get(timeout=15) for _ in processes]
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0

    assert all(error is None for _, error in outcomes), outcomes
    assert len({certificate for certificate, _ in outcomes}) == 1


def test_ca_recovers_key_only_crash_state(app_client) -> None:
    _, _ = app_client
    from blindport.core import ca

    key_path, cert_path = ca._ca_paths()
    ca.get_ca_cert_pem()
    expected_key = key_path.read_bytes()
    cert_path.unlink()
    ca._CACHE.clear()

    recovered = x509.load_pem_x509_certificate(ca.get_ca_cert_pem().encode("ascii"))
    recovered_public_key = recovered.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    private_key = serialization.load_pem_private_key(expected_key, password=None)
    assert recovered_public_key == private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def test_legacy_client_cert_can_be_disabled(app_client, monkeypatch):
    client, _ = app_client
    token, _ = _signup(client)
    monkeypatch.setattr("blindport.api.v1.settings.LEGACY_CLIENT_CERT_ISSUANCE_ENABLED", False)

    response = client.get(
        "/api/v1/client/cert",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404


def test_relay_cert_requires_secret(app_client):
    client, _ = app_client
    r = client.post("/internal/v1/relay/cert", json={"hostnames": ["relay.test"]})
    assert r.status_code == 401


def test_relay_cert_issues_server_cert_with_sans(app_client):
    import ipaddress

    client, _ = app_client
    r = client.post(
        "/internal/v1/relay/cert",
        json={"hostnames": ["relay"], "ips": ["203.0.113.10"]},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    cert = x509.load_pem_x509_certificate(body["server_cert_pem"].encode())
    ca = x509.load_pem_x509_certificate(body["ca_cert_pem"].encode())
    assert body["not_after"] == cert.not_valid_after_utc.isoformat()
    assert cert.issuer == ca.subject
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    dns = san.get_values_for_type(x509.DNSName)
    ips = san.get_values_for_type(x509.IPAddress)
    assert "relay" in dns
    assert ipaddress.ip_address("203.0.113.10") in ips
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert x509.ExtendedKeyUsageOID.SERVER_AUTH in eku


def test_relay_cert_rejects_empty_request(app_client):
    client, _ = app_client
    r = client.post(
        "/internal/v1/relay/cert",
        json={},
        headers={"X-Relay-Secret": "test-secret"},
    )
    assert r.status_code == 400


def test_relay_cert_rejects_unconfigured_sans(app_client):
    client, _ = app_client
    response = client.post(
        "/internal/v1/relay/cert",
        json={"hostnames": ["attacker.example"], "ips": ["198.51.100.99"]},
        headers={"X-Relay-Secret": "test-secret"},
    )

    assert response.status_code == 403
