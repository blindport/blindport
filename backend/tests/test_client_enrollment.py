"""Tests for local client CSR enrollment at /api/v2/client/certificate."""

from __future__ import annotations

import base64
import textwrap
from uuid import UUID, uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlmodel import Session, select

from blindport.core.models import ClientCredential, User


def _signup(client) -> tuple[str, str]:
    response = client.post("/api/v2/signup")
    assert response.status_code == 200, response.text
    return response.json()["token"], response.json()["account_id"]


def _csr(
    key=None, *, subject: str = "caller-controlled", with_san: bool = False
) -> tuple[object, str]:
    key = key or Ed25519PrivateKey.generate()
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    )
    if with_san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName("caller.example")]),
            critical=False,
        )
    algorithm = hashes.SHA256() if not isinstance(key, Ed25519PrivateKey) else None
    csr = builder.sign(key, algorithm)
    return key, csr.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _enroll(client, token: str, instance_id: str, generation: int, csr_pem: str):
    return client.post(
        "/api/v2/client/certificate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "instance_id": instance_id,
            "generation": generation,
            "csr_pem": csr_pem,
        },
    )


def test_enrollment_requires_auth(app_client) -> None:
    client, _ = app_client
    _, csr_pem = _csr()

    response = _enroll(client, "invalid", str(uuid4()), 1, csr_pem)

    assert response.status_code == 401


def test_enrollment_issues_chain_for_client_key_and_ignores_csr_identity(app_client) -> None:
    client, _ = app_client
    token, account_id = _signup(client)
    key, csr_pem = _csr(subject="untrusted-subject", with_san=True)
    instance_id = str(uuid4())

    response = _enroll(client, token, instance_id, 1, csr_pem)

    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    body = response.json()
    assert set(body) == {
        "instance_id",
        "generation",
        "ca_cert_pem",
        "client_cert_pem",
        "serial",
        "not_before",
        "not_after",
        "renew_after",
    }
    assert all("PRIVATE KEY" not in str(value) for value in body.values())
    ca = x509.load_pem_x509_certificate(body["ca_cert_pem"].encode())
    cert = x509.load_pem_x509_certificate(body["client_cert_pem"].encode())
    ca.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
    expected_public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    assert (
        cert.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        == expected_public_key
    )
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == (
        f"account:{account_id}"
    )
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.UniformResourceIdentifier) == [
        f"urn:blindport:client:{instance_id}"
    ]
    assert san.get_values_for_type(x509.DNSName) == []
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert usage.digital_signature
    assert not usage.key_cert_sign
    assert body["serial"] == f"{cert.serial_number:x}"


def test_enrollment_is_idempotent_and_renewal_rotates_certificate(app_client) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()
    instance_id = str(uuid4())

    first = _enroll(client, token, instance_id, 1, csr_pem)
    retry = _enroll(client, token, instance_id, 1, csr_pem)
    renewal = _enroll(client, token, instance_id, 2, csr_pem)
    renewal_retry = _enroll(client, token, instance_id, 2, csr_pem)

    assert first.status_code == retry.status_code == renewal.status_code == 200
    assert retry.json() == first.json()
    assert renewal.json()["serial"] != first.json()["serial"]
    assert renewal.json()["generation"] == 2
    assert renewal_retry.json() == renewal.json()


@pytest.mark.parametrize("generation", [0, -1, 2_147_483_648, True, 1.0, "1"])
def test_enrollment_rejects_non_positive_or_non_strict_generation(app_client, generation) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()

    response = _enroll(client, token, str(uuid4()), generation, csr_pem)

    assert response.status_code == 422


@pytest.mark.parametrize(
    "instance_id",
    ["not-a-uuid", str(uuid4()).upper(), "{" + str(uuid4()) + "}", uuid4().hex],
)
def test_enrollment_requires_canonical_uuid(app_client, instance_id: str) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()

    response = _enroll(client, token, instance_id, 1, csr_pem)

    assert response.status_code == 422


def test_enrollment_rejects_noncanonical_multiple_and_oversized_csr(app_client) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()
    instance_id = str(uuid4())

    values = [csr_pem + "\n", csr_pem + csr_pem, csr_pem.replace("\n", "\r\n"), "x" * 16_385]

    for value in values:
        assert _enroll(client, token, instance_id, 1, value).status_code == 422


def test_enrollment_rejects_invalid_signature_and_non_ed25519_key(app_client) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()
    der = bytearray(base64.b64decode("".join(csr_pem.splitlines()[1:-1])))
    der[-1] ^= 1
    encoded = base64.b64encode(der).decode("ascii")
    invalid_signature = (
        "-----BEGIN CERTIFICATE REQUEST-----\n"
        + "\n".join(textwrap.wrap(encoded, 64))
        + "\n-----END CERTIFICATE REQUEST-----\n"
    )
    rsa_key = generate_private_key(public_exponent=65537, key_size=2048)
    _, rsa_csr = _csr(rsa_key)

    assert _enroll(client, token, str(uuid4()), 1, invalid_signature).status_code == 422
    assert _enroll(client, token, str(uuid4()), 1, rsa_csr).status_code == 422


def test_enrollment_rejects_extra_request_fields(app_client) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    _, csr_pem = _csr()
    response = client.post(
        "/api/v2/client/certificate",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "instance_id": str(uuid4()),
            "generation": 1,
            "csr_pem": csr_pem,
            "client_key_pem": "forbidden",
        },
    )

    assert response.status_code == 422


def test_enrollment_conflict_cases(app_client) -> None:
    client, _ = app_client
    token, _ = _signup(client)
    key, csr_pem = _csr()
    _, other_csr = _csr()
    instance_id = str(uuid4())
    assert _enroll(client, token, instance_id, 1, csr_pem).status_code == 200

    conflicts = [
        _enroll(client, token, str(uuid4()), 1, csr_pem),
        _enroll(client, token, instance_id, 1, other_csr),
        _enroll(client, token, instance_id, 3, csr_pem),
    ]
    assert [response.status_code for response in conflicts] == [409, 409, 409]
    assert all(response.headers["Cache-Control"] == "no-store" for response in conflicts)

    assert _enroll(client, token, instance_id, 2, csr_pem).status_code == 200
    assert _enroll(client, token, instance_id, 1, csr_pem).status_code == 409
    assert key is not None


def test_first_enrollment_requires_generation_one_and_instance_is_global(app_client) -> None:
    client, factory = app_client
    del factory
    token1, _ = _signup(client)
    token2, _ = _signup(client)
    _, csr_pem = _csr()
    instance_id = str(uuid4())

    assert _enroll(client, token1, str(uuid4()), 2, csr_pem).status_code == 409
    assert _enroll(client, token1, instance_id, 1, csr_pem).status_code == 200
    assert _enroll(client, token2, instance_id, 1, csr_pem).status_code == 409


def test_enrollment_persists_only_public_credential_metadata(app_client) -> None:
    client, _ = app_client
    token, account_id = _signup(client)
    _, csr_pem = _csr()
    instance_id = str(uuid4())
    assert _enroll(client, token, instance_id, 1, csr_pem).status_code == 200

    from blindport.db import engine

    with Session(engine) as session:
        user = session.exec(select(User).where(User.public_id == UUID(account_id))).one()
        credential = session.exec(
            select(ClientCredential).where(ClientCredential.user_id == user.id)
        ).one()
    assert credential.instance_id == instance_id
    assert len(credential.public_key_fingerprint) == 64
    assert "PRIVATE KEY" not in credential.client_cert_pem
    assert credential.created_at is not None
    assert credential.updated_at is not None
