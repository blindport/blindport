"""End-to-end tests for the backend mini-CA and relay mTLS."""

from __future__ import annotations

import os
import socket
import ssl
from uuid import uuid4

import httpx
import pytest  # noqa: F401  - kept for future negative tests
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

BACKEND = os.environ["BLINDPORT_BACKEND_URL"]
RELAY_HOST = os.environ["BLINDPORT_RELAY_HOST"]
RELAY_ADMIN = os.environ["BLINDPORT_RELAY_ADMIN_URL"]


def _signup() -> str:
    r = httpx.post(f"{BACKEND}/api/v1/signup", timeout=5)
    r.raise_for_status()
    return r.json()["token"]


def _client_cert(token: str) -> dict:
    r = httpx.get(
        f"{BACKEND}/api/v1/client/cert",
        headers={"Authorization": f"Bearer {token}"},
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


def _client_cert_v2(token: str) -> tuple[dict, Ed25519PrivateKey]:
    key = Ed25519PrivateKey.generate()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    r = httpx.post(
        f"{BACKEND}/api/v2/client/certificate",
        headers={"Authorization": f"Bearer {token}"},
        json={"instance_id": str(uuid4()), "generation": 1, "csr_pem": csr},
        timeout=5,
    )
    r.raise_for_status()
    body = r.json()
    assert all("PRIVATE KEY" not in str(value) for value in body.values())
    return body, key


def test_client_cert_endpoint_returns_valid_chain() -> None:
    token = _signup()
    body = _client_cert(token)
    ca = x509.load_pem_x509_certificate(body["ca_cert_pem"].encode())
    cert = x509.load_pem_x509_certificate(body["client_cert_pem"].encode())
    load_pem_private_key(body["client_key_pem"].encode(), password=None)
    assert cert.issuer == ca.subject
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn.startswith("user:")


def test_relay_private_health_and_metrics_are_ready_and_fixed_cardinality() -> None:
    ready = httpx.get(f"{RELAY_ADMIN}/readyz", timeout=5)
    assert ready.status_code == 200
    assert set(ready.json()["components"]) == {
        "authorization",
        "certificate",
        "lifecycle",
        "listeners",
        "wireguard",
    }
    metrics = httpx.get(f"{RELAY_ADMIN}/metrics", timeout=5)
    metrics.raise_for_status()
    text = metrics.text
    assert "blindport_relay_ready 1" in text
    assert 'blindport_relay_connections_active{listener="control"}' in text
    assert 'blindport_relay_streams_total{claim="relay"}' in text
    assert "blindport_relay_wireguard_peers_active" in text
    assert "blindport_relay_wireguard_prefixes_active" in text
    assert "BLINDPORT-" not in text
    assert "relay.test" not in text


def test_relay_rejects_plain_tcp_on_control_plane() -> None:
    """Without TLS the relay control listener must close the connection.

    With mTLS active, a plain TCP write looks like garbage TLS handshake
    bytes; Go's TLS server rejects immediately and closes the socket. We
    only check that we cannot exchange protocol bytes; the exact failure
    mode (RST, FIN, timeout on read) is implementation-defined.
    """
    sock = socket.create_connection((RELAY_HOST, 5443), timeout=3)
    try:
        sock.sendall(b"NOT-A-TLS-HELLO\n")
        sock.settimeout(2)
        try:
            data = sock.recv(64)
        except (socket.timeout, ConnectionResetError, OSError):
            data = b""
        # Either we get back nothing (FIN/RST) or at most a TLS alert. We
        # must NOT see anything resembling a Blindport protocol frame.
        assert b"HELLO" not in data and b"OK" not in data
    finally:
        sock.close()


def test_relay_accepts_mtls_with_issued_client_cert(tmp_path) -> None:
    """A proper mTLS handshake with a backend-issued cert must complete."""
    token = _signup()
    body, key = _client_cert_v2(token)
    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "client.pem"
    key_path = tmp_path / "client.key"
    ca_path.write_text(body["ca_cert_pem"])
    cert_path.write_text(body["client_cert_pem"])
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    ctx = ssl.create_default_context(cafile=str(ca_path))
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    # The compose alias 'relay' is in the SAN list.
    sock = socket.create_connection(("relay", 5443), timeout=5)
    try:
        with ctx.wrap_socket(sock, server_hostname="relay") as ssock:
            # The handshake completed: read peer certificate to be sure.
            peer = ssock.getpeercert()
            assert peer, "expected non-empty peer cert after mTLS handshake"
    finally:
        try:
            sock.close()
        except OSError:
            pass


def test_relay_rejects_self_signed_client_cert(tmp_path) -> None:
    """A client cert NOT signed by the backend CA must be rejected."""
    import datetime as dt

    # Build a self-signed cert that the relay should not trust.
    key = Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "rogue")])
    now = dt.datetime.now(tz=dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(private_key=key, algorithm=None)
    )
    cert_path = tmp_path / "rogue.pem"
    key_path = tmp_path / "rogue.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # We still need the real CA to verify the relay's server cert.
    token = _signup()
    body = _client_cert(token)
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(body["ca_cert_pem"])

    ctx = ssl.create_default_context(cafile=str(ca_path))
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    sock = socket.create_connection(("relay", 5443), timeout=5)
    try:
        # With TLS 1.3 the client's cert failure can surface either during the
        # handshake or on the first read (post-handshake alert), so we accept
        # any SSL/OS error as proof of rejection.
        ssock = None
        rejected = False
        try:
            ssock = ctx.wrap_socket(sock, server_hostname="relay")
            ssock.settimeout(3)
            try:
                ssock.sendall(b"PING\n")
                data = ssock.recv(64)
                # An honest server would have at least kept the socket open
                # long enough to send something; an empty read means it shut
                # the connection right after the bad cert.
                rejected = data == b""
            except (ssl.SSLError, OSError):
                rejected = True
        except (ssl.SSLError, OSError):
            rejected = True
        finally:
            if ssock is not None:
                try:
                    ssock.close()
                except OSError:
                    pass
        assert rejected, "relay must reject a client cert from an unknown CA"
    finally:
        try:
            sock.close()
        except OSError:
            pass
