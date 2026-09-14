"""Internal mini Certificate Authority for the client<->relay mTLS tunnel.

The backend acts as a private CA: on first use it generates a long-lived
Ed25519 root key and self-signed root certificate stored under
``settings.CA_DIR``. Each authenticated user can request a short-lived
client certificate (default 30 days) bound to their public account id; the relay
trusts only certs issued by this CA.

This is intentionally narrow scope:

* Single root, no intermediates.
* Ed25519 keys everywhere (fast, small, modern).
* No CRL/OCSP, no revocation: client certs expire quickly, relay
  re-resolves authorisation against the backend on every connection
  anyway, so revocation is effectively handled at the application
  layer (token disabled -> control-plane refuses HELLO).
"""

from __future__ import annotations

import datetime as _dt
import fcntl
import os
import stat
import tempfile
import threading
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.x509.oid import NameOID

from blindport.config import settings


@dataclass(frozen=True)
class IssuedClientCert:
    """A freshly issued client certificate + private key (PEM)."""

    ca_cert_pem: str
    client_cert_pem: str
    client_key_pem: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    serial: int


@dataclass(frozen=True)
class IssuedServerCert:
    """A freshly issued server certificate (for relay nodes) + private key (PEM)."""

    ca_cert_pem: str
    server_cert_pem: str
    server_key_pem: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    serial: int


@dataclass(frozen=True)
class IssuedPublicKeyClientCert:
    """A client certificate issued for a caller-controlled public key."""

    ca_cert_pem: str
    client_cert_pem: str
    not_before: _dt.datetime
    not_after: _dt.datetime
    serial: int


@dataclass(frozen=True)
class ClientCertificateIdentity:
    """Account identity encoded by current or rollout-era client certificates."""

    account_id: UUID | None = None
    legacy_user_id: int | None = None


def parse_client_certificate_common_name(common_name: str) -> ClientCertificateIdentity:
    """Parse current account UUID CNs and legacy integer user CNs."""
    kind, separator, value = common_name.partition(":")
    if not separator:
        raise ValueError("invalid client certificate common name")
    if kind == "account":
        try:
            account_id = UUID(value)
        except ValueError as error:
            raise ValueError("invalid account client certificate common name") from error
        if account_id.version != 4 or str(account_id) != value:
            raise ValueError("invalid account client certificate common name")
        return ClientCertificateIdentity(account_id=account_id)
    if kind == "user" and value.isascii() and value.isdecimal():
        legacy_user_id = int(value)
        if legacy_user_id > 0 and str(legacy_user_id) == value:
            return ClientCertificateIdentity(legacy_user_id=legacy_user_id)
    raise ValueError("invalid client certificate common name")


_LOCK = threading.Lock()
_CACHE: dict[str, tuple[Ed25519PrivateKey, x509.Certificate]] = {}


def _ca_paths() -> tuple[Path, Path]:
    base = Path(settings.CA_DIR)
    base.mkdir(parents=True, exist_ok=True)
    return base / "ca.key", base / "ca.crt"


def _build_root_cert(key: Ed25519PrivateKey) -> x509.Certificate:
    """Self-sign a fresh root certificate for ``key``."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blindport"),
            x509.NameAttribute(NameOID.COMMON_NAME, settings.CA_COMMON_NAME),
        ]
    )
    now = _dt.datetime.now(tz=_dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        # Long-lived root: 10y. Rotation is via filesystem (drop the dir).
        .not_valid_after(now + _dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key=key, algorithm=None)
    )


def _atomic_write(path: Path, data: bytes, mode: int) -> None:
    """Durably replace one CA file without sharing a temporary name across replicas."""
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as temporary:
            descriptor = -1
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)


def _load_root_key(path: Path) -> Ed25519PrivateKey:
    key_obj = serialization.load_pem_private_key(_read_ca_file(path, private=True), password=None)
    if not isinstance(key_obj, Ed25519PrivateKey):
        raise RuntimeError(f"CA key at {path} is not Ed25519")
    return key_obj


def _read_ca_file(path: Path, *, private: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"CA file at {path} is not a regular file")
        if metadata.st_uid != os.geteuid():
            raise RuntimeError(f"CA file at {path} is not owned by the effective user")
        if private and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise RuntimeError(f"CA private key at {path} is accessible by group or others")
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            return source.read()
    finally:
        os.close(descriptor)


def _validate_root_pair(
    key_path: Path,
    key: Ed25519PrivateKey,
    cert: x509.Certificate,
) -> None:
    key_public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    cert_public = cert.public_key()
    if (
        not isinstance(cert_public, Ed25519PublicKey)
        or cert_public.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        != key_public
    ):
        raise RuntimeError(f"CA key and certificate at {key_path.parent} do not match")
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound as error:
        raise RuntimeError(f"CA certificate at {key_path.parent} lacks CA constraints") from error
    if not constraints.ca or not usage.key_cert_sign:
        raise RuntimeError(f"CA certificate at {key_path.parent} is not a certificate authority")


def _load_or_create_root() -> tuple[Ed25519PrivateKey, x509.Certificate]:
    key_path, cert_path = _ca_paths()
    with _LOCK:
        cached = _CACHE.get(str(key_path))
        if cached is not None:
            return cached

        lock_path = key_path.parent / ".ca.lock"
        lock_descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            if cert_path.exists() and not key_path.exists():
                raise RuntimeError(f"CA certificate at {cert_path} exists without its private key")
            if key_path.exists():
                key_obj = _load_root_key(key_path)
            else:
                key_obj = Ed25519PrivateKey.generate()
                key_pem = key_obj.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                _atomic_write(key_path, key_pem, 0o600)
            if cert_path.exists():
                cert = x509.load_pem_x509_certificate(_read_ca_file(cert_path, private=False))
            else:
                cert = _build_root_cert(key_obj)
                _atomic_write(
                    cert_path,
                    cert.public_bytes(serialization.Encoding.PEM),
                    0o644,
                )
            _validate_root_pair(key_path, key_obj, cert)
        finally:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)

        _CACHE[str(key_path)] = (key_obj, cert)
        return key_obj, cert


def get_ca_cert_pem() -> str:
    """Return the CA root certificate in PEM (no key)."""
    _, cert = _load_or_create_root()
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _aki_from_ca(ca_cert: x509.Certificate) -> x509.AuthorityKeyIdentifier:
    """Derive an AuthorityKeyIdentifier extension from the CA's SKI when present.

    Python 3.14's stdlib ``ssl`` rejects certificates issued by a CA that does
    not advertise an AKI, so every leaf we sign embeds one.
    """
    try:
        ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return x509.AuthorityKeyIdentifier(
            key_identifier=ski.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:  # pragma: no cover - legacy CAs only
        return x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())


def issue_client_cert(user_id: int) -> IssuedClientCert:
    """Issue a rollout-era client cert pinning the internal user id in the CN."""
    ca_key, ca_cert = _load_or_create_root()
    client_key = Ed25519PrivateKey.generate()
    now = _dt.datetime.now(tz=_dt.UTC)
    not_after = now + _dt.timedelta(days=settings.CLIENT_CERT_TTL_DAYS)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blindport"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "client"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"user:{user_id}"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()),
            critical=False,
        )
        .add_extension(_aki_from_ca(ca_cert), critical=False)
        .sign(private_key=ca_key, algorithm=None)
    )
    return IssuedClientCert(
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        client_cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        client_key_pem=client_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii"),
        not_before=now,
        not_after=not_after,
        serial=cert.serial_number,
    )


def issue_client_cert_for_public_key(
    account_id: UUID,
    instance_id: UUID,
    public_key: Ed25519PublicKey,
) -> IssuedPublicKeyClientCert:
    """Issue a client certificate for an Ed25519 public key supplied by the client."""
    ca_key, ca_cert = _load_or_create_root()
    now = _dt.datetime.now(tz=_dt.UTC)
    not_before = now - _dt.timedelta(minutes=5)
    not_after = now + _dt.timedelta(days=settings.CLIENT_CERT_TTL_DAYS)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blindport"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "client"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"account:{account_id}"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(f"urn:blindport:client:{instance_id}")]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(_aki_from_ca(ca_cert), critical=False)
        .sign(private_key=ca_key, algorithm=None)
    )
    return IssuedPublicKeyClientCert(
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        client_cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        serial=cert.serial_number,
    )


# Test helper: ed25519 in cryptography requires algorithm=None which mypy/lint
# can flag; keep the function tiny so it doesn't show up in coverage reports.
__all__ = [
    "ClientCertificateIdentity",
    "IssuedClientCert",
    "IssuedPublicKeyClientCert",
    "IssuedServerCert",
    "get_ca_cert_pem",
    "issue_client_cert",
    "issue_client_cert_for_public_key",
    "issue_server_cert",
    "parse_client_certificate_common_name",
]


def issue_server_cert(
    hostnames: list[str],
    ips: list[str] | None = None,
    ttl_days: int | None = None,
) -> IssuedServerCert:
    """Issue a TLS server cert signed by the mini-CA.

    Used by relay nodes to terminate the mTLS control plane. The SANs cover
    every public hostname/IP the relay might be reached at (clients connect
    by IP today but may switch to a stable DNS name later).
    """
    ca_key, ca_cert = _load_or_create_root()
    server_key = Ed25519PrivateKey.generate()
    now = _dt.datetime.now(tz=_dt.UTC)
    days = ttl_days if ttl_days is not None else settings.CLIENT_CERT_TTL_DAYS
    not_after = now + _dt.timedelta(days=days)
    cn = hostnames[0] if hostnames else (ips[0] if ips else "relay")
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Blindport"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "relay"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )
    san_entries: list[x509.GeneralName] = [x509.DNSName(h) for h in hostnames]
    if ips:
        import ipaddress as _ip

        for raw in ips:
            try:
                san_entries.append(x509.IPAddress(_ip.ip_address(raw)))
            except ValueError:
                # Skip invalid entries rather than fail issuance.
                continue
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(_aki_from_ca(ca_cert), critical=False)
    )
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
    cert = builder.sign(private_key=ca_key, algorithm=None)
    return IssuedServerCert(
        ca_cert_pem=ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_cert_pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        server_key_pem=server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii"),
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        serial=cert.serial_number,
    )
