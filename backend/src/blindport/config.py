"""Application configuration loaded from environment variables."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from contextlib import suppress
from dataclasses import dataclass
from email.headerregistry import Address
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from .core.hostnames import canonicalize_hostname
from .core.models import PaymentMethod
from .core.wireguard import canonical_wireguard_key


@dataclass(frozen=True)
class RelayEdge:
    endpoint: str
    ip: str


@dataclass(frozen=True)
class StableRelayEdge:
    """A relay endpoint with a deployment-stable authorization identifier."""

    id: str
    endpoint: str


@dataclass(frozen=True)
class DnsSupervisionTarget:
    """One public A-record set monitored by the DNS supervisor."""

    hostname: str
    expected_ips: tuple[str, ...]


_OFFLINE_EDGE_ID_RE = re.compile(r"[a-z0-9][a-z0-9._-]{0,31}\Z")
_RELAY_HEARTBEAT_TOKEN_RE = re.compile(r"[0-9a-f]{64}\Z")
_OFFLINE_ENTITLEMENT_PRIVATE_KEY_MAX_BYTES = 16 * 1024


def validate_v3_onion_hostname(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return value
    if not value.endswith(".onion") or len(value) != 62:
        raise ValueError("ONION_HOST must be an empty value or a canonical v3 onion hostname")
    label = value[:-6]
    try:
        decoded = base64.b32decode(label.upper(), casefold=False)
    except (ValueError, base64.binascii.Error) as error:
        raise ValueError(
            "ONION_HOST must be an empty value or a canonical v3 onion hostname"
        ) from error
    if len(decoded) != 35 or decoded[-1] != 3:
        raise ValueError("ONION_HOST must be an empty value or a canonical v3 onion hostname")
    expected_checksum = hashlib.sha3_256(b".onion checksum" + decoded[:32] + decoded[-1:]).digest()[
        :2
    ]
    if decoded[32:34] != expected_checksum:
        raise ValueError("ONION_HOST has an invalid v3 checksum")
    return value


def _canonical_http_origin(value: str) -> str:
    parsed = urlsplit(value)
    hostname = parsed.hostname or ""
    try:
        rendered_host = f"[{hostname}]" if ip_address(hostname).version == 6 else hostname
    except ValueError:
        rendered_host = hostname.lower()
    default_port = (parsed.scheme == "http" and parsed.port == 80) or (
        parsed.scheme == "https" and parsed.port == 443
    )
    port = None if default_port else parsed.port
    return f"{parsed.scheme.lower()}://{rendered_host}{f':{port}' if port is not None else ''}"


RELAY_REAUTH_INTERVAL_DEFAULT_SECONDS = 45
RELAY_REAUTH_MAX_STALENESS_DEFAULT_SECONDS = 90
RELAY_RENEWAL_GRACE_MIN_SECONDS = (
    RELAY_REAUTH_MAX_STALENESS_DEFAULT_SECONDS + RELAY_REAUTH_INTERVAL_DEFAULT_SECONDS + 1
)
MIN_PRODUCTION_SECRET_LENGTH = 32
MIN_PRODUCTION_TOKEN_BYTES = 16
DEFAULT_SECRET_KEY = "change-me-in-production"
DEFAULT_ADMIN_TOKEN = "BLINDPORT-ADMIN-TOKEN-CHANGE-ME"
DEFAULT_BRAND_NAME = "Blindport"
DEFAULT_BRAND_TAGLINE = "Public reach for self-hosted services. TLS stays on your box."
_DEVELOPMENT_HOSTNAME_SUFFIXES = (".test", ".localhost", ".local", ".invalid", ".example")
_DEVELOPMENT_HOSTNAMES = {
    "relay",
    "localhost",
    "local",
    "test",
    "invalid",
    "example",
    "example.com",
    "example.net",
    "example.org",
}


class EnvironmentMode(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


def parse_enabled_payment_methods(value: str) -> frozenset[PaymentMethod]:
    """Parse a strict comma-separated payment method allowlist."""
    if not value or value.strip() != value:
        raise ValueError("PAYMENT_ENABLED_METHODS must not be empty or contain whitespace")
    raw_methods = value.split(",")
    if any(not method or method.strip() != method for method in raw_methods):
        raise ValueError("PAYMENT_ENABLED_METHODS must not contain whitespace or empty methods")
    try:
        methods = [PaymentMethod(method) for method in raw_methods]
    except ValueError as e:
        raise ValueError("PAYMENT_ENABLED_METHODS contains an unsupported payment method") from e
    if len(methods) != len(set(methods)):
        raise ValueError("PAYMENT_ENABLED_METHODS contains duplicate payment methods")
    active_methods = {
        PaymentMethod.LIGHTNING,
        PaymentMethod.NWC,
        PaymentMethod.STABLECOIN_SWAP,
    }
    if any(method not in active_methods for method in methods):
        raise ValueError("PAYMENT_ENABLED_METHODS contains an unsupported payment method")
    return frozenset(methods)


def _parse_port_pool(value: str, transport: str) -> list[int]:
    if not value or value.strip() != value or value.count("-") != 1:
        raise ValueError(f"must be one inclusive {transport} port range such as 10000-10007")
    start_raw, end_raw = value.split("-", 1)
    if not start_raw.isdecimal() or not end_raw.isdecimal():
        raise ValueError(f"{transport} port range endpoints must be decimal integers")
    start, end = int(start_raw), int(end_raw)
    if not 1 <= start <= end <= 65535:
        raise ValueError(f"{transport} port range must be within 1-65535")
    if end - start + 1 > 4096:
        raise ValueError(f"{transport} port range cannot contain more than 4096 ports")
    return list(range(start, end + 1))


def parse_tcp_port_pool(value: str) -> list[int]:
    """Parse one inclusive TCP port range, for example ``10000-10007``."""
    return _parse_port_pool(value, "TCP")


def parse_udp_port_pool(value: str) -> list[int]:
    """Parse one inclusive UDP port range, for example ``10000-10007``."""
    return _parse_port_pool(value, "UDP")


def _parse_ip_list(value: str, field_name: str) -> list[str]:
    if not value:
        return []
    raw_values = value.split(",")
    if any(not part.strip() for part in raw_values):
        raise ValueError(f"{field_name} contains an empty address")
    values: list[str] = []
    for item in (part.strip() for part in raw_values):
        try:
            values.append(str(ip_address(item)))
        except ValueError as e:
            raise ValueError(f"{field_name} contains invalid IP address {item!r}") from e
    if len(values) != len(set(values)):
        raise ValueError(f"{field_name} contains duplicate addresses")
    return values


def parse_managed_suffixes(value: str) -> list[str]:
    """Parse and canonicalize the provider-managed Blindport Relay DNS suffixes."""
    if not value:
        return []
    raw_values = value.split(",")
    if any(not part or part.strip() != part for part in raw_values):
        raise ValueError("RELAY_MANAGED_SUFFIXES contains whitespace or an empty suffix")
    suffixes = [canonicalize_hostname(part) for part in raw_values]
    if len(suffixes) != len(set(suffixes)):
        raise ValueError("RELAY_MANAGED_SUFFIXES contains duplicate suffixes")
    return suffixes


def parse_relay_pool_domains(value: str) -> list[str]:
    """Parse and canonicalize relay pool DNS names without accepting partial lists."""
    if not value:
        return []
    raw_values = value.split(",")
    if any(not part or part.strip() != part for part in raw_values):
        raise ValueError("RELAY_POOL_DOMAINS contains whitespace or an empty domain")
    domains = [canonicalize_hostname(part) for part in raw_values]
    if any(len(domain) > 220 for domain in domains):
        raise ValueError("RELAY_POOL_DOMAINS entries must allow a 32-character child label")
    if len(domains) != len(set(domains)):
        raise ValueError("RELAY_POOL_DOMAINS contains duplicate domains")
    return domains


def _relay_endpoint_host(endpoint: str) -> str:
    return endpoint.rsplit(":", 1)[0].strip("[]")


def _is_global_unicast_address(value: str) -> bool:
    address = ip_address(value)
    return bool(
        address.is_global
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_unspecified
        and not address.is_reserved
    )


def _canonical_public_ipv4(value: str, field_name: str) -> str:
    try:
        address = ip_address(value)
    except ValueError as error:
        raise ValueError(f"{field_name} contains an invalid IP address") from error
    if address.version != 4 or not _is_global_unicast_address(str(address)):
        raise ValueError(f"{field_name} must contain public unicast IPv4 addresses")
    return str(address)


def parse_dns_supervision_targets(value: str) -> list[DnsSupervisionTarget]:
    """Parse the strict JSON DNS target list into canonical public A-record sets."""
    if not value:
        return []
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("DNS_SUPERVISION_TARGETS must be valid JSON") from error
    if not isinstance(raw, list):
        raise ValueError("DNS_SUPERVISION_TARGETS must be a JSON list")
    if len(raw) > 32:
        raise ValueError("DNS_SUPERVISION_TARGETS cannot contain more than 32 targets")
    targets: list[DnsSupervisionTarget] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"hostname", "expected_ips"}:
            raise ValueError(
                "DNS_SUPERVISION_TARGETS entries must contain only hostname and expected_ips"
            )
        hostname = item["hostname"]
        expected_ips = item["expected_ips"]
        if not isinstance(hostname, str) or not isinstance(expected_ips, list) or not expected_ips:
            raise ValueError("DNS_SUPERVISION_TARGETS entries require hostname and expected_ips")
        canonical_hostname = canonicalize_hostname(hostname)
        if hostname != canonical_hostname:
            raise ValueError("DNS_SUPERVISION_TARGETS hostnames must be canonical")
        if any(not isinstance(address, str) for address in expected_ips):
            raise ValueError("DNS_SUPERVISION_TARGETS expected_ips values must be strings")
        canonical_ips = tuple(
            _canonical_public_ipv4(address, "DNS_SUPERVISION_TARGETS") for address in expected_ips
        )
        if list(canonical_ips) != expected_ips or list(canonical_ips) != sorted(set(canonical_ips)):
            raise ValueError(
                "DNS_SUPERVISION_TARGETS expected_ips must be sorted unique canonical public IPv4 addresses"
            )
        targets.append(DnsSupervisionTarget(canonical_hostname, canonical_ips))
    if len({target.hostname for target in targets}) != len(targets):
        raise ValueError("DNS_SUPERVISION_TARGETS contains duplicate hostnames")
    return targets


def parse_dns_supervision_resolvers(value: str) -> list[str]:
    """Parse the configured public recursive resolver addresses."""
    if not value:
        return []
    values = value.split(",")
    if any(not address or address.strip() != address for address in values):
        raise ValueError("DNS_SUPERVISION_RESOLVERS contains whitespace or an empty address")
    canonical = [_canonical_public_ipv4(address, "DNS_SUPERVISION_RESOLVERS") for address in values]
    if canonical != values:
        raise ValueError("DNS_SUPERVISION_RESOLVERS addresses must be canonical")
    if len(canonical) != len(set(canonical)):
        raise ValueError("DNS_SUPERVISION_RESOLVERS contains duplicate addresses")
    return canonical


def _is_production_relay_hostname(value: str) -> bool:
    return bool(
        "." in value
        and value not in _DEVELOPMENT_HOSTNAMES
        and not value.endswith(_DEVELOPMENT_HOSTNAME_SUFFIXES)
    )


def canonicalize_relay_endpoint(value: str) -> str:
    """Validate and canonicalize one relay control ``host:port`` endpoint."""
    if not value or value.strip() != value or "://" in value or any(c in value for c in "/?#"):
        raise ValueError("relay endpoint must be host:port without a scheme, path, or whitespace")
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or closing + 1 >= len(value) or value[closing + 1] != ":":
            raise ValueError("IPv6 relay endpoint must use [address]:port syntax")
        host = value[1:closing]
        port_raw = value[closing + 2 :]
        try:
            parsed_ip = ip_address(host)
        except ValueError as e:
            raise ValueError("bracketed relay host must be an IPv6 address") from e
        if parsed_ip.version != 6:
            raise ValueError("bracketed relay host must be an IPv6 address")
        if parsed_ip.scope_id is not None:
            raise ValueError("scoped IPv6 relay endpoints are not supported")
        canonical_host = f"[{parsed_ip}]"
    else:
        if value.count(":") != 1:
            raise ValueError("relay endpoint must be host:port; bracket IPv6 addresses")
        host, port_raw = value.rsplit(":", 1)
        try:
            canonical_host = str(ip_address(host))
        except ValueError:
            canonical_host = canonicalize_hostname(host)
    if not port_raw.isdecimal() or str(int(port_raw)) != port_raw:
        raise ValueError("relay endpoint port must be a canonical decimal integer")
    port = int(port_raw)
    if not 1 <= port <= 65535:
        raise ValueError("relay endpoint port must be within 1-65535")
    return f"{canonical_host}:{port}"


def parse_relay_endpoints(value: str) -> list[str]:
    """Parse the strict comma-separated Blindport Relay control endpoint list."""
    if not value:
        return []
    raw_values = value.split(",")
    if any(not part or part.strip() != part for part in raw_values):
        raise ValueError("RELAY_CONTROL_URLS contains whitespace or an empty endpoint")
    endpoints: list[str] = []
    for part in raw_values:
        endpoint = canonicalize_relay_endpoint(part)
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    return endpoints


def parse_port_ha_edges(value: str) -> list[RelayEdge]:
    """Parse the JSON list that maps each Port relay endpoint to its public IP."""
    if not value:
        return []
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("PORT_HA_EDGES must be valid JSON") from error
    if not isinstance(raw, list):
        raise ValueError("PORT_HA_EDGES must be a JSON list")
    edges: list[RelayEdge] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"endpoint", "ip"}:
            raise ValueError("PORT_HA_EDGES entries must contain only endpoint and ip")
        endpoint = item["endpoint"]
        address = item["ip"]
        if not isinstance(endpoint, str) or not isinstance(address, str):
            raise ValueError("PORT_HA_EDGES endpoint and ip values must be strings")
        try:
            canonical_ip = str(ip_address(address))
        except ValueError as error:
            raise ValueError(f"PORT_HA_EDGES contains invalid IP address {address!r}") from error
        edges.append(RelayEdge(canonicalize_relay_endpoint(endpoint), canonical_ip))
    if len({edge.endpoint for edge in edges}) != len(edges):
        raise ValueError("PORT_HA_EDGES contains duplicate relay endpoints")
    if len({edge.ip for edge in edges}) != len(edges):
        raise ValueError("PORT_HA_EDGES contains duplicate public IPs")
    return edges


def parse_framed_ip_endpoints(value: str) -> dict[str, str]:
    """Parse the JSON object mapping framed dedicated IPs to their owning edge."""
    if not value:
        return {}
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("FRAMED_IP_ENDPOINTS must be valid JSON") from error
    if not isinstance(raw, dict):
        raise ValueError("FRAMED_IP_ENDPOINTS must be a JSON object")
    mappings: dict[str, str] = {}
    for address, endpoint in raw.items():
        if not isinstance(address, str) or not isinstance(endpoint, str):
            raise ValueError("FRAMED_IP_ENDPOINTS keys and values must be strings")
        try:
            canonical_ip = str(ip_address(address))
        except ValueError as error:
            raise ValueError(
                f"FRAMED_IP_ENDPOINTS contains invalid IP address {address!r}"
            ) from error
        if canonical_ip in mappings:
            raise ValueError("FRAMED_IP_ENDPOINTS contains duplicate canonical IPs")
        mappings[canonical_ip] = canonicalize_relay_endpoint(endpoint)
    return mappings


def parse_relay_edges(value: str) -> list[StableRelayEdge]:
    """Parse the stable edge map used by offline entitlement artifacts."""
    if not value:
        return []
    try:
        raw = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("RELAY_EDGES must be valid JSON") from error
    if not isinstance(raw, list) or not raw:
        raise ValueError("RELAY_EDGES must be a non-empty JSON list")
    edges: list[StableRelayEdge] = []
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"id", "endpoint"}:
            raise ValueError("RELAY_EDGES entries must contain only id and endpoint")
        edge_id = item["id"]
        endpoint = item["endpoint"]
        if not isinstance(edge_id, str) or not _OFFLINE_EDGE_ID_RE.fullmatch(edge_id):
            raise ValueError("RELAY_EDGES ids must be lowercase stable edge identifiers")
        if not isinstance(endpoint, str):
            raise ValueError("RELAY_EDGES endpoints must be strings")
        canonical_endpoint = canonicalize_relay_endpoint(endpoint)
        edges.append(StableRelayEdge(id=edge_id, endpoint=canonical_endpoint))
    if len({edge.id for edge in edges}) != len(edges):
        raise ValueError("RELAY_EDGES contains duplicate ids")
    if len({edge.endpoint for edge in edges}) != len(edges):
        raise ValueError("RELAY_EDGES contains duplicate canonical endpoints")
    return edges


def parse_relay_heartbeat_keys(value: str) -> dict[str, str]:
    """Parse a canonical map of relay edge identifiers to heartbeat tokens."""
    if not value:
        return {}
    try:
        keys = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError("RELAY_HEARTBEAT_KEYS must be valid JSON") from error
    if not isinstance(keys, dict):
        raise ValueError("RELAY_HEARTBEAT_KEYS must be a JSON object")
    if value != json.dumps(keys, sort_keys=True, separators=(",", ":"), ensure_ascii=True):
        raise ValueError("RELAY_HEARTBEAT_KEYS must use canonical JSON")
    if any(
        not _OFFLINE_EDGE_ID_RE.fullmatch(edge_id)
        or not isinstance(token, str)
        or not _RELAY_HEARTBEAT_TOKEN_RE.fullmatch(token)
        for edge_id, token in keys.items()
    ):
        raise ValueError("RELAY_HEARTBEAT_KEYS contains invalid edge identifiers or tokens")
    if len(set(keys.values())) != len(keys):
        raise ValueError("RELAY_HEARTBEAT_KEYS tokens must be unique")
    return keys


def load_offline_entitlement_private_key(path_value: str) -> Ed25519PrivateKey:
    """Open one owner-only regular Ed25519 PEM key without following symlinks."""
    path = Path(path_value).expanduser()
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("offline entitlement private key is not securely readable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("offline entitlement private key must be a regular file")
        if metadata.st_uid != os.geteuid():
            raise ValueError("offline entitlement private key must be owned by the effective user")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError(
                "offline entitlement private key must not be accessible by group or others"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            raw = source.read(_OFFLINE_ENTITLEMENT_PRIVATE_KEY_MAX_BYTES + 1)
    finally:
        os.close(descriptor)
    if not raw or len(raw) > _OFFLINE_ENTITLEMENT_PRIVATE_KEY_MAX_BYTES:
        raise ValueError(
            "offline entitlement private key must be a non-empty PEM no larger than 16 KiB"
        )
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "offline entitlement private key must be an unencrypted Ed25519 PEM key"
        ) from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("offline entitlement private key must be Ed25519")
    canonical = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    if raw != canonical:
        raise ValueError("offline entitlement private key must contain one canonical PEM key")
    return key


class Settings(BaseSettings):
    """Blindport backend settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        hide_input_in_errors=True,
    )

    ENVIRONMENT: EnvironmentMode = EnvironmentMode.DEVELOPMENT

    # HTTP server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Branding
    BRAND_NAME: str = DEFAULT_BRAND_NAME
    BRAND_TAGLINE: str = DEFAULT_BRAND_TAGLINE
    PUBLIC_SITE_URL: str = "http://localhost:8000"
    ONION_HOST: str = ""
    BLINDPORTD_VERSION: str = "dev"

    # Database
    DATABASE_URL: str = "sqlite:///./blindport.db"
    DATABASE_MIGRATE_ON_STARTUP: bool = True

    # Security
    SECRET_KEY: str = DEFAULT_SECRET_KEY
    TOKEN_HASH_KEY: str = ""
    RELAY_SECRET: str = ""
    CREDENTIAL_ENCRYPTION_KEY: str = ""
    # Dedicated administrator bearer and browser session lifetime.
    ADMIN_TOKEN: str = DEFAULT_ADMIN_TOKEN
    ADMIN_SESSION_MAX_AGE_SECONDS: int = Field(default=900, ge=60, le=86400)
    PASSKEYS_ENABLED: bool = False
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = Field(default="Blindport", min_length=1, max_length=100)
    WEBAUTHN_ORIGIN: str = "http://localhost:8000"
    PASSKEY_CHALLENGE_TTL_SECONDS: int = Field(default=300, ge=60, le=600)
    PASSKEY_MAX_PENDING_CHALLENGES: int = Field(default=10000, ge=100, le=1000000)
    PASSKEY_MAX_CREDENTIALS_PER_USER: int = Field(default=20, ge=1, le=100)
    BROWSER_SESSION_MAX_AGE_SECONDS: int = Field(default=2592000, ge=300, le=31536000)
    BROWSER_SESSION_MAX_PER_USER: int = Field(default=20, ge=1, le=100)

    # Product catalog and sales controls
    IP_ENABLED: bool = True
    IP_SALES_PAUSED: bool = False
    IP_YEARLY_SATS: int = 75000
    BILLING_YEARLY_ENABLED: bool = False
    PORT_ENABLED: bool = True
    PORT_SALES_PAUSED: bool = False
    PORT_MONTHLY_SATS: int = 1500
    PORT_YEARLY_SATS: int = 15000
    RELAY_ENABLED: bool = True
    RELAY_SALES_PAUSED: bool = False
    RELAY_MONTHLY_SATS: int = 3000
    RELAY_YEARLY_SATS: int = 30000
    RELAY_WILDCARD_MONTHLY_SATS: int = 7500
    RELAY_WILDCARD_YEARLY_SATS: int = 75000
    RELAY_MANAGED_DOMAIN_CAP: int = Field(default=1000, ge=0)
    RELAY_CUSTOMER_DOMAINS_ENABLED: bool = True

    # Durable per-account abuse limits
    ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS: int = Field(default=20, ge=1, le=1000)
    ACCOUNT_MAX_OPEN_PAYMENTS: int = Field(default=5, ge=1, le=100)
    ACCOUNT_MAX_PENDING_RELAY_CLAIMS: int = Field(default=2, ge=1, le=20)

    # Public request rate limits. Direct-client scopes use only Request.client;
    # production proxies/ASGI servers must be configured with an explicit trusted
    # proxy policy so that value represents the real peer. Application code never
    # accepts Forwarded or X-Forwarded-For headers directly.
    RATE_LIMIT_SIGNUP_REQUESTS: int = Field(default=10, ge=1, le=1000)
    RATE_LIMIT_SIGNUP_WINDOW_SECONDS: int = Field(default=60, ge=1, le=3600)
    RATE_LIMIT_ADMIN_LOGIN_REQUESTS: int = Field(default=5, ge=1, le=1000)
    RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3600)
    RATE_LIMIT_BROWSER_LOGIN_REQUESTS: int = Field(default=10, ge=1, le=1000)
    RATE_LIMIT_BROWSER_LOGIN_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3600)
    RATE_LIMIT_PAYMENT_CREATE_REQUESTS: int = Field(default=60, ge=1, le=10000)
    RATE_LIMIT_PAYMENT_CREATE_WINDOW_SECONDS: int = Field(default=60, ge=1, le=3600)
    RATE_LIMIT_DOMAIN_VERIFY_REQUESTS: int = Field(default=20, ge=1, le=1000)
    RATE_LIMIT_DOMAIN_VERIFY_WINDOW_SECONDS: int = Field(default=60, ge=1, le=3600)
    RATE_LIMIT_CLIENT_CERT_REQUESTS: int = Field(default=20, ge=1, le=1000)
    RATE_LIMIT_CLIENT_CERT_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3600)
    RATE_LIMIT_BUCKET_RETENTION_SECONDS: int = Field(default=3600, ge=60, le=604800)
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS: int = Field(default=60, ge=1, le=3600)
    RATE_LIMIT_CLEANUP_BATCH_SIZE: int = Field(default=500, ge=10, le=5000)
    RATE_LIMIT_MAX_BUCKETS: int = Field(default=100000, ge=1000, le=10000000)

    # Adapter selection. Direct LND Lightning is the production payment path;
    # mocks remain the default for local development and tests.
    PAYMENT_LIGHTNING_ADAPTER: str = "mock"
    PAYMENT_NWC_ADAPTER: str = "mock"
    PAYMENT_ENABLED_METHODS: str = PaymentMethod.LIGHTNING.value
    STABLECOIN_PAYMENTS_ENABLED: bool = False
    STABLECOIN_SWAP_MARKUP_BPS: int = Field(default=1000, ge=1, le=10000)
    STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS: int = Field(default=1200, ge=60, le=3600)
    STABLECOIN_SWAP_DEFAULT_ASSET: str = "USDC-BASE"

    # Advisory Bitcoin/USD display pricing. This never affects payment amounts.
    BTC_USD_PRICE_ENABLED: bool = False
    BTC_USD_PRICE_REFRESH_SECONDS: int = Field(default=300, ge=60, le=3600)
    BTC_USD_PRICE_MAX_STALE_SECONDS: int = Field(default=1800, ge=300, le=86400)
    BTC_USD_PRICE_TIMEOUT_SECONDS: float = Field(default=5.0, ge=1, le=15)

    # LND REST (required when PAYMENT_LIGHTNING_ADAPTER=lnd)
    LND_REST_URL: str = ""
    LND_CERT_PATH: str = ""
    LND_MACAROON_PATH: str = ""
    LND_INVOICE_EXPIRY_SECONDS: int = 600
    LND_REQUEST_TIMEOUT_SECONDS: float = 10.0
    LND_INVOICE_HMAC_KEY: str = ""
    PAYMENT_MIN_PAYABLE_SECONDS: int = Field(default=30, ge=5, le=300)
    PAYMENT_EXPIRY_SAFETY_SECONDS: int = Field(default=15, ge=1, le=60)
    PAYMENT_RECONCILIATION_ENABLED: bool = True
    PAYMENT_RECONCILIATION_INTERVAL_SECONDS: float = Field(default=10.0, ge=0.1, le=300)
    PAYMENT_RECONCILIATION_BATCH_SIZE: int = Field(default=100, ge=1, le=1000)
    PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS: float = Field(default=30.0, ge=1, le=600)
    PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS: float = Field(default=60.0, ge=1, le=3600)

    # NWC helper and bounded outgoing-payment retries.
    NWC_HELPER_PATH: str = "/usr/local/bin/blindport-nwc-helper"
    NWC_ALLOWED_RELAY_HOSTS: str = ""
    NWC_ALLOW_PUBLIC_RELAYS: bool = False
    NWC_HELPER_TIMEOUT_SECONDS: float = Field(default=20.0, ge=1, le=120)
    NWC_MAX_PAYMENT_ATTEMPTS: int = Field(default=3, ge=1, le=10)
    NWC_RETRY_BASE_SECONDS: int = Field(default=30, ge=1, le=3600)
    NWC_LOOKUP_INTERVAL_SECONDS: int = Field(default=30, ge=5, le=300)
    NWC_PAYMENT_LEASE_SECONDS: int = Field(default=45, ge=5, le=300)
    NWC_AUTO_RENEW_LEAD_SECONDS: int = Field(default=86400, ge=60, le=604800)

    # Optional expiration reminders delivered through generic SMTP.
    REMINDER_EMAIL_ENABLED: bool = False
    ANNOUNCEMENT_EMAIL_ENABLED: bool = False
    NOTIFICATION_RECONCILIATION_ENABLED: bool = True
    NOTIFICATION_RECONCILIATION_INTERVAL_SECONDS: float = Field(default=10.0, ge=0.1, le=300)
    NOTIFICATION_RECONCILIATION_BATCH_SIZE: int = Field(default=100, ge=1, le=1000)
    NOTIFICATION_RECONCILIATION_STARTUP_GRACE_SECONDS: float = Field(default=30.0, ge=1, le=600)
    NOTIFICATION_RECONCILIATION_STALE_AFTER_SECONDS: float = Field(default=60.0, ge=1, le=3600)
    SMTP_HOST: str = ""
    SMTP_PORT: int = Field(default=587, ge=1, le=65535)
    SMTP_SECURITY: str = "starttls"
    SMTP_USERNAME: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_TIMEOUT_SECONDS: float = Field(default=10.0, ge=1, le=60)
    REMINDER_DELIVERY_LEASE_SECONDS: int = Field(default=45, ge=10, le=300)
    NOTIFICATION_DELIVERY_LEASE_SECONDS: int = Field(default=45, ge=10, le=300)

    # Optional payment integrations
    BOLTZ_URL: str = "https://api.boltz.exchange"
    BOLTZ_WEB_URL: str = "https://boltz.exchange"

    # Relay control plane
    RELAY_CONTROL_URL: str = "relay:5443"
    RELAY_CONTROL_URLS: str = ""
    PORT_HA_EDGES: str = ""  # JSON [{"endpoint":"edge:5443","ip":"203.0.113.20"}]
    PORT_HOSTNAME_SUFFIX: str = ""
    FRAMED_IP_ENDPOINTS: str = ""  # JSON {"203.0.113.10":"edge:5443"}
    OFFLINE_ENTITLEMENTS_ENABLED: bool = False
    OFFLINE_ENTITLEMENT_GRACE_SECONDS: int = Field(default=604800, ge=86400, le=604800)
    OFFLINE_ENTITLEMENT_KEY_ID: str = ""
    OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE: str = ""
    RELAY_EDGES: str = ""  # JSON [{"id":"edge-a","endpoint":"edge-a:5443"}]
    RELAY_HEARTBEAT_KEYS: str = ""  # Canonical JSON {"edge-a":"64 lowercase hex characters"}
    RELAY_PUBLIC_IPS: str = "203.0.113.10,203.0.113.11"  # comma-separated, allocated pool
    WIREGUARD_PUBLIC_IPS: str = ""  # provider-routed /32 inventory, never locally bound
    RELAY_SHARED_IPS: str = "203.0.113.20"  # separate Blindport Port/SNI ingress inventory
    RELAY_SHARED_TCP_PORTS: str = "10000-10007"  # one bounded inclusive range
    RELAY_SHARED_UDP_PORTS: str = "10000-10007"  # independently leased UDP sockets
    RELAY_POOL_DOMAINS: str = "relay1.blindport.test,relay2.blindport.test"
    WIREGUARD_RELAY_PUBLIC_KEY: str = ""
    WIREGUARD_ENDPOINT: str = ""
    WIREGUARD_MTU: int = Field(default=1420, ge=1280, le=1420)
    WIREGUARD_PERSISTENT_KEEPALIVE_SECONDS: int = Field(default=25, ge=0, le=120)
    WIREGUARD_RECONCILE_INTERVAL_SECONDS: float = Field(default=10.0, ge=1, le=300)
    WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS: float = Field(default=90.0, ge=1, le=3600)
    WIREGUARD_SMTP_EGRESS_FEE_SATS: int = Field(default=50000, gt=0, le=100000000)
    RELAY_MANAGED_SUFFIXES: str = ""
    RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS: int = Field(default=1800, ge=60, le=86400)
    RELAY_DOMAIN_CLAIM_TTL_SECONDS: int = Field(default=3600, ge=60, le=86400)
    RELAY_RENEWAL_GRACE_SECONDS: int = Field(
        default=604800,
        ge=RELAY_RENEWAL_GRACE_MIN_SECONDS,
        le=2592000,
    )
    RELAY_DNS_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=30)
    RELAY_HEARTBEAT_STALE_SECONDS: int = Field(default=90, ge=30, le=3600)
    BANDWIDTH_METRICS_ENABLED: bool = False
    BANDWIDTH_RETENTION_DAYS: int = Field(default=400, ge=1, le=3660)
    BANDWIDTH_INGEST_MAX_AGE_DAYS: int = Field(default=3, ge=0, le=30)
    BANDWIDTH_CLEANUP_INTERVAL_SECONDS: int = Field(default=3600, ge=60, le=86400)
    BANDWIDTH_CLEANUP_BATCH_SIZE: int = Field(default=1000, ge=1, le=10000)
    DNS_SUPERVISION_ENABLED: bool = False
    DNS_SUPERVISION_INTERVAL_SECONDS: int = Field(default=60, ge=30, le=3600)
    DNS_SUPERVISION_STALE_SECONDS: int = Field(default=180, ge=30, le=3600)
    DNS_SUPERVISION_TARGETS: str = ""
    DNS_SUPERVISION_RESOLVERS: str = "1.1.1.1,8.8.8.8"
    RESOURCE_RESERVATION_TTL_SECONDS: int = Field(default=1800, ge=60, le=86400)
    RESOURCE_REUSE_QUARANTINE_SECONDS: int = Field(default=180, ge=60, le=7776000)
    IP_REUSE_QUARANTINE_SECONDS: int = Field(default=604800, ge=3600, le=7776000)

    # Token format settings
    TOKEN_BYTES: int = 16  # 16 bytes -> 26 base32 chars
    TOKEN_GROUP_SIZE: int = 5  # for human-friendly chunking

    # mTLS mini-CA (signs short-lived client certs for the client<->relay tunnel)
    CA_DIR: str = "./data/ca"  # holds ca.key / ca.crt, persisted across restarts
    CA_COMMON_NAME: str = "Blindport Internal CA"
    CLIENT_CERT_TTL_DAYS: int = Field(default=30, ge=1, le=90)
    LEGACY_CLIENT_CERT_ISSUANCE_ENABLED: bool = True

    @property
    def relay_public_ips_list(self) -> list[str]:
        return _parse_ip_list(self.RELAY_PUBLIC_IPS, "RELAY_PUBLIC_IPS")

    @property
    def relay_shared_ips_list(self) -> list[str]:
        return _parse_ip_list(self.RELAY_SHARED_IPS, "RELAY_SHARED_IPS")

    @property
    def wireguard_public_ips_list(self) -> list[str]:
        return _parse_ip_list(self.WIREGUARD_PUBLIC_IPS, "WIREGUARD_PUBLIC_IPS")

    @property
    def wireguard_enabled(self) -> bool:
        return bool(self.wireguard_public_ips_list)

    @property
    def relay_shared_tcp_ports_list(self) -> list[int]:
        return parse_tcp_port_pool(self.RELAY_SHARED_TCP_PORTS)

    @property
    def relay_shared_udp_ports_list(self) -> list[int]:
        return parse_udp_port_pool(self.RELAY_SHARED_UDP_PORTS)

    @property
    def relay_pool_domains_list(self) -> list[str]:
        return parse_relay_pool_domains(self.RELAY_POOL_DOMAINS)

    @property
    def relay_managed_suffixes_list(self) -> list[str]:
        return parse_managed_suffixes(self.RELAY_MANAGED_SUFFIXES)

    @property
    def relay_control_urls_list(self) -> list[str]:
        endpoints = parse_relay_endpoints(self.RELAY_CONTROL_URLS)
        return endpoints or [self.RELAY_CONTROL_URL]

    @property
    def port_ha_edges_list(self) -> list[RelayEdge]:
        return parse_port_ha_edges(self.PORT_HA_EDGES)

    @property
    def framed_ip_endpoints_map(self) -> dict[str, str]:
        return parse_framed_ip_endpoints(self.FRAMED_IP_ENDPOINTS)

    @property
    def relay_edges_list(self) -> list[StableRelayEdge]:
        return parse_relay_edges(self.RELAY_EDGES)

    @property
    def relay_heartbeat_keys(self) -> dict[str, str]:
        return parse_relay_heartbeat_keys(self.RELAY_HEARTBEAT_KEYS)

    @property
    def dns_supervision_targets_list(self) -> list[DnsSupervisionTarget]:
        return parse_dns_supervision_targets(self.DNS_SUPERVISION_TARGETS)

    @property
    def dns_supervision_resolvers_list(self) -> list[str]:
        return parse_dns_supervision_resolvers(self.DNS_SUPERVISION_RESOLVERS)

    @property
    def enabled_payment_methods(self) -> frozenset[PaymentMethod]:
        return parse_enabled_payment_methods(self.PAYMENT_ENABLED_METHODS)

    @property
    def nwc_allowed_relay_hosts(self) -> tuple[str, ...]:
        if not self.NWC_ALLOWED_RELAY_HOSTS:
            return ()
        return tuple(self.NWC_ALLOWED_RELAY_HOSTS.split(","))

    def is_payment_method_enabled(self, method: PaymentMethod) -> bool:
        if method == PaymentMethod.STABLECOIN_SWAP and not self.STABLECOIN_PAYMENTS_ENABLED:
            return False
        return method in self.enabled_payment_methods

    @property
    def token_hash_key(self) -> str:
        return self.TOKEN_HASH_KEY or self.SECRET_KEY

    @property
    def relay_secret(self) -> str:
        return self.RELAY_SECRET or self.SECRET_KEY

    @property
    def relay_certificate_hostnames(self) -> set[str]:
        hostnames: set[str] = set()
        mapped_endpoints = {
            *(edge.endpoint for edge in self.port_ha_edges_list),
            *self.framed_ip_endpoints_map.values(),
        }
        for endpoint in {self.RELAY_CONTROL_URL, *self.relay_control_urls_list, *mapped_endpoints}:
            host = endpoint.rsplit(":", 1)[0].strip("[]")
            try:
                ip_address(host)
            except ValueError:
                hostnames.add(host)
        return hostnames

    @property
    def relay_certificate_ips(self) -> set[str]:
        addresses = {
            *self.relay_public_ips_list,
            *self.relay_shared_ips_list,
            *self.wireguard_public_ips_list,
            *(edge.ip for edge in self.port_ha_edges_list),
        }
        mapped_endpoints = {
            *(edge.endpoint for edge in self.port_ha_edges_list),
            *self.framed_ip_endpoints_map.values(),
        }
        for endpoint in {self.RELAY_CONTROL_URL, *self.relay_control_urls_list, *mapped_endpoints}:
            host = endpoint.rsplit(":", 1)[0].strip("[]")
            with suppress(ValueError):
                addresses.add(str(ip_address(host)))
        return addresses

    @property
    def lnd_invoice_hmac_key_bytes(self) -> bytes:
        if self.LND_INVOICE_HMAC_KEY:
            return bytes.fromhex(self.LND_INVOICE_HMAC_KEY)
        return hashlib.sha256(f"blindport-development:{self.SECRET_KEY}".encode()).digest()

    @field_validator("RELAY_PUBLIC_IPS", "RELAY_SHARED_IPS", "WIREGUARD_PUBLIC_IPS")
    @classmethod
    def validate_ip_pool(cls, value: str, info) -> str:
        _parse_ip_list(value, info.field_name)
        return value

    @field_validator("ONION_HOST")
    @classmethod
    def validate_onion_host(cls, value: str) -> str:
        return validate_v3_onion_hostname(value)

    @field_validator("PUBLIC_SITE_URL")
    @classmethod
    def validate_public_site_url(cls, value: str) -> str:
        if not value or value.strip() != value:
            raise ValueError("PUBLIC_SITE_URL must be an absolute HTTP or HTTPS origin")
        parsed = urlsplit(value)
        try:
            _ = parsed.port
            invalid_port = False
        except ValueError:
            invalid_port = True
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or invalid_port
        ):
            raise ValueError("PUBLIC_SITE_URL must be an absolute HTTP or HTTPS origin")
        return _canonical_http_origin(value)

    @field_validator("WEBAUTHN_RP_ID")
    @classmethod
    def validate_webauthn_rp_id(cls, value: str) -> str:
        if not value or not value.isascii() or value != value.lower():
            raise ValueError("WEBAUTHN_RP_ID must be a lowercase ASCII DNS hostname or localhost")
        try:
            canonical = canonicalize_hostname(value)
        except ValueError as error:
            raise ValueError(
                "WEBAUTHN_RP_ID must be a lowercase ASCII DNS hostname or localhost"
            ) from error
        if canonical != value:
            raise ValueError("WEBAUTHN_RP_ID must be a lowercase ASCII DNS hostname or localhost")
        return value

    @field_validator("WEBAUTHN_RP_NAME")
    @classmethod
    def validate_webauthn_rp_name(cls, value: str) -> str:
        if not value.isascii() or not value.isprintable():
            raise ValueError("WEBAUTHN_RP_NAME must contain only printable ASCII characters")
        return value

    @field_validator("WEBAUTHN_ORIGIN")
    @classmethod
    def validate_webauthn_origin(cls, value: str) -> str:
        if not value or value.strip() != value:
            raise ValueError("WEBAUTHN_ORIGIN must be an exact HTTP or HTTPS origin")
        parsed = urlsplit(value)
        try:
            _ = parsed.port
            invalid_port = False
        except ValueError:
            invalid_port = True
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or invalid_port
        ):
            raise ValueError("WEBAUTHN_ORIGIN must be an exact HTTP or HTTPS origin")
        return _canonical_http_origin(value)

    @field_validator("BOLTZ_WEB_URL")
    @classmethod
    def validate_boltz_web_url(cls, value: str) -> str:
        if not value or value.strip() != value:
            raise ValueError("BOLTZ_WEB_URL must be an absolute HTTP or HTTPS origin")
        parsed = urlsplit(value)
        try:
            _ = parsed.port
            invalid_port = False
        except ValueError:
            invalid_port = True
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
            or invalid_port
        ):
            raise ValueError("BOLTZ_WEB_URL must be an absolute HTTP or HTTPS origin")
        return value.rstrip("/")

    @field_validator("STABLECOIN_SWAP_DEFAULT_ASSET")
    @classmethod
    def validate_stablecoin_swap_asset(cls, value: str) -> str:
        if not re.fullmatch(r"(?:USDC|USDT0)(?:-[A-Z0-9]+)?", value):
            raise ValueError(
                "STABLECOIN_SWAP_DEFAULT_ASSET must be a canonical Boltz USDC or USDT0 asset"
            )
        return value

    @field_validator("WIREGUARD_RELAY_PUBLIC_KEY")
    @classmethod
    def validate_wireguard_relay_public_key(cls, value: str) -> str:
        if value:
            canonical_wireguard_key(value, "WIREGUARD_RELAY_PUBLIC_KEY")
        return value

    @field_validator("WIREGUARD_ENDPOINT")
    @classmethod
    def validate_wireguard_endpoint(cls, value: str) -> str:
        return canonicalize_relay_endpoint(value) if value else value

    @field_validator("RELAY_SHARED_TCP_PORTS")
    @classmethod
    def validate_shared_tcp_ports(cls, value: str) -> str:
        parse_tcp_port_pool(value)
        return value

    @field_validator("RELAY_SHARED_UDP_PORTS")
    @classmethod
    def validate_shared_udp_ports(cls, value: str) -> str:
        parse_udp_port_pool(value)
        return value

    @field_validator("RELAY_MANAGED_SUFFIXES")
    @classmethod
    def validate_managed_suffixes(cls, value: str) -> str:
        return ",".join(parse_managed_suffixes(value))

    @field_validator("RELAY_POOL_DOMAINS")
    @classmethod
    def validate_relay_pool_domains(cls, value: str) -> str:
        return ",".join(parse_relay_pool_domains(value))

    @field_validator("RELAY_CONTROL_URL")
    @classmethod
    def validate_relay_control_url(cls, value: str) -> str:
        return canonicalize_relay_endpoint(value)

    @field_validator("RELAY_CONTROL_URLS")
    @classmethod
    def validate_relay_control_urls(cls, value: str) -> str:
        return ",".join(parse_relay_endpoints(value))

    @field_validator("PORT_HA_EDGES")
    @classmethod
    def validate_port_ha_edges(cls, value: str) -> str:
        edges = parse_port_ha_edges(value)
        return json.dumps([{"endpoint": edge.endpoint, "ip": edge.ip} for edge in edges])

    @field_validator("FRAMED_IP_ENDPOINTS")
    @classmethod
    def validate_framed_ip_endpoints(cls, value: str) -> str:
        return json.dumps(parse_framed_ip_endpoints(value), sort_keys=True) if value else ""

    @field_validator("RELAY_EDGES")
    @classmethod
    def validate_relay_edges(cls, value: str) -> str:
        edges = parse_relay_edges(value) if value else []
        return (
            json.dumps([{"id": edge.id, "endpoint": edge.endpoint} for edge in edges])
            if edges
            else ""
        )

    @field_validator("RELAY_HEARTBEAT_KEYS")
    @classmethod
    def validate_relay_heartbeat_keys(cls, value: str) -> str:
        parse_relay_heartbeat_keys(value)
        return value

    @field_validator("DNS_SUPERVISION_TARGETS")
    @classmethod
    def validate_dns_supervision_targets(cls, value: str) -> str:
        targets = parse_dns_supervision_targets(value)
        return (
            json.dumps(
                [
                    {"hostname": target.hostname, "expected_ips": list(target.expected_ips)}
                    for target in targets
                ]
            )
            if targets
            else ""
        )

    @field_validator("DNS_SUPERVISION_RESOLVERS")
    @classmethod
    def validate_dns_supervision_resolvers(cls, value: str) -> str:
        return ",".join(parse_dns_supervision_resolvers(value))

    @field_validator("PORT_HOSTNAME_SUFFIX")
    @classmethod
    def validate_port_hostname_suffix(cls, value: str) -> str:
        if not value:
            return ""
        hostname = canonicalize_hostname(value)
        if len(hostname) > 216:
            raise ValueError("PORT_HOSTNAME_SUFFIX must allow a UUID child label")
        return hostname

    @field_validator("PAYMENT_ENABLED_METHODS")
    @classmethod
    def validate_enabled_payment_methods(cls, value: str) -> str:
        methods = parse_enabled_payment_methods(value)
        return ",".join(method.value for method in PaymentMethod if method in methods)

    @field_validator("LND_INVOICE_HMAC_KEY")
    @classmethod
    def validate_invoice_hmac_key(cls, value: str) -> str:
        if not value:
            return value
        if len(value) != 64 or value.lower() != value:
            raise ValueError("LND_INVOICE_HMAC_KEY must be 64 lowercase hexadecimal characters")
        try:
            bytes.fromhex(value)
        except ValueError as e:
            raise ValueError(
                "LND_INVOICE_HMAC_KEY must be 64 lowercase hexadecimal characters"
            ) from e
        return value

    @field_validator("CREDENTIAL_ENCRYPTION_KEY")
    @classmethod
    def validate_credential_encryption_key(cls, value: str) -> str:
        if not value:
            return value
        from .core.credentials import parse_credential_keyring

        parse_credential_keyring(value)
        return value

    @field_validator("NWC_ALLOWED_RELAY_HOSTS")
    @classmethod
    def validate_nwc_relay_hosts(cls, value: str) -> str:
        if not value:
            return value
        raw = value.split(",")
        if any(not host or host.strip() != host for host in raw):
            raise ValueError("NWC_ALLOWED_RELAY_HOSTS contains whitespace or an empty hostname")
        hosts = [canonicalize_hostname(host) for host in raw]
        if len(hosts) > 32 or sum(len(host) for host in hosts) > 4096:
            raise ValueError("NWC_ALLOWED_RELAY_HOSTS is too large")
        if len(hosts) != len(set(hosts)):
            raise ValueError("NWC_ALLOWED_RELAY_HOSTS contains duplicate hostnames")
        return ",".join(hosts)

    @field_validator("SMTP_SECURITY")
    @classmethod
    def validate_smtp_security(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in {"starttls", "tls"}:
            raise ValueError("SMTP_SECURITY must be starttls or tls")
        return normalized

    @field_validator("SMTP_HOST")
    @classmethod
    def validate_smtp_host(cls, value: str) -> str:
        if not value:
            return value
        if value.strip() != value or "://" in value or any(c in value for c in "/?#"):
            raise ValueError("SMTP_HOST must be a hostname or IP address")
        try:
            return str(ip_address(value))
        except ValueError:
            return canonicalize_hostname(value)

    @field_validator("SMTP_USERNAME", "SMTP_PASSWORD")
    @classmethod
    def validate_smtp_credential(cls, value: str) -> str:
        if value and (value.strip() != value or len(value) > 4096 or not value.isprintable()):
            raise ValueError("SMTP credentials are invalid")
        return value

    @field_validator("SMTP_FROM_EMAIL")
    @classmethod
    def validate_smtp_from_email(cls, value: str) -> str:
        if not value:
            return value
        if value.strip() != value or not value.isascii() or len(value) > 254:
            raise ValueError("SMTP_FROM_EMAIL must be a valid email address")
        try:
            address = Address(addr_spec=value)
        except (TypeError, ValueError):
            raise ValueError("SMTP_FROM_EMAIL must be a valid email address") from None
        if address.display_name or address.addr_spec != value or "." not in address.domain:
            raise ValueError("SMTP_FROM_EMAIL must be a valid email address")
        return f"{address.username}@{address.domain.lower()}"

    @model_validator(mode="after")
    def validate_separate_ip_inventory(self) -> Settings:
        if self.PASSKEYS_ENABLED:
            origin_hostname = urlsplit(self.WEBAUTHN_ORIGIN).hostname
            if origin_hostname is None or (
                origin_hostname != self.WEBAUTHN_RP_ID
                and not origin_hostname.endswith(f".{self.WEBAUTHN_RP_ID}")
            ):
                raise ValueError(
                    "WEBAUTHN_ORIGIN hostname must equal WEBAUTHN_RP_ID or be its subdomain"
                )
        edge_ids = {edge.id for edge in self.relay_edges_list}
        heartbeat_key_ids = set(self.relay_heartbeat_keys)
        if not edge_ids and self.RELAY_HEARTBEAT_KEYS:
            raise ValueError("RELAY_HEARTBEAT_KEYS must be empty when RELAY_EDGES is empty")
        if edge_ids and edge_ids != heartbeat_key_ids:
            raise ValueError("RELAY_HEARTBEAT_KEYS must match configured RELAY_EDGES exactly")
        if self.DNS_SUPERVISION_STALE_SECONDS < self.DNS_SUPERVISION_INTERVAL_SECONDS:
            raise ValueError(
                "DNS_SUPERVISION_STALE_SECONDS must be at least DNS_SUPERVISION_INTERVAL_SECONDS"
            )
        if self.DNS_SUPERVISION_ENABLED:
            target_count = len(self.dns_supervision_targets_list)
            if not target_count:
                raise ValueError(
                    "DNS_SUPERVISION_TARGETS is required when DNS supervision is enabled"
                )
            resolver_count = len(self.dns_supervision_resolvers_list)
            if not 2 <= resolver_count <= 4:
                raise ValueError(
                    "DNS_SUPERVISION_RESOLVERS requires two to four resolvers when DNS supervision is enabled"
                )
        for product in ("PORT", "RELAY", "RELAY_WILDCARD"):
            monthly = getattr(self, f"{product}_MONTHLY_SATS")
            yearly = getattr(self, f"{product}_YEARLY_SATS")
            if yearly != monthly * 10:
                raise ValueError(
                    f"{product}_YEARLY_SATS must equal 10 times {product}_MONTHLY_SATS"
                )
        framed = set(self.relay_public_ips_list)
        shared = set(self.relay_shared_ips_list)
        routed = set(self.wireguard_public_ips_list)
        port_edges = self.port_ha_edges_list
        framed_endpoints = self.framed_ip_endpoints_map
        overlap = framed & shared
        if overlap:
            raise ValueError(
                "RELAY_PUBLIC_IPS and RELAY_SHARED_IPS must be disjoint; overlap: "
                + ", ".join(sorted(overlap))
            )
        routed_overlap = routed & (framed | shared)
        if routed_overlap:
            raise ValueError(
                "WIREGUARD_PUBLIC_IPS must be disjoint from relay listener inventory; overlap: "
                + ", ".join(sorted(routed_overlap))
            )
        if port_edges:
            if len(port_edges) < 2:
                raise ValueError("PORT_HA_EDGES requires at least two provider edges")
            if len(shared) != 1:
                raise ValueError(
                    "PORT_HA_EDGES currently requires exactly one RELAY_SHARED_IPS entry"
                )
            primary_ip = next(iter(shared))
            if RelayEdge(self.RELAY_CONTROL_URL, primary_ip) not in port_edges:
                raise ValueError(
                    "PORT_HA_EDGES must map RELAY_CONTROL_URL to the RELAY_SHARED_IPS address"
                )
            if not self.PORT_HOSTNAME_SUFFIX:
                raise ValueError(
                    "PORT_HOSTNAME_SUFFIX is required when PORT_HA_EDGES is configured"
                )
            configured_endpoints = set(self.relay_control_urls_list)
            missing_endpoints = {edge.endpoint for edge in port_edges} - configured_endpoints
            if missing_endpoints:
                raise ValueError("every PORT_HA_EDGES endpoint must appear in RELAY_CONTROL_URLS")
            edge_inventory_overlap = ({edge.ip for edge in port_edges} - shared) & (framed | routed)
            if edge_inventory_overlap:
                raise ValueError(
                    "PORT_HA_EDGES provider IPs must be disjoint from dedicated IP inventory"
                )
        elif self.PORT_HOSTNAME_SUFFIX:
            raise ValueError("PORT_HA_EDGES is required when PORT_HOSTNAME_SUFFIX is configured")
        if framed_endpoints and set(framed_endpoints) != framed:
            raise ValueError("FRAMED_IP_ENDPOINTS must map every RELAY_PUBLIC_IPS address exactly")
        if set(framed_endpoints.values()) - set(self.relay_control_urls_list):
            raise ValueError("every FRAMED_IP_ENDPOINTS value must appear in RELAY_CONTROL_URLS")
        if self.OFFLINE_ENTITLEMENTS_ENABLED:
            if not _OFFLINE_EDGE_ID_RE.fullmatch(self.OFFLINE_ENTITLEMENT_KEY_ID):
                raise ValueError(
                    "OFFLINE_ENTITLEMENT_KEY_ID must be a lowercase stable key identifier"
                )
            if not self.OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE:
                raise ValueError(
                    "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE is required when offline entitlements are enabled"
                )
            endpoint_counts: dict[str, int] = {}
            for edge in self.relay_edges_list:
                endpoint_counts[edge.endpoint] = endpoint_counts.get(edge.endpoint, 0) + 1
            used_endpoints = {
                self.RELAY_CONTROL_URL,
                *self.relay_control_urls_list,
                *(edge.endpoint for edge in port_edges),
                *framed_endpoints.values(),
            }
            if any(endpoint_counts.get(endpoint) != 1 for endpoint in used_endpoints):
                raise ValueError(
                    "every configured relay endpoint must map to exactly one RELAY_EDGES id"
                )
            if self.RESOURCE_REUSE_QUARANTINE_SECONDS <= (
                self.OFFLINE_ENTITLEMENT_GRACE_SECONDS + 120
            ):
                raise ValueError(
                    "RESOURCE_REUSE_QUARANTINE_SECONDS must exceed offline entitlement grace plus 120 seconds"
                )
            if self.RELAY_RENEWAL_GRACE_SECONDS <= (self.OFFLINE_ENTITLEMENT_GRACE_SECONDS + 120):
                raise ValueError(
                    "RELAY_RENEWAL_GRACE_SECONDS must exceed offline entitlement grace plus 120 seconds"
                )
        if self.wireguard_enabled:
            if any(ip_address(address).version != 4 for address in routed):
                raise ValueError("WIREGUARD_PUBLIC_IPS currently supports IPv4 addresses only")
            if not self.WIREGUARD_RELAY_PUBLIC_KEY or not self.WIREGUARD_ENDPOINT:
                raise ValueError(
                    "WIREGUARD_RELAY_PUBLIC_KEY and WIREGUARD_ENDPOINT are required when "
                    "WIREGUARD_PUBLIC_IPS is configured"
                )
            if (
                self.WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS
                < self.WIREGUARD_RECONCILE_INTERVAL_SECONDS * 2
            ):
                raise ValueError(
                    "WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS must be at least twice "
                    "WIREGUARD_RECONCILE_INTERVAL_SECONDS"
                )
            if self.IP_REUSE_QUARANTINE_SECONDS <= (
                self.WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS
                + self.WIREGUARD_RECONCILE_INTERVAL_SECONDS
            ):
                raise ValueError(
                    "IP_REUSE_QUARANTINE_SECONDS must exceed WireGuard reconciliation "
                    "staleness plus one interval"
                )
        minimum_window = self.PAYMENT_MIN_PAYABLE_SECONDS + self.PAYMENT_EXPIRY_SAFETY_SECONDS
        for claim_ttl_field in (
            "RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS",
            "RELAY_DOMAIN_CLAIM_TTL_SECONDS",
        ):
            if minimum_window >= getattr(self, claim_ttl_field):
                raise ValueError(
                    f"{claim_ttl_field} must cover the minimum payable window "
                    "and payment expiry safety interval"
                )
        if minimum_window >= self.RESOURCE_RESERVATION_TTL_SECONDS:
            raise ValueError(
                "RESOURCE_RESERVATION_TTL_SECONDS must cover the minimum payable window "
                "and payment expiry safety interval"
            )
        if minimum_window >= self.RELAY_RENEWAL_GRACE_SECONDS:
            raise ValueError(
                "RELAY_RENEWAL_GRACE_SECONDS must cover the minimum payable window "
                "and payment expiry safety interval"
            )
        if (
            self.PAYMENT_LIGHTNING_ADAPTER.lower() == "lnd"
            and self.PAYMENT_EXPIRY_SAFETY_SECONDS < self.LND_REQUEST_TIMEOUT_SECONDS
        ):
            raise ValueError(
                "PAYMENT_EXPIRY_SAFETY_SECONDS must be at least LND_REQUEST_TIMEOUT_SECONDS"
            )
        if (
            self.PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS
            < self.PAYMENT_RECONCILIATION_INTERVAL_SECONDS * 2
        ):
            raise ValueError(
                "PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS must be at least twice "
                "PAYMENT_RECONCILIATION_INTERVAL_SECONDS"
            )
        if self.BTC_USD_PRICE_MAX_STALE_SECONDS < self.BTC_USD_PRICE_REFRESH_SECONDS * 2:
            raise ValueError(
                "BTC_USD_PRICE_MAX_STALE_SECONDS must be at least twice "
                "BTC_USD_PRICE_REFRESH_SECONDS"
            )
        if (
            self.NOTIFICATION_RECONCILIATION_STALE_AFTER_SECONDS
            < self.NOTIFICATION_RECONCILIATION_INTERVAL_SECONDS * 2
        ):
            raise ValueError(
                "NOTIFICATION_RECONCILIATION_STALE_AFTER_SECONDS must be at least twice "
                "NOTIFICATION_RECONCILIATION_INTERVAL_SECONDS"
            )
        if self.STABLECOIN_PAYMENTS_ENABLED:
            if PaymentMethod.STABLECOIN_SWAP not in self.enabled_payment_methods:
                raise ValueError(
                    "PAYMENT_ENABLED_METHODS must include stablecoin_swap when stablecoin "
                    "payments are enabled"
                )
            if not self.PAYMENT_RECONCILIATION_ENABLED:
                raise ValueError(
                    "PAYMENT_RECONCILIATION_ENABLED is required when stablecoin payments "
                    "are enabled"
                )
            if (
                self.STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS + self.PAYMENT_EXPIRY_SAFETY_SECONDS
                >= self.RESOURCE_RESERVATION_TTL_SECONDS
            ):
                raise ValueError(
                    "STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS plus payment expiry safety must "
                    "be shorter than RESOURCE_RESERVATION_TTL_SECONDS"
                )
            for claim_ttl_field in (
                "RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS",
                "RELAY_DOMAIN_CLAIM_TTL_SECONDS",
            ):
                if (
                    getattr(self, claim_ttl_field)
                    <= self.STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS
                    + self.PAYMENT_EXPIRY_SAFETY_SECONDS
                ):
                    raise ValueError(
                        "STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS plus payment expiry safety "
                        f"must be shorter than {claim_ttl_field}"
                    )
        if self.NWC_PAYMENT_LEASE_SECONDS < self.NWC_HELPER_TIMEOUT_SECONDS + 5:
            raise ValueError(
                "NWC_PAYMENT_LEASE_SECONDS must exceed NWC_HELPER_TIMEOUT_SECONDS by at least 5"
            )
        if self.NWC_ALLOW_PUBLIC_RELAYS and self.nwc_allowed_relay_hosts:
            raise ValueError(
                "NWC_ALLOW_PUBLIC_RELAYS and NWC_ALLOWED_RELAY_HOSTS are mutually exclusive"
            )
        if self.SMTP_TIMEOUT_SECONDS + 5 > self.REMINDER_DELIVERY_LEASE_SECONDS:
            raise ValueError(
                "REMINDER_DELIVERY_LEASE_SECONDS must exceed SMTP_TIMEOUT_SECONDS by at least 5"
            )
        if self.SMTP_TIMEOUT_SECONDS + 5 > self.NOTIFICATION_DELIVERY_LEASE_SECONDS:
            raise ValueError(
                "NOTIFICATION_DELIVERY_LEASE_SECONDS must exceed SMTP_TIMEOUT_SECONDS by at least 5"
            )
        if bool(self.SMTP_USERNAME) != bool(self.SMTP_PASSWORD):
            raise ValueError("SMTP_USERNAME and SMTP_PASSWORD must be configured together")
        if self.REMINDER_EMAIL_ENABLED or self.ANNOUNCEMENT_EMAIL_ENABLED:
            if not self.NOTIFICATION_RECONCILIATION_ENABLED:
                raise ValueError(
                    "NOTIFICATION_RECONCILIATION_ENABLED is required when email delivery is enabled"
                )
            if not self.CREDENTIAL_ENCRYPTION_KEY:
                raise ValueError(
                    "CREDENTIAL_ENCRYPTION_KEY is required when email delivery is enabled"
                )
            if not self.SMTP_HOST or not self.SMTP_FROM_EMAIL:
                raise ValueError(
                    "SMTP_HOST and SMTP_FROM_EMAIL are required when email delivery is enabled"
                )
        rate_limit_windows = (
            self.RATE_LIMIT_SIGNUP_WINDOW_SECONDS,
            self.RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS,
            self.RATE_LIMIT_BROWSER_LOGIN_WINDOW_SECONDS,
            self.RATE_LIMIT_PAYMENT_CREATE_WINDOW_SECONDS,
            self.RATE_LIMIT_DOMAIN_VERIFY_WINDOW_SECONDS,
            self.RATE_LIMIT_CLIENT_CERT_WINDOW_SECONDS,
        )
        if max(rate_limit_windows) > self.RATE_LIMIT_BUCKET_RETENTION_SECONDS:
            raise ValueError(
                "RATE_LIMIT_BUCKET_RETENTION_SECONDS must cover every rate-limit window"
            )
        if self.ENVIRONMENT == EnvironmentMode.PRODUCTION:
            self._validate_production()
        return self

    def _validate_production(self) -> None:
        failures: list[str] = []
        if not self.PUBLIC_SITE_URL.startswith("https://"):
            failures.append("PUBLIC_SITE_URL must use HTTPS in production")
        if self.PASSKEYS_ENABLED:
            if not self.WEBAUTHN_ORIGIN.startswith("https://"):
                failures.append("WEBAUTHN_ORIGIN must use HTTPS when passkeys are enabled")
            if self.WEBAUTHN_ORIGIN != self.PUBLIC_SITE_URL:
                failures.append(
                    "WEBAUTHN_ORIGIN must equal PUBLIC_SITE_URL when passkeys are enabled"
                )
        try:
            database_driver = make_url(self.DATABASE_URL).drivername
        except Exception:
            database_driver = ""
        if database_driver != "postgresql+psycopg":
            failures.append("DATABASE_URL must use PostgreSQL with the psycopg driver")
        if self.DATABASE_MIGRATE_ON_STARTUP:
            failures.append("DATABASE_MIGRATE_ON_STARTUP must be false")
        if self.PAYMENT_LIGHTNING_ADAPTER.lower() != "lnd":
            failures.append("PAYMENT_LIGHTNING_ADAPTER must use the lnd adapter")
        if PaymentMethod.LIGHTNING not in self.enabled_payment_methods:
            failures.append("PAYMENT_ENABLED_METHODS must enable direct Lightning")
        if not self.LND_INVOICE_HMAC_KEY:
            failures.append("LND_INVOICE_HMAC_KEY must be set to a dedicated 32-byte hex key")
        if not self.PAYMENT_RECONCILIATION_ENABLED:
            failures.append("PAYMENT_RECONCILIATION_ENABLED must be true")
        if self.enabled_payment_methods - {
            PaymentMethod.LIGHTNING,
            PaymentMethod.NWC,
            PaymentMethod.STABLECOIN_SWAP,
        }:
            failures.append("PAYMENT_ENABLED_METHODS must not enable unsupported methods")
        if self.STABLECOIN_PAYMENTS_ENABLED and not self.BOLTZ_WEB_URL.startswith("https://"):
            failures.append("BOLTZ_WEB_URL must use HTTPS when stablecoin payments are enabled")
        if PaymentMethod.NWC in self.enabled_payment_methods:
            if self.PAYMENT_NWC_ADAPTER.lower() != "nwc":
                failures.append("PAYMENT_NWC_ADAPTER must use the nwc adapter when NWC is enabled")
            if not self.CREDENTIAL_ENCRYPTION_KEY:
                failures.append(
                    "CREDENTIAL_ENCRYPTION_KEY must contain a dedicated 32-byte hex key when NWC is enabled"
                )
            if not Path(self.NWC_HELPER_PATH).is_absolute():
                failures.append("NWC_HELPER_PATH must be absolute")
            if not self.NWC_ALLOW_PUBLIC_RELAYS and not self.nwc_allowed_relay_hosts:
                failures.append(
                    "NWC relay policy requires NWC_ALLOW_PUBLIC_RELAYS=true or at least one "
                    "NWC_ALLOWED_RELAY_HOSTS entry"
                )
        if (
            self.REMINDER_EMAIL_ENABLED or self.ANNOUNCEMENT_EMAIL_ENABLED
        ) and self.SMTP_SECURITY not in {"starttls", "tls"}:
            failures.append("SMTP_SECURITY must use TLS in production")
        if (
            self.SECRET_KEY == DEFAULT_SECRET_KEY
            or len(self.SECRET_KEY) < MIN_PRODUCTION_SECRET_LENGTH
        ):
            failures.append("SECRET_KEY must be changed and contain at least 32 characters")
        for field_name in ("TOKEN_HASH_KEY", "RELAY_SECRET"):
            value = getattr(self, field_name)
            if not value or len(value) < MIN_PRODUCTION_SECRET_LENGTH:
                failures.append(f"{field_name} must be explicitly set to at least 32 characters")
        explicit_secrets = (
            self.SECRET_KEY,
            self.TOKEN_HASH_KEY,
            self.RELAY_SECRET,
            self.ADMIN_TOKEN,
            self.LND_INVOICE_HMAC_KEY,
        )
        if all(explicit_secrets) and len(set(explicit_secrets)) != len(explicit_secrets):
            failures.append(
                "SECRET_KEY, TOKEN_HASH_KEY, RELAY_SECRET, ADMIN_TOKEN, and "
                "LND_INVOICE_HMAC_KEY must be distinct"
            )
        if self.CREDENTIAL_ENCRYPTION_KEY:
            credential_keys = self.CREDENTIAL_ENCRYPTION_KEY.split(",")
            if any(key in explicit_secrets for key in credential_keys):
                failures.append("CREDENTIAL_ENCRYPTION_KEY must be distinct from other secrets")
        if (
            self.ADMIN_TOKEN == DEFAULT_ADMIN_TOKEN
            or len(self.ADMIN_TOKEN) < MIN_PRODUCTION_SECRET_LENGTH
        ):
            failures.append("ADMIN_TOKEN must be changed and contain at least 32 characters")
        if self.DEBUG:
            failures.append("DEBUG must be false")
        if not Path(self.CA_DIR).expanduser().is_absolute():
            failures.append("CA_DIR must be an absolute path")
        if self.LEGACY_CLIENT_CERT_ISSUANCE_ENABLED:
            failures.append("LEGACY_CLIENT_CERT_ISSUANCE_ENABLED must be false")
        if self.OFFLINE_ENTITLEMENTS_ENABLED:
            if not Path(self.OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE).expanduser().is_absolute():
                failures.append("OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE must be absolute")
            else:
                try:
                    load_offline_entitlement_private_key(self.OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE)
                except ValueError as error:
                    failures.append(str(error))
        for price_field in (
            "IP_YEARLY_SATS",
            "PORT_MONTHLY_SATS",
            "PORT_YEARLY_SATS",
            "RELAY_MONTHLY_SATS",
            "RELAY_YEARLY_SATS",
        ):
            if getattr(self, price_field) <= 0:
                failures.append(f"{price_field} must be positive")
        if self.TOKEN_BYTES < MIN_PRODUCTION_TOKEN_BYTES:
            failures.append("TOKEN_BYTES must provide at least 128 bits of entropy")
        public_ip_fields = {
            "RELAY_PUBLIC_IPS": self.relay_public_ips_list,
            "RELAY_SHARED_IPS": self.relay_shared_ips_list,
            "WIREGUARD_PUBLIC_IPS": self.wireguard_public_ips_list,
            "PORT_HA_EDGES": [edge.ip for edge in self.port_ha_edges_list],
        }
        for field_name, addresses in public_ip_fields.items():
            invalid = [address for address in addresses if not _is_global_unicast_address(address)]
            if invalid:
                failures.append(
                    f"{field_name} must contain only globally routable unicast addresses"
                )
        relay_endpoint_fields = {
            "RELAY_CONTROL_URL": [self.RELAY_CONTROL_URL],
            "RELAY_CONTROL_URLS": parse_relay_endpoints(self.RELAY_CONTROL_URLS),
            "WIREGUARD_ENDPOINT": [self.WIREGUARD_ENDPOINT] if self.WIREGUARD_ENDPOINT else [],
            "FRAMED_IP_ENDPOINTS": list(self.framed_ip_endpoints_map.values()),
        }
        for field_name, endpoints in relay_endpoint_fields.items():
            for endpoint in endpoints:
                host = _relay_endpoint_host(endpoint)
                try:
                    valid = _is_global_unicast_address(host)
                except ValueError:
                    valid = _is_production_relay_hostname(host)
                if not valid:
                    failures.append(
                        f"{field_name} must use a public relay hostname or globally routable IP"
                    )
                    break
        public_domain_fields = {
            "RELAY_POOL_DOMAINS": self.relay_pool_domains_list,
            "RELAY_MANAGED_SUFFIXES": self.relay_managed_suffixes_list,
            "PORT_HOSTNAME_SUFFIX": [self.PORT_HOSTNAME_SUFFIX]
            if self.PORT_HOSTNAME_SUFFIX
            else [],
        }
        for field_name, domains in public_domain_fields.items():
            if any(not _is_production_relay_hostname(domain) for domain in domains):
                failures.append(f"{field_name} must contain only public production DNS names")
        if failures:
            raise ValueError("invalid production configuration: " + "; ".join(failures))


settings = Settings()
