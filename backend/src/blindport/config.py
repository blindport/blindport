"""Application configuration loaded from environment variables."""

from __future__ import annotations

import base64
import hashlib
from contextlib import suppress
from enum import StrEnum
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url

from .core.hostnames import canonicalize_hostname
from .core.models import PaymentMethod
from .core.wireguard import canonical_wireguard_key


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


RELAY_REAUTH_INTERVAL_DEFAULT_SECONDS = 45
RELAY_REAUTH_MAX_STALENESS_DEFAULT_SECONDS = 90
RELAY_RENEWAL_GRACE_MIN_SECONDS = (
    RELAY_REAUTH_MAX_STALENESS_DEFAULT_SECONDS + RELAY_REAUTH_INTERVAL_DEFAULT_SECONDS + 1
)
MIN_PRODUCTION_SECRET_LENGTH = 32
MIN_PRODUCTION_TOKEN_BYTES = 16
DEFAULT_SECRET_KEY = "change-me-in-production"
DEFAULT_ADMIN_TOKEN = "BLINDPORT-ADMIN-TOKEN-CHANGE-ME"
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
    BRAND_NAME: str = "Blindport"
    BRAND_TAGLINE: str = "Public reach for self-hosted services. TLS stays on your box."
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
    # Admin bearer token (a single super-admin token; in prod, store hashed)
    ADMIN_TOKEN: str = DEFAULT_ADMIN_TOKEN

    # Product catalog and sales controls
    IP_ENABLED: bool = True
    IP_SALES_PAUSED: bool = False
    IP_MONTHLY_SATS: int = 7500
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
    RELAY_MANAGED_DOMAIN_CAP: int = Field(default=1000, ge=0)
    RELAY_CUSTOMER_DOMAINS_ENABLED: bool = True

    # Durable per-account abuse limits
    ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS: int = Field(default=20, ge=1, le=1000)
    ACCOUNT_MAX_OPEN_PAYMENTS: int = Field(default=5, ge=1, le=100)

    # Public request rate limits. Direct-client scopes use only Request.client;
    # production proxies/ASGI servers must be configured with an explicit trusted
    # proxy policy so that value represents the real peer. Application code never
    # accepts Forwarded or X-Forwarded-For headers directly.
    RATE_LIMIT_SIGNUP_REQUESTS: int = Field(default=10, ge=1, le=1000)
    RATE_LIMIT_SIGNUP_WINDOW_SECONDS: int = Field(default=60, ge=1, le=3600)
    RATE_LIMIT_ADMIN_LOGIN_REQUESTS: int = Field(default=5, ge=1, le=1000)
    RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS: int = Field(default=300, ge=1, le=3600)
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
    PAYMENT_CASHU_ADAPTER: str = "mock"
    PAYMENT_NWC_ADAPTER: str = "mock"
    PAYMENT_ENABLED_METHODS: str = PaymentMethod.LIGHTNING.value

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
    NWC_HELPER_TIMEOUT_SECONDS: float = Field(default=20.0, ge=1, le=120)
    NWC_MAX_PAYMENT_ATTEMPTS: int = Field(default=3, ge=1, le=10)
    NWC_RETRY_BASE_SECONDS: int = Field(default=30, ge=1, le=3600)
    NWC_LOOKUP_INTERVAL_SECONDS: int = Field(default=30, ge=5, le=300)
    NWC_PAYMENT_LEASE_SECONDS: int = Field(default=45, ge=5, le=300)
    NWC_AUTO_RENEW_LEAD_SECONDS: int = Field(default=86400, ge=60, le=604800)

    # Optional expiration reminders paid from an operator-controlled NWC budget.
    REMINDER_EMAIL_ENABLED: bool = False
    LNEMAIL_BASE_URL: str = "https://lnemail.net"
    LNEMAIL_ACCESS_TOKEN: str = ""
    LNEMAIL_ADMIN_NWC_URI: str = ""
    LNEMAIL_REQUEST_TIMEOUT_SECONDS: float = Field(default=10.0, ge=1, le=60)
    LNEMAIL_MAX_SEND_PRICE_SATS: int = Field(default=100, ge=1, le=1000)
    REMINDER_DELIVERY_LEASE_SECONDS: int = Field(default=45, ge=10, le=300)

    # Optional payment integrations
    CASHU_MINTS: str = ""  # comma-separated mint URLs
    BOLTZ_URL: str = "https://api.boltz.exchange"

    # Relay control plane
    RELAY_CONTROL_URL: str = "relay:5443"
    RELAY_CONTROL_URLS: str = ""
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
    RELAY_MANAGED_SUFFIXES: str = ""
    RELAY_DOMAIN_CLAIM_TTL_SECONDS: int = Field(default=7200, ge=60, le=604800)
    RELAY_RENEWAL_GRACE_SECONDS: int = Field(
        default=604800,
        ge=RELAY_RENEWAL_GRACE_MIN_SECONDS,
        le=2592000,
    )
    RELAY_DNS_TIMEOUT_SECONDS: float = Field(default=5.0, gt=0, le=30)
    RESOURCE_RESERVATION_TTL_SECONDS: int = Field(default=1800, ge=60, le=86400)
    RESOURCE_REUSE_QUARANTINE_SECONDS: int = Field(default=180, ge=60, le=86400)

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
    def cashu_mints_list(self) -> list[str]:
        return [s.strip() for s in self.CASHU_MINTS.split(",") if s.strip()]

    @property
    def enabled_payment_methods(self) -> frozenset[PaymentMethod]:
        return parse_enabled_payment_methods(self.PAYMENT_ENABLED_METHODS)

    @property
    def nwc_allowed_relay_hosts(self) -> tuple[str, ...]:
        if not self.NWC_ALLOWED_RELAY_HOSTS:
            return ()
        return tuple(self.NWC_ALLOWED_RELAY_HOSTS.split(","))

    def is_payment_method_enabled(self, method: PaymentMethod) -> bool:
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
        for endpoint in {self.RELAY_CONTROL_URL, *self.relay_control_urls_list}:
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
        }
        for endpoint in {self.RELAY_CONTROL_URL, *self.relay_control_urls_list}:
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

    @field_validator("LNEMAIL_BASE_URL")
    @classmethod
    def validate_lnemail_base_url(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise ValueError("LNEMAIL_BASE_URL must be an exact HTTPS origin") from None
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
            or port not in (None, 443)
        ):
            raise ValueError("LNEMAIL_BASE_URL must be an exact HTTPS origin")
        hostname = parsed.hostname.lower()
        origin_host = f"[{hostname}]" if ":" in hostname else hostname
        return f"https://{origin_host}"

    @model_validator(mode="after")
    def validate_separate_ip_inventory(self) -> Settings:
        for product in ("IP", "PORT", "RELAY"):
            monthly = getattr(self, f"{product}_MONTHLY_SATS")
            yearly = getattr(self, f"{product}_YEARLY_SATS")
            if yearly != monthly * 10:
                raise ValueError(
                    f"{product}_YEARLY_SATS must equal 10 times {product}_MONTHLY_SATS"
                )
        framed = set(self.relay_public_ips_list)
        shared = set(self.relay_shared_ips_list)
        routed = set(self.wireguard_public_ips_list)
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
            if self.RESOURCE_REUSE_QUARANTINE_SECONDS <= (
                self.WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS
                + self.WIREGUARD_RECONCILE_INTERVAL_SECONDS
            ):
                raise ValueError(
                    "RESOURCE_REUSE_QUARANTINE_SECONDS must exceed WireGuard reconciliation "
                    "staleness plus one interval"
                )
        minimum_window = self.PAYMENT_MIN_PAYABLE_SECONDS + self.PAYMENT_EXPIRY_SAFETY_SECONDS
        if minimum_window >= self.RELAY_DOMAIN_CLAIM_TTL_SECONDS:
            raise ValueError(
                "RELAY_DOMAIN_CLAIM_TTL_SECONDS must cover the minimum payable window "
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
        if self.NWC_PAYMENT_LEASE_SECONDS < self.NWC_HELPER_TIMEOUT_SECONDS + 5:
            raise ValueError(
                "NWC_PAYMENT_LEASE_SECONDS must exceed NWC_HELPER_TIMEOUT_SECONDS by at least 5"
            )
        reminder_timeout = max(
            self.NWC_HELPER_TIMEOUT_SECONDS,
            self.LNEMAIL_REQUEST_TIMEOUT_SECONDS,
        )
        if self.REMINDER_EMAIL_ENABLED:
            reminder_timeout = (
                self.NWC_HELPER_TIMEOUT_SECONDS + self.LNEMAIL_REQUEST_TIMEOUT_SECONDS
            )
        if reminder_timeout + 5 > self.REMINDER_DELIVERY_LEASE_SECONDS:
            raise ValueError(
                "REMINDER_DELIVERY_LEASE_SECONDS must exceed provider timeouts by at least 5"
            )
        if self.REMINDER_EMAIL_ENABLED:
            if not self.PAYMENT_RECONCILIATION_ENABLED:
                raise ValueError(
                    "PAYMENT_RECONCILIATION_ENABLED is required when payment reminders are enabled"
                )
            if not self.CREDENTIAL_ENCRYPTION_KEY:
                raise ValueError(
                    "CREDENTIAL_ENCRYPTION_KEY is required when payment reminders are enabled"
                )
            if not self.LNEMAIL_ACCESS_TOKEN or not self.LNEMAIL_ADMIN_NWC_URI:
                raise ValueError(
                    "LNEMAIL_ACCESS_TOKEN and LNEMAIL_ADMIN_NWC_URI are required when payment "
                    "reminders are enabled"
                )
            if self.PAYMENT_NWC_ADAPTER.lower() != "nwc":
                raise ValueError("PAYMENT_NWC_ADAPTER must use NWC for payment reminders")
            if not self.nwc_allowed_relay_hosts:
                raise ValueError(
                    "NWC_ALLOWED_RELAY_HOSTS is required when payment reminders are enabled"
                )
        rate_limit_windows = (
            self.RATE_LIMIT_SIGNUP_WINDOW_SECONDS,
            self.RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS,
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
        if self.enabled_payment_methods - {PaymentMethod.LIGHTNING, PaymentMethod.NWC}:
            failures.append("PAYMENT_ENABLED_METHODS must not enable unsupported methods")
        if PaymentMethod.NWC in self.enabled_payment_methods:
            if self.PAYMENT_NWC_ADAPTER.lower() != "nwc":
                failures.append("PAYMENT_NWC_ADAPTER must use the nwc adapter when NWC is enabled")
            if not self.CREDENTIAL_ENCRYPTION_KEY:
                failures.append(
                    "CREDENTIAL_ENCRYPTION_KEY must contain a dedicated 32-byte hex key when NWC is enabled"
                )
            if not Path(self.NWC_HELPER_PATH).is_absolute():
                failures.append("NWC_HELPER_PATH must be absolute")
            if not self.nwc_allowed_relay_hosts:
                failures.append("NWC_ALLOWED_RELAY_HOSTS must contain at least one trusted host")
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
        for price_field in (
            "IP_MONTHLY_SATS",
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
        }
        for field_name, domains in public_domain_fields.items():
            if any(not _is_production_relay_hostname(domain) for domain in domains):
                failures.append(f"{field_name} must contain only public production DNS names")
        if failures:
            raise ValueError("invalid production configuration: " + "; ".join(failures))


settings = Settings()
