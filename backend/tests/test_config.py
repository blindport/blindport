"""Validation tests for relay inventory settings."""

from __future__ import annotations

import base64

import pytest
from pydantic import ValidationError

from blindport.config import (
    DEFAULT_ADMIN_TOKEN,
    DEFAULT_SECRET_KEY,
    RELAY_RENEWAL_GRACE_MIN_SECONDS,
    EnvironmentMode,
    Settings,
    canonicalize_relay_endpoint,
    parse_framed_ip_endpoints,
    parse_managed_suffixes,
    parse_port_ha_edges,
    parse_relay_edges,
    parse_relay_endpoints,
    parse_relay_heartbeat_keys,
    parse_relay_pool_domains,
    parse_tcp_port_pool,
    parse_udp_port_pool,
    validate_v3_onion_hostname,
)
from blindport.core.models import PaymentMethod


def _production_settings(**overrides) -> Settings:
    values = {
        "ENVIRONMENT": "production",
        "PUBLIC_SITE_URL": "https://blindport.com",
        "DATABASE_URL": "postgresql+psycopg://blindport:database-secret@db/blindport",
        "DATABASE_MIGRATE_ON_STARTUP": False,
        "PAYMENT_LIGHTNING_ADAPTER": "lnd",
        "PAYMENT_ENABLED_METHODS": "lightning",
        "PAYMENT_RECONCILIATION_ENABLED": True,
        "LND_INVOICE_HMAC_KEY": "ab" * 32,
        "SECRET_KEY": "s" * 40,
        "TOKEN_HASH_KEY": "t" * 40,
        "RELAY_SECRET": "r" * 40,
        "ADMIN_TOKEN": "A" * 40,
        "DEBUG": False,
        "CA_DIR": "/var/lib/blindport/ca",
        "LEGACY_CLIENT_CERT_ISSUANCE_ENABLED": False,
        "IP_YEARLY_SATS": 75000,
        "PORT_MONTHLY_SATS": 1500,
        "PORT_YEARLY_SATS": 15000,
        "RELAY_MONTHLY_SATS": 3000,
        "RELAY_YEARLY_SATS": 30000,
        "RELAY_WILDCARD_MONTHLY_SATS": 7500,
        "RELAY_WILDCARD_YEARLY_SATS": 75000,
        "RELAY_CONTROL_URL": "relay.blindport.com:5443",
        "RELAY_CONTROL_URLS": "relay.blindport.com:5443",
        "RELAY_PUBLIC_IPS": "8.8.8.8",
        "RELAY_SHARED_IPS": "1.1.1.1",
        "WIREGUARD_PUBLIC_IPS": "",
        "RELAY_POOL_DOMAINS": "pool1.blindport.com,pool2.blindport.com",
        "RELAY_MANAGED_SUFFIXES": "relay.blindport.com",
        "TOKEN_BYTES": 16,
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_startup_database_migration_defaults_on() -> None:
    assert Settings(_env_file=None).DATABASE_MIGRATE_ON_STARTUP is True


def test_obsolete_ip_monthly_price_is_ignored() -> None:
    assert Settings(_env_file=None, IP_MONTHLY_SATS=1).IP_YEARLY_SATS == 75000


def test_relay_wildcard_price_defaults_are_yearly_discounted() -> None:
    settings = Settings(_env_file=None)

    assert (settings.RELAY_WILDCARD_MONTHLY_SATS, settings.RELAY_WILDCARD_YEARLY_SATS) == (
        7500,
        75000,
    )


def test_client_certificate_defaults_are_bounded_and_legacy_enabled() -> None:
    settings = Settings(_env_file=None)

    assert settings.CLIENT_CERT_TTL_DAYS == 30
    assert settings.LEGACY_CLIENT_CERT_ISSUANCE_ENABLED is True


def test_admin_browser_session_and_login_limits_are_bounded() -> None:
    settings = Settings(_env_file=None)

    assert settings.ADMIN_SESSION_MAX_AGE_SECONDS == 900
    assert settings.RATE_LIMIT_BROWSER_LOGIN_REQUESTS == 10
    assert settings.RATE_LIMIT_BROWSER_LOGIN_WINDOW_SECONDS == 300

    for field, value in (
        ("ADMIN_SESSION_MAX_AGE_SECONDS", 59),
        ("ADMIN_SESSION_MAX_AGE_SECONDS", 86401),
        ("RATE_LIMIT_BROWSER_LOGIN_REQUESTS", 1001),
        ("RATE_LIMIT_BROWSER_LOGIN_WINDOW_SECONDS", 3601),
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize("days", [0, 91])
def test_client_certificate_ttl_is_bounded(days: int) -> None:
    with pytest.raises(ValidationError, match="CLIENT_CERT_TTL_DAYS"):
        Settings(_env_file=None, CLIENT_CERT_TTL_DAYS=days)


def test_environment_and_payment_method_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    monkeypatch.delenv("PAYMENT_ENABLED_METHODS", raising=False)
    monkeypatch.delenv("STABLECOIN_PAYMENTS_ENABLED", raising=False)

    settings = Settings(_env_file=None)

    assert settings.ENVIRONMENT == EnvironmentMode.DEVELOPMENT
    assert {method.value for method in settings.enabled_payment_methods} == {"lightning"}
    assert settings.STABLECOIN_PAYMENTS_ENABLED is False
    assert settings.is_payment_method_enabled(PaymentMethod.LIGHTNING)


def test_stablecoin_feature_requires_allowlist_and_reconciliation() -> None:
    with pytest.raises(ValidationError, match="PAYMENT_ENABLED_METHODS"):
        Settings(
            _env_file=None,
            PAYMENT_ENABLED_METHODS="lightning",
            STABLECOIN_PAYMENTS_ENABLED=True,
        )
    with pytest.raises(ValidationError, match="PAYMENT_RECONCILIATION_ENABLED"):
        Settings(
            _env_file=None,
            PAYMENT_ENABLED_METHODS="lightning,stablecoin_swap",
            STABLECOIN_PAYMENTS_ENABLED=True,
            PAYMENT_RECONCILIATION_ENABLED=False,
        )


def test_stablecoin_feature_has_bounded_secure_defaults() -> None:
    settings = Settings(
        _env_file=None,
        PAYMENT_ENABLED_METHODS="lightning,stablecoin_swap",
        STABLECOIN_PAYMENTS_ENABLED=True,
        PAYMENT_RECONCILIATION_ENABLED=True,
    )

    assert settings.is_payment_method_enabled(PaymentMethod.STABLECOIN_SWAP)
    assert settings.STABLECOIN_SWAP_MARKUP_BPS == 1000
    assert settings.STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS == 1200
    assert settings.STABLECOIN_SWAP_DEFAULT_ASSET == "USDC-BASE"
    assert settings.STABLECOIN_SWAP_MIN_INVOICE_SATS == 5000
    assert settings.STABLECOIN_CHECKOUT_PROVIDER == "lightning_swap"
    assert settings.BOLTZ_WEB_URL == "https://boltz.exchange"
    assert settings.LIGHTNING_SWAP_WEB_URL == "https://lightning-swap.com"
    assert settings.LIGHTNING_SWAP_DEFAULT_ASSET == "USDCSOL"


@pytest.mark.parametrize(
    "field,value",
    [
        ("BOLTZ_WEB_URL", "https://boltz.exchange/swap"),
        ("BOLTZ_WEB_URL", "https://user@boltz.exchange"),
        ("LIGHTNING_SWAP_WEB_URL", "https://lightning-swap.com/swap"),
        ("LIGHTNING_SWAP_WEB_URL", "https://user@lightning-swap.com"),
        ("STABLECOIN_SWAP_DEFAULT_ASSET", "BTC"),
        ("STABLECOIN_SWAP_DEFAULT_ASSET", "usdc-base"),
    ],
)
def test_stablecoin_checkout_settings_are_strict(field: str, value: str) -> None:
    with pytest.raises(ValidationError, match=field):
        Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize(
    ("provider", "origin_field", "origin"),
    [
        ("boltz", "BOLTZ_WEB_URL", "http://boltz.internal"),
        ("lightning_swap", "LIGHTNING_SWAP_WEB_URL", "http://lightning-swap.internal"),
    ],
)
def test_production_stablecoin_checkout_requires_selected_provider_https(
    provider: str, origin_field: str, origin: str
) -> None:
    with pytest.raises(ValidationError, match=origin_field):
        _production_settings(
            PAYMENT_ENABLED_METHODS="lightning,stablecoin_swap",
            STABLECOIN_PAYMENTS_ENABLED=True,
            STABLECOIN_CHECKOUT_PROVIDER=provider,
            **{origin_field: origin},
        )


def test_stablecoin_checkout_provider_is_limited_to_supported_values() -> None:
    with pytest.raises(ValidationError, match="STABLECOIN_CHECKOUT_PROVIDER"):
        Settings(_env_file=None, STABLECOIN_CHECKOUT_PROVIDER="other")


@pytest.mark.parametrize("asset", ["USDC-BASE", "usdsol", "BTC", "USDC"])
def test_lightning_swap_asset_is_limited_to_supported_stablecoin_networks(asset: str) -> None:
    with pytest.raises(ValidationError, match="LIGHTNING_SWAP_DEFAULT_ASSET"):
        Settings(_env_file=None, LIGHTNING_SWAP_DEFAULT_ASSET=asset)


def test_environment_mode_is_strict() -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, ENVIRONMENT="prod")


def test_v3_onion_hostname_validation() -> None:
    hostname = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
    assert validate_v3_onion_hostname(hostname.upper()) == hostname
    settings = Settings(_env_file=None, ONION_HOST=hostname)
    assert hostname == settings.ONION_HOST


@pytest.mark.parametrize(
    "value",
    [
        "",
        "blindport.com",
        " https://blindport.com",
        "https://user@blindport.com",
        "https://blindport.com/path",
        "https://blindport.com?source=test",
    ],
)
def test_public_site_url_requires_an_http_origin(value: str) -> None:
    with pytest.raises(ValidationError, match="PUBLIC_SITE_URL"):
        Settings(_env_file=None, PUBLIC_SITE_URL=value)


def test_public_site_url_is_canonicalized_and_requires_https_in_production() -> None:
    assert (
        Settings(_env_file=None, PUBLIC_SITE_URL="https://blindport.com/").PUBLIC_SITE_URL
        == "https://blindport.com"
    )
    with pytest.raises(ValidationError, match="PUBLIC_SITE_URL must use HTTPS"):
        _production_settings(PUBLIC_SITE_URL="http://blindport.com")


def test_http_origins_canonicalize_hostname_and_default_port() -> None:
    settings = Settings(
        _env_file=None,
        PASSKEYS_ENABLED=True,
        PUBLIC_SITE_URL="https://EXAMPLE.com:443/",
        WEBAUTHN_RP_ID="example.com",
        WEBAUTHN_ORIGIN="https://EXAMPLE.com:443",
    )

    assert settings.PUBLIC_SITE_URL == "https://example.com"
    assert settings.WEBAUTHN_RP_ID == "example.com"
    assert settings.WEBAUTHN_ORIGIN == "https://example.com"


def test_production_passkeys_require_the_canonical_public_origin() -> None:
    settings = _production_settings(
        PASSKEYS_ENABLED=True,
        WEBAUTHN_RP_ID="blindport.com",
        WEBAUTHN_ORIGIN="https://BLINDPORT.com:443",
    )

    assert settings.WEBAUTHN_ORIGIN == settings.PUBLIC_SITE_URL == "https://blindport.com"


@pytest.mark.parametrize(
    "hostname",
    [
        "legacyexample.onion",
        "not-base32!" + "a" * 45 + ".onion",
        "awo4goq5pozh2qdf63mhfghlm6l4xr6y4eudeqdon5i4ybidkenrsxad.onion",
    ],
)
def test_onion_hostname_rejects_non_v3_values(hostname: str) -> None:
    with pytest.raises((ValueError, ValidationError), match="ONION_HOST"):
        Settings(_env_file=None, ONION_HOST=hostname)


@pytest.mark.parametrize(
    "value",
    ["", "cash", "cashu", "lightning, nwc", "lightning,", "lightning,lightning"],
)
def test_enabled_payment_methods_are_strict(value: str) -> None:
    with pytest.raises(ValidationError, match="PAYMENT_ENABLED_METHODS"):
        Settings(_env_file=None, PAYMENT_ENABLED_METHODS=value)


@pytest.mark.parametrize("value", ["ab", "AB" * 32, "zz" * 32])
def test_invoice_hmac_key_requires_canonical_32_byte_hex(value: str) -> None:
    with pytest.raises(ValidationError, match="LND_INVOICE_HMAC_KEY"):
        Settings(_env_file=None, LND_INVOICE_HMAC_KEY=value)


def test_production_settings_accept_direct_lightning_baseline() -> None:
    settings = _production_settings()

    assert settings.ENVIRONMENT == EnvironmentMode.PRODUCTION
    assert {method.value for method in settings.enabled_payment_methods} == {"lightning"}
    assert settings.RATE_LIMIT_PAYMENT_CREATE_REQUESTS >= 30


def test_production_settings_allow_secured_nwc_alongside_lightning() -> None:
    settings = _production_settings(
        PAYMENT_ENABLED_METHODS="lightning,nwc",
        PAYMENT_NWC_ADAPTER="nwc",
        CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
        NWC_ALLOWED_RELAY_HOSTS="relay.getalby.com",
    )

    assert {method.value for method in settings.enabled_payment_methods} == {
        "lightning",
        "nwc",
    }
    assert settings.NWC_ALLOW_LEGACY_NIP04 is False


def test_legacy_nip04_fallback_is_explicitly_configurable() -> None:
    settings = Settings(_env_file=None, NWC_ALLOW_LEGACY_NIP04=True)

    assert settings.NWC_ALLOW_LEGACY_NIP04 is True


def test_production_settings_allow_public_user_selected_nwc_relays() -> None:
    settings = _production_settings(
        PAYMENT_ENABLED_METHODS="lightning,nwc",
        PAYMENT_NWC_ADAPTER="nwc",
        CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
        NWC_ALLOW_PUBLIC_RELAYS=True,
    )

    assert settings.NWC_ALLOW_PUBLIC_RELAYS is True
    assert settings.nwc_allowed_relay_hosts == ()


@pytest.mark.parametrize("value", ["ab", "AB" * 32, "zz" * 32, f"{'ab' * 32},{'ab' * 32}"])
def test_credential_keyring_requires_distinct_canonical_32_byte_hex(value: str) -> None:
    with pytest.raises(ValidationError, match="credential encryption"):
        Settings(_env_file=None, CREDENTIAL_ENCRYPTION_KEY=value)


def test_production_nwc_requires_dedicated_credential_key() -> None:
    with pytest.raises(ValidationError, match="CREDENTIAL_ENCRYPTION_KEY"):
        _production_settings(
            PAYMENT_ENABLED_METHODS="lightning,nwc",
            PAYMENT_NWC_ADAPTER="nwc",
            CREDENTIAL_ENCRYPTION_KEY="",
            NWC_ALLOWED_RELAY_HOSTS="relay.getalby.com",
        )


def test_production_nwc_requires_an_explicit_relay_policy() -> None:
    with pytest.raises(ValidationError, match="NWC relay policy"):
        _production_settings(
            PAYMENT_ENABLED_METHODS="lightning,nwc",
            PAYMENT_NWC_ADAPTER="nwc",
            CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
            NWC_ALLOWED_RELAY_HOSTS="",
        )


def test_nwc_relay_policies_are_mutually_exclusive() -> None:
    with pytest.raises(ValidationError, match="mutually exclusive"):
        Settings(
            _env_file=None,
            NWC_ALLOWED_RELAY_HOSTS="relay.getalby.com",
            NWC_ALLOW_PUBLIC_RELAYS=True,
        )


def test_nwc_relay_allowlist_is_bounded() -> None:
    with pytest.raises(ValidationError, match="NWC_ALLOWED_RELAY_HOSTS is too large"):
        Settings(
            _env_file=None,
            NWC_ALLOWED_RELAY_HOSTS=",".join(f"relay-{index}.example.com" for index in range(33)),
        )


def test_nwc_lease_must_cover_helper_timeout() -> None:
    with pytest.raises(ValidationError, match="NWC_PAYMENT_LEASE_SECONDS"):
        Settings(
            _env_file=None,
            NWC_HELPER_TIMEOUT_SECONDS=20,
            NWC_PAYMENT_LEASE_SECONDS=24,
        )


@pytest.mark.parametrize("product", ["PORT", "RELAY", "RELAY_WILDCARD"])
def test_yearly_price_must_equal_ten_monthly_payments(product: str) -> None:
    with pytest.raises(ValidationError, match=f"{product}_YEARLY_SATS must equal 10 times"):
        Settings(_env_file=None, **{f"{product}_YEARLY_SATS": 12345})


def test_yearly_billing_issuance_defaults_off() -> None:
    assert Settings(_env_file=None, BILLING_YEARLY_ENABLED=False).BILLING_YEARLY_ENABLED is False


def test_email_reminders_default_off() -> None:
    settings = Settings(_env_file=None)

    assert settings.REMINDER_EMAIL_ENABLED is False
    assert settings.ANNOUNCEMENT_EMAIL_ENABLED is False
    assert settings.SMTP_PORT == 587
    assert settings.SMTP_SECURITY == "starttls"
    assert settings.SMTP_TIMEOUT_SECONDS == 10


@pytest.mark.parametrize(
    "value",
    [
        "smtp://mail.example.com",
        "mail.example.com:587",
        "mail.example.com/path",
        " mail.example.com",
    ],
)
def test_smtp_host_must_be_a_hostname_or_ip(value: str) -> None:
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        Settings(_env_file=None, SMTP_HOST=value)


def test_enabled_email_reminders_require_smtp_endpoint() -> None:
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        Settings(
            _env_file=None,
            REMINDER_EMAIL_ENABLED=True,
            PAYMENT_RECONCILIATION_ENABLED=True,
            CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
        )


def test_enabled_service_announcements_require_smtp_endpoint() -> None:
    with pytest.raises(ValidationError, match="SMTP_HOST"):
        Settings(
            _env_file=None,
            ANNOUNCEMENT_EMAIL_ENABLED=True,
            PAYMENT_RECONCILIATION_ENABLED=True,
            CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
        )


def test_smtp_authentication_requires_username_and_password_together() -> None:
    with pytest.raises(ValidationError, match="configured together"):
        Settings(_env_file=None, SMTP_USERNAME="sender")
    with pytest.raises(ValidationError, match="configured together"):
        Settings(_env_file=None, SMTP_PASSWORD="secret")


def test_enabled_reminders_allow_trusted_relay_without_authentication() -> None:
    settings = Settings(
        _env_file=None,
        REMINDER_EMAIL_ENABLED=True,
        PAYMENT_RECONCILIATION_ENABLED=True,
        CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
        SMTP_HOST="mail.internal",
        SMTP_FROM_EMAIL="notices@example.com",
    )
    assert settings.SMTP_USERNAME == settings.SMTP_PASSWORD == ""


def test_smtp_security_and_from_address_are_strict() -> None:
    with pytest.raises(ValidationError, match="SMTP_SECURITY"):
        Settings(_env_file=None, SMTP_SECURITY="plain")
    with pytest.raises(ValidationError, match="SMTP_FROM_EMAIL"):
        Settings(_env_file=None, SMTP_FROM_EMAIL="Blindport <notices@example.com>")


def test_email_reminders_require_reconciliation_worker() -> None:
    with pytest.raises(ValidationError, match="NOTIFICATION_RECONCILIATION_ENABLED"):
        Settings(
            _env_file=None,
            REMINDER_EMAIL_ENABLED=True,
            NOTIFICATION_RECONCILIATION_ENABLED=False,
            CREDENTIAL_ENCRYPTION_KEY="cd" * 32,
            SMTP_HOST="mail.example.com",
            SMTP_FROM_EMAIL="notices@example.com",
        )


def test_reminder_lease_covers_smtp_timeout() -> None:
    with pytest.raises(ValidationError, match="REMINDER_DELIVERY_LEASE_SECONDS"):
        Settings(
            _env_file=None,
            SMTP_TIMEOUT_SECONDS=20,
            REMINDER_DELIVERY_LEASE_SECONDS=24,
        )


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"DATABASE_URL": "sqlite:////data/blindport.db"}, "DATABASE_URL"),
        ({"DATABASE_URL": "postgresql://blindport:secret@db/blindport"}, "DATABASE_URL"),
        ({"DATABASE_MIGRATE_ON_STARTUP": True}, "DATABASE_MIGRATE_ON_STARTUP"),
        ({"PAYMENT_LIGHTNING_ADAPTER": "mock"}, "PAYMENT_LIGHTNING_ADAPTER"),
        ({"PAYMENT_LIGHTNING_ADAPTER": "mock-auto"}, "PAYMENT_LIGHTNING_ADAPTER"),
        ({"PAYMENT_LIGHTNING_ADAPTER": "unknown"}, "PAYMENT_LIGHTNING_ADAPTER"),
        ({"SECRET_KEY": DEFAULT_SECRET_KEY}, "SECRET_KEY"),
        ({"SECRET_KEY": "short-production-secret"}, "SECRET_KEY"),
        ({"TOKEN_HASH_KEY": ""}, "TOKEN_HASH_KEY"),
        ({"TOKEN_HASH_KEY": "short"}, "TOKEN_HASH_KEY"),
        ({"RELAY_SECRET": ""}, "RELAY_SECRET"),
        ({"RELAY_SECRET": "short"}, "RELAY_SECRET"),
        ({"TOKEN_HASH_KEY": "s" * 40}, "must be distinct"),
        ({"RELAY_SECRET": "t" * 40}, "must be distinct"),
        ({"ADMIN_TOKEN": "r" * 40}, "must be distinct"),
        ({"SECRET_KEY": "ab" * 32}, "must be distinct"),
        ({"ADMIN_TOKEN": DEFAULT_ADMIN_TOKEN}, "ADMIN_TOKEN"),
        ({"ADMIN_TOKEN": "SHORTADMIN"}, "ADMIN_TOKEN"),
        ({"DEBUG": True}, "DEBUG"),
        ({"CA_DIR": "data/ca"}, "CA_DIR"),
        ({"LEGACY_CLIENT_CERT_ISSUANCE_ENABLED": True}, "LEGACY_CLIENT_CERT_ISSUANCE_ENABLED"),
        ({"IP_YEARLY_SATS": 0}, "IP_YEARLY_SATS"),
        ({"PORT_MONTHLY_SATS": -1}, "PORT_MONTHLY_SATS"),
        ({"PORT_YEARLY_SATS": -1}, "PORT_YEARLY_SATS"),
        ({"RELAY_MONTHLY_SATS": 0}, "RELAY_MONTHLY_SATS"),
        ({"RELAY_YEARLY_SATS": 0}, "RELAY_YEARLY_SATS"),
        ({"RELAY_WILDCARD_MONTHLY_SATS": 0}, "RELAY_WILDCARD_MONTHLY_SATS"),
        ({"RELAY_WILDCARD_YEARLY_SATS": 0}, "RELAY_WILDCARD_YEARLY_SATS"),
        ({"TOKEN_BYTES": 15}, "TOKEN_BYTES"),
        ({"PAYMENT_ENABLED_METHODS": "cashu"}, "unsupported payment method"),
        ({"PAYMENT_ENABLED_METHODS": "lightning,cashu"}, "unsupported payment method"),
        (
            {"PAYMENT_ENABLED_METHODS": "lightning,nwc", "PAYMENT_NWC_ADAPTER": "mock"},
            "PAYMENT_NWC_ADAPTER",
        ),
        ({"PAYMENT_RECONCILIATION_ENABLED": False}, "PAYMENT_RECONCILIATION_ENABLED"),
        ({"LND_INVOICE_HMAC_KEY": ""}, "LND_INVOICE_HMAC_KEY"),
    ],
)
def test_production_settings_fail_fast(overrides: dict, error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        _production_settings(**overrides)


def test_production_validation_does_not_render_secrets() -> None:
    secret_key = "do-not-render-secret-key-value"
    admin_token = "do-not-render-admin-token-value"
    database_password = "do-not-render-database-password"

    with pytest.raises(ValidationError) as exc_info:
        _production_settings(
            DATABASE_URL=f"sqlite:///{database_password}",
            SECRET_KEY=secret_key,
            ADMIN_TOKEN=admin_token,
        )

    message = str(exc_info.value)
    assert secret_key not in message
    assert admin_token not in message
    assert database_password not in message


@pytest.mark.parametrize(
    "field,address",
    [
        ("RELAY_PUBLIC_IPS", "10.0.0.1"),
        ("RELAY_PUBLIC_IPS", "192.0.2.10"),
        ("RELAY_PUBLIC_IPS", "127.0.0.1"),
        ("RELAY_SHARED_IPS", "169.254.10.1"),
        ("RELAY_SHARED_IPS", "224.0.0.1"),
        ("RELAY_SHARED_IPS", "2001:db8::10"),
        ("RELAY_SHARED_IPS", "fe80::1"),
        ("RELAY_SHARED_IPS", "ff02::1"),
    ],
)
def test_production_rejects_non_global_listener_inventory(field: str, address: str) -> None:
    with pytest.raises(ValidationError, match=field):
        _production_settings(**{field: address})


def test_production_rejects_non_global_wireguard_inventory() -> None:
    public_key = base64.b64encode(bytes(range(1, 33))).decode()
    with pytest.raises(ValidationError, match="WIREGUARD_PUBLIC_IPS"):
        _production_settings(
            WIREGUARD_PUBLIC_IPS="198.51.100.20",
            WIREGUARD_RELAY_PUBLIC_KEY=public_key,
            WIREGUARD_ENDPOINT="wireguard.blindport.com:51820",
        )


def test_production_rejects_development_wireguard_endpoint() -> None:
    public_key = base64.b64encode(bytes(range(1, 33))).decode()
    with pytest.raises(ValidationError, match="WIREGUARD_ENDPOINT"):
        _production_settings(
            WIREGUARD_PUBLIC_IPS="9.9.9.9",
            WIREGUARD_RELAY_PUBLIC_KEY=public_key,
            WIREGUARD_ENDPOINT="wireguard.test:51820",
        )


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"RELAY_CONTROL_URL": "relay:5443"}, "RELAY_CONTROL_URL"),
        ({"RELAY_CONTROL_URL": "relay.test:5443"}, "RELAY_CONTROL_URL"),
        ({"RELAY_CONTROL_URL": "localhost:5443"}, "RELAY_CONTROL_URL"),
        ({"RELAY_CONTROL_URL": "edge.local:5443"}, "RELAY_CONTROL_URL"),
        ({"RELAY_CONTROL_URL": "127.0.0.1:5443"}, "RELAY_CONTROL_URL"),
        ({"RELAY_CONTROL_URLS": "edge.test:5443"}, "RELAY_CONTROL_URLS"),
        ({"RELAY_POOL_DOMAINS": "pool.localhost"}, "RELAY_POOL_DOMAINS"),
        ({"RELAY_POOL_DOMAINS": "pool.test"}, "RELAY_POOL_DOMAINS"),
        ({"RELAY_POOL_DOMAINS": "relay"}, "RELAY_POOL_DOMAINS"),
        ({"RELAY_MANAGED_SUFFIXES": "relay.test"}, "RELAY_MANAGED_SUFFIXES"),
        ({"RELAY_MANAGED_SUFFIXES": "relay.local"}, "RELAY_MANAGED_SUFFIXES"),
    ],
)
def test_production_rejects_development_relay_names(overrides: dict[str, str], error: str) -> None:
    with pytest.raises(ValidationError, match=error):
        _production_settings(**overrides)


def test_production_allows_empty_public_inventory_and_private_lnd_hostname() -> None:
    settings = _production_settings(
        RELAY_PUBLIC_IPS="",
        RELAY_SHARED_IPS="",
        WIREGUARD_PUBLIC_IPS="",
        RELAY_POOL_DOMAINS="",
        RELAY_MANAGED_SUFFIXES="",
        LND_REST_URL="https://lnd.internal:8080",
    )

    assert settings.relay_public_ips_list == []
    assert settings.relay_shared_ips_list == []
    assert settings.relay_pool_domains_list == []
    assert settings.LND_REST_URL == "https://lnd.internal:8080"


def test_development_relay_defaults_remain_allowed() -> None:
    settings = Settings(
        _env_file=None,
        ENVIRONMENT="development",
        RELAY_CONTROL_URL="relay:5443",
        RELAY_PUBLIC_IPS="203.0.113.10",
        RELAY_SHARED_IPS="203.0.113.20",
        RELAY_POOL_DOMAINS="relay1.blindport.test",
        RELAY_MANAGED_SUFFIXES="relay.test",
    )

    assert settings.RELAY_CONTROL_URL == "relay:5443"
    assert settings.relay_public_ips_list == ["203.0.113.10"]


@pytest.mark.parametrize(
    "value",
    [
        "pool1.blindport.com, pool2.blindport.com",
        "pool1.blindport.com,",
        "pool1.blindport.com,,pool2.blindport.com",
        "bad_.blindport.com",
        "127.0.0.1",
        "Pool1.Blindport.Com,pool1.blindport.com",
    ],
)
def test_relay_pool_domains_reject_malformed_lists(value: str) -> None:
    with pytest.raises((ValueError, ValidationError)):
        parse_relay_pool_domains(value)


def test_relay_pool_domain_leaves_room_for_generated_cname_label() -> None:
    valid = f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 28}"
    too_long = f"{'a' * 63}.{'b' * 63}.{'c' * 63}.{'d' * 29}"

    assert len(valid) == 220
    assert parse_relay_pool_domains(valid) == [valid]
    with pytest.raises(ValueError, match="32-character child label"):
        parse_relay_pool_domains(too_long)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("Relay.Example:5443", "relay.example:5443"),
        ("203.0.113.10:443", "203.0.113.10:443"),
        ("[2001:0db8::1]:443", "[2001:db8::1]:443"),
    ],
)
def test_canonicalize_relay_endpoint(value: str, expected: str) -> None:
    assert canonicalize_relay_endpoint(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://relay.example:5443",
        "relay.example",
        "relay.example:0",
        "relay.example:65536",
        "relay.example:05443",
        "relay.example:abc",
        " relay.example:5443",
        "relay.example:5443/path",
        "2001:db8::1:443",
        "[fe80::1%eth0]:443",
        "[relay.example]:443",
    ],
)
def test_relay_endpoint_rejects_noncanonical_or_invalid_values(value: str) -> None:
    with pytest.raises(ValueError):
        canonicalize_relay_endpoint(value)


def test_relay_control_urls_are_canonical_and_unique() -> None:
    settings = Settings(
        _env_file=None,
        RELAY_CONTROL_URL="primary.example:5443",
        RELAY_CONTROL_URLS=("Relay-A.Example:5443,[2001:0db8::1]:5443,relay-a.example:5443"),
    )
    assert settings.RELAY_CONTROL_URLS == "relay-a.example:5443,[2001:db8::1]:5443"
    assert settings.relay_control_urls_list == [
        "relay-a.example:5443",
        "[2001:db8::1]:5443",
    ]


def test_relay_control_urls_fall_back_to_primary() -> None:
    settings = Settings(_env_file=None, RELAY_CONTROL_URL="primary.example:5443")
    assert settings.relay_control_urls_list == ["primary.example:5443"]


def test_port_ha_edges_are_canonical_and_bound_to_primary_inventory() -> None:
    settings = Settings(
        _env_file=None,
        RELAY_CONTROL_URL="primary.example:5443",
        RELAY_CONTROL_URLS="primary.example:5443,secondary.example:5443",
        RELAY_SHARED_IPS="203.0.113.20",
        PORT_HOSTNAME_SUFFIX="Ports.Example.",
        PORT_HA_EDGES=(
            '[{"endpoint":"Primary.Example:5443","ip":"203.0.113.20"},'
            '{"endpoint":"secondary.example:5443","ip":"203.0.113.21"}]'
        ),
    )

    assert settings.PORT_HOSTNAME_SUFFIX == "ports.example"
    assert settings.port_ha_edges_list == parse_port_ha_edges(settings.PORT_HA_EDGES)
    assert [edge.ip for edge in settings.port_ha_edges_list] == [
        "203.0.113.20",
        "203.0.113.21",
    ]


def test_port_hostname_suffix_must_leave_room_for_subscription_id() -> None:
    suffix = ".".join(["a" * 63, "b" * 63, "c" * 63, "d" * 24])
    assert len(suffix) == 216

    with pytest.raises(ValidationError, match="UUID child label"):
        Settings(_env_file=None, PORT_HOSTNAME_SUFFIX=f"x.{suffix}")


def test_production_port_hostname_suffix_must_be_public() -> None:
    with pytest.raises(ValidationError, match="PORT_HOSTNAME_SUFFIX"):
        _production_settings(
            RELAY_CONTROL_URLS="relay.blindport.com:5443,relay-b.blindport.com:5443",
            PORT_HA_EDGES=(
                '[{"endpoint":"relay.blindport.com:5443","ip":"1.1.1.1"},'
                '{"endpoint":"relay-b.blindport.com:5443","ip":"9.9.9.9"}]'
            ),
            PORT_HOSTNAME_SUFFIX="ports.localhost",
        )


@pytest.mark.parametrize(
    "edges,suffix,match",
    [
        (
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"}]',
            "ports.example",
            "at least two",
        ),
        (
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.21"},'
            '{"endpoint":"secondary.example:5443","ip":"203.0.113.22"}]',
            "ports.example",
            "map RELAY_CONTROL_URL",
        ),
        (
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"},'
            '{"endpoint":"missing.example:5443","ip":"203.0.113.21"}]',
            "ports.example",
            "RELAY_CONTROL_URLS",
        ),
        (
            '[{"endpoint":"primary.example:5443","ip":"203.0.113.20"},'
            '{"endpoint":"secondary.example:5443","ip":"203.0.113.21"}]',
            "",
            "PORT_HOSTNAME_SUFFIX",
        ),
    ],
)
def test_port_ha_edges_reject_incomplete_topologies(edges: str, suffix: str, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        Settings(
            _env_file=None,
            RELAY_CONTROL_URL="primary.example:5443",
            RELAY_CONTROL_URLS="primary.example:5443,secondary.example:5443",
            RELAY_SHARED_IPS="203.0.113.20",
            PORT_HA_EDGES=edges,
            PORT_HOSTNAME_SUFFIX=suffix,
        )


def test_framed_ip_endpoints_must_cover_inventory() -> None:
    raw = '{"203.0.113.10":"Edge.Example:5443","203.0.113.11":"edge.example:5443"}'
    settings = Settings(
        _env_file=None,
        RELAY_PUBLIC_IPS="203.0.113.10,203.0.113.11",
        RELAY_CONTROL_URLS="edge.example:5443",
        FRAMED_IP_ENDPOINTS=raw,
    )
    assert settings.framed_ip_endpoints_map == parse_framed_ip_endpoints(raw)

    with pytest.raises(ValidationError, match="map every"):
        Settings(
            _env_file=None,
            RELAY_PUBLIC_IPS="203.0.113.10,203.0.113.11",
            RELAY_CONTROL_URLS="edge.example:5443",
            FRAMED_IP_ENDPOINTS='{"203.0.113.10":"edge.example:5443"}',
        )


@pytest.mark.parametrize(
    "value",
    [
        "relay-a.example:5443,",
        "relay-a.example:5443, relay-b.example:5443",
    ],
)
def test_relay_control_urls_reject_invalid_lists(value: str) -> None:
    with pytest.raises((ValueError, ValidationError)):
        parse_relay_endpoints(value)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1-1", [1]),
        ("10000-10007", list(range(10000, 10008))),
        ("65535-65535", [65535]),
    ],
)
def test_parse_tcp_port_pool(value: str, expected: list[int]) -> None:
    assert parse_tcp_port_pool(value) == expected
    assert parse_udp_port_pool(value) == expected


@pytest.mark.parametrize(
    "value",
    ["", "80", "80,81", "0-80", "100-99", "1-65536", " 80-81", "a-b", "1-4097"],
)
def test_parse_tcp_port_pool_rejects_invalid_or_excessive_ranges(value: str) -> None:
    with pytest.raises(ValueError):
        parse_tcp_port_pool(value)


def test_settings_reject_overlapping_dedicated_and_shared_inventory() -> None:
    with pytest.raises(ValidationError, match="must be disjoint"):
        Settings(
            _env_file=None,
            RELAY_PUBLIC_IPS="203.0.113.10,203.0.113.11",
            RELAY_SHARED_IPS="203.0.113.11",
        )


def test_wireguard_inventory_requires_complete_disjoint_configuration() -> None:
    public_key = base64.b64encode(bytes(range(1, 33))).decode()
    settings = Settings(
        _env_file=None,
        WIREGUARD_PUBLIC_IPS="198.51.100.20",
        WIREGUARD_RELAY_PUBLIC_KEY=public_key,
        WIREGUARD_ENDPOINT="wg.example:51820",
    )
    assert settings.wireguard_enabled
    assert settings.wireguard_public_ips_list == ["198.51.100.20"]
    assert settings.WIREGUARD_ENDPOINT == "wg.example:51820"

    with pytest.raises(ValidationError, match="required"):
        Settings(_env_file=None, WIREGUARD_PUBLIC_IPS="198.51.100.20")
    with pytest.raises(ValidationError, match="disjoint"):
        Settings(
            _env_file=None,
            WIREGUARD_PUBLIC_IPS="203.0.113.10",
            WIREGUARD_RELAY_PUBLIC_KEY=public_key,
            WIREGUARD_ENDPOINT="wg.example:51820",
        )


@pytest.mark.parametrize("value", ["invalid", base64.b64encode(bytes(32)).decode()])
def test_wireguard_relay_key_is_canonical_and_nonzero(value: str) -> None:
    with pytest.raises(ValidationError, match="WIREGUARD_RELAY_PUBLIC_KEY"):
        Settings(_env_file=None, WIREGUARD_RELAY_PUBLIC_KEY=value)


def test_wireguard_reconciliation_must_fit_ip_quarantine() -> None:
    public_key = base64.b64encode(bytes(range(1, 33))).decode()
    with pytest.raises(ValidationError, match="IP_REUSE_QUARANTINE_SECONDS"):
        Settings(
            _env_file=None,
            WIREGUARD_PUBLIC_IPS="198.51.100.20",
            WIREGUARD_RELAY_PUBLIC_KEY=public_key,
            WIREGUARD_ENDPOINT="wg.example:51820",
            WIREGUARD_RECONCILE_INTERVAL_SECONDS=300,
            WIREGUARD_RECONCILE_MAX_STALENESS_SECONDS=3300,
            IP_REUSE_QUARANTINE_SECONDS=3600,
        )


@pytest.mark.parametrize("value", [0, -1])
def test_wireguard_smtp_egress_fee_must_be_positive(value: int) -> None:
    with pytest.raises(ValidationError, match="WIREGUARD_SMTP_EGRESS_FEE_SATS"):
        Settings(_env_file=None, WIREGUARD_SMTP_EGRESS_FEE_SATS=value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("RELAY_PUBLIC_IPS", "not-an-ip"),
        ("RELAY_SHARED_IPS", "203.0.113.20,"),
        ("RELAY_SHARED_IPS", "203.0.113.20,203.0.113.20"),
        ("RELAY_SHARED_TCP_PORTS", "10000,10001"),
        ("RELAY_SHARED_UDP_PORTS", "10000,10001"),
    ],
)
def test_settings_reject_invalid_inventory(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize("seconds", [0, 59, 7776001])
def test_settings_bound_resource_reuse_quarantine(seconds: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, RESOURCE_REUSE_QUARANTINE_SECONDS=seconds)


def test_offline_entitlement_quarantine_supports_seven_day_grace_only_when_enabled() -> None:
    assert Settings(_env_file=None).RESOURCE_REUSE_QUARANTINE_SECONDS == 180
    assert Settings(_env_file=None, RESOURCE_REUSE_QUARANTINE_SECONDS=604921)


def test_offline_entitlement_quarantine_and_relay_hold_must_strictly_exceed_grace() -> None:
    common = {
        "OFFLINE_ENTITLEMENTS_ENABLED": True,
        "OFFLINE_ENTITLEMENT_KEY_ID": "offline-a",
        "OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE": "/tmp/offline-key.pem",
        "RELAY_EDGES": '[{"id":"edge-a","endpoint":"relay:5443"}]',
        "RELAY_HEARTBEAT_KEYS": '{"edge-a":"' + "a" * 64 + '"}',
    }
    with pytest.raises(ValidationError, match="RESOURCE_REUSE_QUARANTINE_SECONDS"):
        Settings(_env_file=None, **common, RESOURCE_REUSE_QUARANTINE_SECONDS=604920)
    with pytest.raises(ValidationError, match="RELAY_RENEWAL_GRACE_SECONDS"):
        Settings(
            _env_file=None,
            **common,
            RESOURCE_REUSE_QUARANTINE_SECONDS=604921,
            RELAY_RENEWAL_GRACE_SECONDS=604920,
        )


def test_relay_edges_are_canonicalized_and_unique() -> None:
    parsed = parse_relay_edges('[{"id":"edge-a","endpoint":"Relay.Example:5443"}]')
    assert [(edge.id, edge.endpoint) for edge in parsed] == [("edge-a", "relay.example:5443")]
    with pytest.raises(ValueError, match="duplicate"):
        parse_relay_edges(
            '[{"id":"edge-a","endpoint":"relay.example:5443"},'
            '{"id":"edge-b","endpoint":"Relay.Example:5443"}]'
        )


def test_relay_heartbeat_keys_are_canonical_unique_and_match_edges() -> None:
    token_a = "a" * 64
    token_b = "b" * 64
    keys = f'{{"edge-a":"{token_a}","edge-b":"{token_b}"}}'
    settings = Settings(
        _env_file=None,
        RELAY_EDGES=(
            '[{"id":"edge-a","endpoint":"relay-a:5443"},{"id":"edge-b","endpoint":"relay-b:5443"}]'
        ),
        RELAY_HEARTBEAT_KEYS=keys,
    )

    assert settings.relay_heartbeat_keys == {"edge-a": token_a, "edge-b": token_b}
    assert parse_relay_heartbeat_keys(keys) == settings.relay_heartbeat_keys
    with pytest.raises(ValidationError, match="must be empty when RELAY_EDGES is empty"):
        Settings(_env_file=None, RELAY_HEARTBEAT_KEYS="{}")
    with pytest.raises(ValidationError, match="canonical JSON"):
        Settings(
            _env_file=None,
            RELAY_EDGES='[{"id":"edge-a","endpoint":"relay-a:5443"}]',
            RELAY_HEARTBEAT_KEYS=f'{{ "edge-a":"{token_a}"}}',
        )
    with pytest.raises(ValidationError, match="match configured RELAY_EDGES exactly"):
        Settings(
            _env_file=None,
            RELAY_EDGES='[{"id":"edge-a","endpoint":"relay-a:5443"}]',
            RELAY_HEARTBEAT_KEYS=f'{{"edge-b":"{token_b}"}}',
        )
    with pytest.raises(ValidationError, match="tokens must be unique"):
        Settings(
            _env_file=None,
            RELAY_EDGES=(
                '[{"id":"edge-a","endpoint":"relay-a:5443"},'
                '{"id":"edge-b","endpoint":"relay-b:5443"}]'
            ),
            RELAY_HEARTBEAT_KEYS=f'{{"edge-a":"{token_a}","edge-b":"{token_a}"}}',
        )


@pytest.mark.parametrize("key_id", ["", "UPPER", "has space", "x" * 33])
def test_enabled_offline_entitlements_require_a_stable_key_id(key_id: str) -> None:
    with pytest.raises(ValidationError, match="OFFLINE_ENTITLEMENT_KEY_ID"):
        Settings(
            _env_file=None,
            OFFLINE_ENTITLEMENTS_ENABLED=True,
            OFFLINE_ENTITLEMENT_KEY_ID=key_id,
            OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE="/tmp/offline.pem",
            RELAY_EDGES='[{"id":"edge-a","endpoint":"relay:5443"}]',
            RELAY_HEARTBEAT_KEYS='{"edge-a":"' + "a" * 64 + '"}',
            RESOURCE_REUSE_QUARANTINE_SECONDS=604921,
            RELAY_RENEWAL_GRACE_SECONDS=604921,
        )


def test_production_offline_entitlement_key_path_must_be_absolute() -> None:
    with pytest.raises(
        ValidationError, match="OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE must be absolute"
    ):
        _production_settings(
            OFFLINE_ENTITLEMENTS_ENABLED=True,
            OFFLINE_ENTITLEMENT_KEY_ID="offline-a",
            OFFLINE_ENTITLEMENT_PRIVATE_KEY_FILE="offline.pem",
            RELAY_EDGES='[{"id":"edge-a","endpoint":"relay.blindport.com:5443"}]',
            RELAY_HEARTBEAT_KEYS='{"edge-a":"' + "a" * 64 + '"}',
            RESOURCE_REUSE_QUARANTINE_SECONDS=604921,
            RELAY_RENEWAL_GRACE_SECONDS=604921,
        )


def test_managed_suffixes_are_strictly_canonicalized() -> None:
    assert parse_managed_suffixes("BÜCHER.Example.,relay.test") == [
        "xn--bcher-kva.example",
        "relay.test",
    ]
    settings = Settings(_env_file=None, RELAY_MANAGED_SUFFIXES="BÜCHER.Example.")
    assert settings.RELAY_MANAGED_SUFFIXES == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "value",
    [" relay.test", "relay.test ", "relay.test,", "relay.test,,example.test", "127.0.0.1"],
)
def test_managed_suffixes_reject_invalid_lists(value: str) -> None:
    with pytest.raises((ValueError, ValidationError)):
        parse_managed_suffixes(value)


def test_managed_suffixes_reject_canonical_duplicates() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        parse_managed_suffixes("BÜCHER.example,xn--bcher-kva.example")


@pytest.mark.parametrize(
    "field,seconds",
    [
        ("RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS", 59),
        ("RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS", 86401),
        ("RELAY_DOMAIN_CLAIM_TTL_SECONDS", 59),
        ("RELAY_DOMAIN_CLAIM_TTL_SECONDS", 86401),
    ],
)
def test_settings_bound_relay_domain_claim_ttl(field: str, seconds: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: seconds})


def test_relay_claim_defaults_limit_unpaid_name_holds(monkeypatch) -> None:
    monkeypatch.delenv("ACCOUNT_MAX_PENDING_RELAY_CLAIMS", raising=False)
    settings = Settings(_env_file=None)

    assert settings.ACCOUNT_MAX_PENDING_RELAY_CLAIMS == 2
    assert settings.RELAY_MANAGED_DOMAIN_CLAIM_TTL_SECONDS == 1800
    assert settings.RELAY_DOMAIN_CLAIM_TTL_SECONDS == 3600


def test_relay_renewal_grace_defaults_to_seven_days() -> None:
    settings = Settings(_env_file=None)
    assert settings.RELAY_RENEWAL_GRACE_SECONDS == 7 * 24 * 60 * 60


@pytest.mark.parametrize("seconds", [0, 135, 2592001])
def test_settings_bound_relay_renewal_grace(seconds: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, RELAY_RENEWAL_GRACE_SECONDS=seconds)


def test_relay_renewal_grace_accepts_relay_handoff_minimum() -> None:
    settings = Settings(
        _env_file=None,
        RELAY_RENEWAL_GRACE_SECONDS=RELAY_RENEWAL_GRACE_MIN_SECONDS,
    )
    assert settings.RELAY_RENEWAL_GRACE_SECONDS == 90 + 45 + 1


@pytest.mark.parametrize(
    "field,value,min_payable,safety",
    [
        ("RELAY_DOMAIN_CLAIM_TTL_SECONDS", 60, 55, 5),
        ("RELAY_RENEWAL_GRACE_SECONDS", 136, 121, 15),
        ("RESOURCE_RESERVATION_TTL_SECONDS", 60, 55, 5),
    ],
)
def test_payment_window_and_safety_interval_must_fit_eligibility(
    field: str,
    value: int,
    min_payable: int,
    safety: int,
) -> None:
    with pytest.raises(ValidationError, match="minimum payable window"):
        Settings(
            _env_file=None,
            PAYMENT_MIN_PAYABLE_SECONDS=min_payable,
            PAYMENT_EXPIRY_SAFETY_SECONDS=safety,
            **{field: value},
        )


def test_lnd_timeout_must_fit_payment_expiry_safety_interval() -> None:
    with pytest.raises(ValidationError, match="LND_REQUEST_TIMEOUT_SECONDS"):
        Settings(
            _env_file=None,
            PAYMENT_LIGHTNING_ADAPTER="lnd",
            LND_REQUEST_TIMEOUT_SECONDS=16,
            PAYMENT_EXPIRY_SAFETY_SECONDS=15,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("PAYMENT_RECONCILIATION_INTERVAL_SECONDS", 0),
        ("PAYMENT_RECONCILIATION_INTERVAL_SECONDS", 301),
        ("PAYMENT_RECONCILIATION_BATCH_SIZE", 0),
        ("PAYMENT_RECONCILIATION_BATCH_SIZE", 1001),
        ("PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS", 0),
        ("PAYMENT_RECONCILIATION_STARTUP_GRACE_SECONDS", 601),
        ("PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS", 0),
        ("PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS", 3601),
    ],
)
def test_payment_reconciliation_settings_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_payment_reconciliation_staleness_covers_two_intervals() -> None:
    with pytest.raises(ValidationError, match="at least twice"):
        Settings(
            _env_file=None,
            PAYMENT_RECONCILIATION_INTERVAL_SECONDS=10,
            PAYMENT_RECONCILIATION_STALE_AFTER_SECONDS=19,
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("RATE_LIMIT_SIGNUP_REQUESTS", 0),
        ("RATE_LIMIT_ADMIN_LOGIN_REQUESTS", 1001),
        ("RATE_LIMIT_PAYMENT_CREATE_REQUESTS", 10001),
        ("RATE_LIMIT_DOMAIN_VERIFY_WINDOW_SECONDS", 0),
        ("RATE_LIMIT_CLIENT_CERT_WINDOW_SECONDS", 3601),
        ("RATE_LIMIT_CLEANUP_INTERVAL_SECONDS", 0),
        ("RATE_LIMIT_CLEANUP_BATCH_SIZE", 9),
        ("RATE_LIMIT_MAX_BUCKETS", 999),
    ],
)
def test_rate_limit_settings_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_rate_limit_retention_covers_all_windows() -> None:
    with pytest.raises(ValidationError, match="must cover every rate-limit window"):
        Settings(
            _env_file=None,
            RATE_LIMIT_BUCKET_RETENTION_SECONDS=60,
            RATE_LIMIT_ADMIN_LOGIN_WINDOW_SECONDS=61,
        )


def test_bandwidth_metric_settings_have_conservative_validated_defaults() -> None:
    settings = Settings(_env_file=None)
    assert settings.BANDWIDTH_METRICS_ENABLED is False
    assert settings.BANDWIDTH_RETENTION_DAYS == 400
    assert settings.BANDWIDTH_INGEST_MAX_AGE_DAYS == 3
    assert settings.BANDWIDTH_CLEANUP_INTERVAL_SECONDS == 3600
    assert settings.BANDWIDTH_CLEANUP_BATCH_SIZE == 1000


@pytest.mark.parametrize(
    "field,value",
    [
        ("BANDWIDTH_RETENTION_DAYS", 0),
        ("BANDWIDTH_RETENTION_DAYS", 3661),
        ("BANDWIDTH_INGEST_MAX_AGE_DAYS", -1),
        ("BANDWIDTH_INGEST_MAX_AGE_DAYS", 31),
        ("BANDWIDTH_CLEANUP_INTERVAL_SECONDS", 59),
        ("BANDWIDTH_CLEANUP_INTERVAL_SECONDS", 86401),
        ("BANDWIDTH_CLEANUP_BATCH_SIZE", 0),
        ("BANDWIDTH_CLEANUP_BATCH_SIZE", 10001),
    ],
)
def test_bandwidth_metric_settings_are_bounded(field: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


@pytest.mark.parametrize("seconds", [0, 31])
def test_settings_bound_relay_dns_timeout(seconds: float) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, RELAY_DNS_TIMEOUT_SECONDS=seconds)
