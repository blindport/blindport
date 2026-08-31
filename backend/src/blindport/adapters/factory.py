"""Adapter factory: chooses concrete implementations based on settings."""

from __future__ import annotations

from functools import lru_cache

from ..config import settings
from .base import ClinkAdapter, LightningAdapter, NwcAdapter
from .clink import SubprocessClinkAdapter
from .lnd_rest import LndRestLightningAdapter
from .mock import MockClinkAdapter, MockLightningAdapter, MockNwcAdapter
from .nwc import SubprocessNwcAdapter


@lru_cache(maxsize=1)
def get_lightning_adapter() -> LightningAdapter:
    name = settings.PAYMENT_LIGHTNING_ADAPTER.lower()
    if name == "mock":
        # In dev/test, never auto-settle: the test triggers settlement explicitly.
        return MockLightningAdapter(auto_settle=False)
    if name == "mock-auto":
        # E2E variant: every invoice is paid the moment it is created.
        return MockLightningAdapter(auto_settle=True)
    if name == "lnd":
        invoice_expiry_ceiling = settings.LND_INVOICE_EXPIRY_SECONDS
        if settings.STABLECOIN_PAYMENTS_ENABLED:
            invoice_expiry_ceiling = max(
                invoice_expiry_ceiling,
                settings.STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS,
            )
        return LndRestLightningAdapter(
            rest_url=settings.LND_REST_URL,
            cert_path=settings.LND_CERT_PATH,
            macaroon_path=settings.LND_MACAROON_PATH,
            invoice_expiry_seconds=invoice_expiry_ceiling,
            request_timeout_seconds=settings.LND_REQUEST_TIMEOUT_SECONDS,
        )
    raise ValueError(f"unknown lightning adapter: {name!r}")


@lru_cache(maxsize=1)
def get_nwc_adapter() -> NwcAdapter:
    name = settings.PAYMENT_NWC_ADAPTER.lower()
    if name == "mock":
        return MockNwcAdapter(auto_settle=False, settle_callback=get_lightning_adapter().mark_paid)
    if name == "mock-auto":
        return MockNwcAdapter(auto_settle=True, settle_callback=get_lightning_adapter().mark_paid)
    if name == "nwc":
        return SubprocessNwcAdapter(
            settings.NWC_HELPER_PATH,
            settings.NWC_HELPER_TIMEOUT_SECONDS,
            settings.nwc_allowed_relay_hosts,
            allow_public_relays=settings.NWC_ALLOW_PUBLIC_RELAYS,
            allow_legacy_nip04=settings.NWC_ALLOW_LEGACY_NIP04,
        )
    raise ValueError(f"unknown nwc adapter: {name!r}")


@lru_cache(maxsize=1)
def get_clink_adapter() -> ClinkAdapter:
    name = settings.PAYMENT_CLINK_ADAPTER.lower()
    if name == "mock":
        return MockClinkAdapter(
            auto_settle=False, settle_callback=get_lightning_adapter().mark_paid
        )
    if name == "mock-auto":
        return MockClinkAdapter(auto_settle=True, settle_callback=get_lightning_adapter().mark_paid)
    if name == "clink":
        return SubprocessClinkAdapter(
            settings.CLINK_HELPER_PATH,
            settings.CLINK_HELPER_TIMEOUT_SECONDS,
            settings.CLINK_REQUEST_TIMEOUT_SECONDS,
            settings.CLINK_NOSTR_PRIVATE_KEY,
            settings.clink_allowed_relay_hosts,
            allow_public_relays=settings.CLINK_ALLOW_PUBLIC_RELAYS,
        )
    raise ValueError(f"unknown CLINK adapter: {name!r}")


def reset_adapters_for_tests() -> None:
    """Clear the lru_cache so a fresh adapter is built (test-only)."""
    get_lightning_adapter.cache_clear()
    get_nwc_adapter.cache_clear()
    get_clink_adapter.cache_clear()
