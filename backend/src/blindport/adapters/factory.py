"""Adapter factory: chooses concrete implementations based on settings."""

from __future__ import annotations

from functools import lru_cache

from ..config import settings
from .base import CashuAdapter, LightningAdapter, NwcAdapter
from .cashu_real import RealCashuAdapter
from .lnd_rest import LndRestLightningAdapter
from .mock import MockCashuAdapter, MockLightningAdapter, MockNwcAdapter
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
def get_cashu_adapter() -> CashuAdapter:
    name = settings.PAYMENT_CASHU_ADAPTER.lower()
    if name == "mock":
        return MockCashuAdapter()
    if name == "cashu":
        mints = settings.cashu_mints_list
        if not mints:
            raise ValueError("PAYMENT_CASHU_ADAPTER=cashu requires CASHU_MINTS to be set")
        return RealCashuAdapter(mint_urls=mints)
    raise ValueError(f"unknown cashu adapter: {name!r}")


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
        )
    raise ValueError(f"unknown nwc adapter: {name!r}")


def reset_adapters_for_tests() -> None:
    """Clear the lru_cache so a fresh adapter is built (test-only)."""
    get_lightning_adapter.cache_clear()
    get_cashu_adapter.cache_clear()
    get_nwc_adapter.cache_clear()
