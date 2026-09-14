"""Test fixtures: spin up a fresh in-memory FastAPI app per test."""

from __future__ import annotations

import os
import re

import pytest

# Set test env BEFORE importing the app so config picks it up.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("SECRET_KEY", "test-secret")
os.environ.setdefault("ADMIN_TOKEN", "TESTADMIN0000")
os.environ.setdefault("PAYMENT_LIGHTNING_ADAPTER", "mock")
os.environ.setdefault("PAYMENT_NWC_ADAPTER", "mock")
os.environ.setdefault("PAYMENT_CLINK_ADAPTER", "mock")
os.environ.setdefault("PAYMENT_ENABLED_METHODS", "lightning,nwc,clink,stablecoin_swap")
os.environ.setdefault("CREDENTIAL_ENCRYPTION_KEY", "cd" * 32)
os.environ.setdefault("PAYMENT_RECONCILIATION_ENABLED", "false")
os.environ.setdefault("BILLING_YEARLY_ENABLED", "true")
os.environ.setdefault("BTC_USD_PRICE_ENABLED", "false")
os.environ.setdefault("RELAY_PUBLIC_IPS", "203.0.113.10,203.0.113.11")
os.environ.setdefault("RELAY_SHARED_IPS", "203.0.113.20")
os.environ.setdefault("RELAY_SHARED_TCP_PORTS", "10000-10001")
os.environ.setdefault("RELAY_SHARED_UDP_PORTS", "10000-10001")
os.environ.setdefault("RELAY_POOL_DOMAINS", "relay1.test,relay2.test")
os.environ.setdefault("RELAY_MANAGED_SUFFIXES", "relay.test")


@pytest.fixture
def customer_login():
    """Submit the browser login form with its browser-bound CSRF token."""

    def submit(client, token: str, *, follow_redirects: bool = True, origin: str = ""):
        page = client.get(f"{origin}/dashboard")
        match = re.search(
            r'name="login_csrf_token" value="([A-Za-z0-9_-]+)"',
            page.text,
        )
        assert match is not None, page.text
        return client.post(
            f"{origin}/login",
            data={"token": token, "login_csrf_token": match.group(1)},
            follow_redirects=follow_redirects,
        )

    return submit


@pytest.fixture
def app_client(monkeypatch, tmp_path):
    # Each test gets its own SQLite file (so state is isolated).
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    monkeypatch.setenv(
        "WIREGUARD_PUBLIC_IPS",
        "198.51.100.20,198.51.100.21,198.51.100.22,198.51.100.23,"
        "198.51.100.24,198.51.100.25,198.51.100.26,198.51.100.27",
    )
    monkeypatch.setenv(
        "WIREGUARD_RELAY_PUBLIC_KEY",
        "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
    )
    monkeypatch.setenv("WIREGUARD_ENDPOINT", "relay.test:51820")
    # And its own CA dir so we don't leak issued certs between tests.
    monkeypatch.setenv("CA_DIR", str(tmp_path / "ca"))

    # Re-import to pick up env.
    import importlib

    from blindport import config as config_mod
    from blindport import db as db_mod
    from blindport.adapters import factory as factory_mod
    from blindport.api import internal as internal_mod
    from blindport.api import pages as pages_mod
    from blindport.api import v1 as v1_mod
    from blindport.api import v2 as v2_mod
    from blindport.api import v3 as v3_mod
    from blindport.core import ca as ca_mod
    from blindport.services import agent_orders as agent_orders_mod
    from blindport.services import bandwidth as bandwidth_mod
    from blindport.services import btc_usd_price as btc_usd_price_mod
    from blindport.services import catalog as catalog_mod
    from blindport.services import client_enrollment as client_enrollment_mod
    from blindport.services import domain_verification as domain_verification_mod
    from blindport.services import health as health_mod
    from blindport.services import payment_reconciliation as payment_reconciliation_mod
    from blindport.services import payments as payments_mod
    from blindport.services import rate_limits as rate_limits_mod
    from blindport.services import relay_routing as relay_routing_mod
    from blindport.services import reminder_reconciliation as reminder_reconciliation_mod
    from blindport.services import subscriptions as subs_mod

    importlib.reload(config_mod)
    importlib.reload(db_mod)
    importlib.reload(ca_mod)
    importlib.reload(factory_mod)
    importlib.reload(client_enrollment_mod)
    importlib.reload(domain_verification_mod)
    importlib.reload(catalog_mod)
    importlib.reload(subs_mod)
    importlib.reload(relay_routing_mod)
    importlib.reload(bandwidth_mod)
    importlib.reload(btc_usd_price_mod)
    importlib.reload(payments_mod)
    importlib.reload(agent_orders_mod)
    importlib.reload(rate_limits_mod)
    importlib.reload(payment_reconciliation_mod)
    importlib.reload(health_mod)
    importlib.reload(v1_mod)
    importlib.reload(v2_mod)
    importlib.reload(v3_mod)
    importlib.reload(internal_mod)
    importlib.reload(pages_mod)
    factory_mod.reset_adapters_for_tests()
    reminder_reconciliation_mod.reset_reminder_adapters_for_tests()

    from blindport import main as main_mod

    importlib.reload(main_mod)
    from fastapi.testclient import TestClient

    with TestClient(main_mod.app) as client:
        yield client, factory_mod
