"""Capacity limits for shared TCP and UDP Blindport Port inventory."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlmodel import Session

from blindport.config import Settings
from blindport.core.models import ProductType, Subscription, Transport, User
from blindport.services.allocator import NoCapacityError
from blindport.services.subscriptions import (
    _TCP_PORT_CAPACITY_ADVISORY_LOCK,
    _UDP_PORT_CAPACITY_ADVISORY_LOCK,
    _lock_port_capacity,
    reserve_subscription_resource,
)


def _port_subscription(session: Session, user_id: int, transport: Transport) -> Subscription:
    subscription = Subscription(
        user_id=user_id,
        product=ProductType.PORT,
        transport=transport,
        monthly_price_sats=1,
    )
    session.add(subscription)
    session.flush()
    return subscription


def _configure_wide_port_inventory(monkeypatch, *, tcp_capacity: int, udp_capacity: int) -> None:
    from blindport.services import catalog, subscriptions

    for module in (catalog, subscriptions):
        monkeypatch.setattr(module.settings, "RELAY_SHARED_TCP_PORTS", "10000-65535")
        monkeypatch.setattr(module.settings, "RELAY_SHARED_UDP_PORTS", "10000-65535")
        monkeypatch.setattr(module.settings, "PORT_TCP_CAPACITY", tcp_capacity)
        monkeypatch.setattr(module.settings, "PORT_UDP_CAPACITY", udp_capacity)


def test_settings_accept_full_transport_ranges_and_bound_capacities() -> None:
    settings = Settings(
        _env_file=None,
        RELAY_SHARED_TCP_PORTS="10000-65535",
        RELAY_SHARED_UDP_PORTS="10000-65535",
    )

    assert settings.relay_shared_tcp_port_range == range(10000, 65536)
    assert settings.relay_shared_udp_port_range == range(10000, 65536)
    assert (settings.PORT_TCP_CAPACITY, settings.PORT_UDP_CAPACITY) == (4096, 4096)

    for field in ("PORT_TCP_CAPACITY", "PORT_UDP_CAPACITY"):
        for value in (0, 4097):
            with pytest.raises(ValidationError):
                Settings(_env_file=None, **{field: value})


def test_wide_inventory_catalog_and_reservation_respect_transport_capacities(
    app_client, monkeypatch
) -> None:
    del app_client
    from blindport.db import engine
    from blindport.services.catalog import get_catalog

    _configure_wide_port_inventory(monkeypatch, tcp_capacity=2, udp_capacity=3)
    with Session(engine) as session:
        user = User(hashed_token="port-capacity-user")
        session.add(user)
        session.flush()
        assert user.id is not None
        tcp_first = _port_subscription(session, user.id, Transport.TCP)
        tcp_second = _port_subscription(session, user.id, Transport.TCP)
        tcp_exhausted = _port_subscription(session, user.id, Transport.TCP)
        udp = _port_subscription(session, user.id, Transport.UDP)
        outside_inventory = Subscription(
            user_id=user.id,
            product=ProductType.PORT,
            transport=Transport.TCP,
            assigned_ip="203.0.113.99",
            assigned_port=10000,
            monthly_price_sats=1,
        )
        session.add(outside_inventory)
        session.flush()

        assert reserve_subscription_resource(session, tcp_first, 1)
        assert reserve_subscription_resource(session, tcp_second, 2)
        assert reserve_subscription_resource(session, udp, 3)
        with pytest.raises(NoCapacityError, match="no Blindport Port capacity"):
            reserve_subscription_resource(session, tcp_exhausted, 4)

        port = next(
            item for item in get_catalog(session).products if item.product == ProductType.PORT
        )
        assert port.capacity.total == 5
        assert port.capacity.tcp_available == 0
        assert port.capacity.udp_available == 2
        assert port.capacity.available == 2


def test_wide_port_inventory_uses_randomized_start(monkeypatch, app_client) -> None:
    del app_client
    from blindport.db import engine
    from blindport.services import subscriptions

    _configure_wide_port_inventory(monkeypatch, tcp_capacity=1, udp_capacity=1)
    monkeypatch.setattr(subscriptions.secrets, "randbelow", lambda upper: 4096)
    with Session(engine) as session:
        user = User(hashed_token="wide-port-random-user")
        session.add(user)
        session.flush()
        assert user.id is not None
        subscription = _port_subscription(session, user.id, Transport.TCP)

        assert reserve_subscription_resource(session, subscription, 1)
        assert subscription.assigned_port == 14096


def test_small_port_inventory_remains_sequential(monkeypatch, app_client) -> None:
    del app_client
    from blindport.db import engine
    from blindport.services import catalog, subscriptions

    for module in (catalog, subscriptions):
        monkeypatch.setattr(module.settings, "RELAY_SHARED_TCP_PORTS", "10000-10001")
        monkeypatch.setattr(module.settings, "PORT_TCP_CAPACITY", 4096)
    with Session(engine) as session:
        user = User(hashed_token="small-port-sequential-user")
        session.add(user)
        session.flush()
        assert user.id is not None
        first = _port_subscription(session, user.id, Transport.TCP)
        second = _port_subscription(session, user.id, Transport.TCP)

        assert reserve_subscription_resource(session, first, 1)
        assert reserve_subscription_resource(session, second, 2)
        assert (first.assigned_port, second.assigned_port) == (10000, 10001)


@pytest.mark.parametrize(
    ("transport", "lock_id"),
    [
        (Transport.TCP, _TCP_PORT_CAPACITY_ADVISORY_LOCK),
        (Transport.UDP, _UDP_PORT_CAPACITY_ADVISORY_LOCK),
    ],
)
def test_postgresql_port_capacity_locks_are_transport_specific(
    transport: Transport, lock_id: int
) -> None:
    class PostgresSession:
        def __init__(self) -> None:
            self.statements: list[str] = []

        def get_bind(self):
            return SimpleNamespace(dialect=SimpleNamespace(name="postgresql"))

        def execute(self, statement) -> None:
            self.statements.append(str(statement))

    session = PostgresSession()
    _lock_port_capacity(session, transport)  # type: ignore[arg-type]

    assert session.statements == [f"SELECT pg_advisory_xact_lock({lock_id})"]
