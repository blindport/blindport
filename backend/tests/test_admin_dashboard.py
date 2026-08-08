"""Operations-summary aggregate coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session


def test_operations_summary_is_zero_for_an_empty_customer_database(app_client) -> None:
    from blindport.db import engine
    from blindport.services.admin_dashboard import build_operations_summary

    _client, _ = app_client
    with Session(engine) as session:
        summary = build_operations_summary(session, now=datetime(2026, 1, 1, tzinfo=UTC))

    assert summary.active_subscriptions == 0
    assert summary.active_customers == 0
    assert summary.settled_gross_sats == 0
    assert summary.open_payments == 0
    assert summary.oldest_open_payment_age is None
    assert summary.active_accounts_24h == 0
    assert summary.active_accounts_7d == 0
    assert summary.ever_paying_customers == 0
    assert summary.active_paying_customers == 0
    assert summary.lapsed_paying_customers == 0
    assert summary.new_paying_customers_30d == 0
    assert summary.active_relay_tunnels == 0
    assert summary.active_relay_streams == 0
    assert summary.relay_edges == ()
    assert summary.dns_targets == ()


def test_operations_summary_uses_customer_aggregates_and_catalog_capacity(
    app_client, monkeypatch
) -> None:
    from blindport.core.models import (
        DnsObservation,
        Payment,
        PaymentMethod,
        PaymentStatus,
        ProductType,
        RelayHeartbeat,
        Subscription,
        SubscriptionStatus,
        Transport,
        User,
    )
    from blindport.db import engine
    from blindport.services import catalog
    from blindport.services.admin_dashboard import build_operations_summary

    _client, _ = app_client
    now = datetime(2026, 1, 8, 12, 0, tzinfo=UTC)
    monkeypatch.setattr(catalog.settings, "RELAY_MANAGED_DOMAIN_CAP", 2)
    from blindport.services import admin_dashboard

    monkeypatch.setattr(
        admin_dashboard.settings,
        "RELAY_EDGES",
        '[{"id":"edge-a","endpoint":"edge-a.test:5443"},{"id":"edge-b","endpoint":"edge-b.test:5443"}]',
    )
    monkeypatch.setattr(
        admin_dashboard.settings,
        "DNS_SUPERVISION_TARGETS",
        '[{"hostname":"edge.example.com","expected_ips":["1.1.1.1"]}]',
    )
    with Session(engine) as session:
        recently_active = User(
            hashed_token="operations-recently-active",
            last_seen_at=now - timedelta(hours=1),
        )
        weekly_active = User(
            hashed_token="operations-weekly-active",
            last_seen_at=now - timedelta(days=2),
        )
        inactive = User(
            hashed_token="operations-inactive",
            last_seen_at=now - timedelta(days=8),
        )
        pending_customer = User(hashed_token="operations-pending-customer")
        admin = User(hashed_token="operations-admin", is_admin=True)
        session.add_all([recently_active, weekly_active, inactive, pending_customer, admin])
        session.flush()

        ip = Subscription(
            user_id=recently_active.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="203.0.113.10",
            monthly_price_sats=1,
        )
        port = Subscription(
            user_id=weekly_active.id,
            product=ProductType.PORT,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="203.0.113.20",
            assigned_port=10000,
            transport=Transport.TCP,
            monthly_price_sats=1,
        )
        relay = Subscription(
            user_id=inactive.id,
            product=ProductType.RELAY,
            status=SubscriptionStatus.ACTIVE,
            domain="operations.relay.test",
            domain_is_managed=True,
            monthly_price_sats=1,
        )
        pending = Subscription(
            user_id=pending_customer.id,
            product=ProductType.PORT,
            monthly_price_sats=1,
        )
        admin_subscription = Subscription(
            user_id=admin.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1,
        )
        session.add_all([ip, port, relay, pending, admin_subscription])
        session.flush()
        session.add_all(
            [
                Payment(
                    subscription_id=ip.id,
                    method=PaymentMethod.LIGHTNING,
                    status=PaymentStatus.PAID,
                    amount_sats=100,
                    paid_at=now - timedelta(days=5),
                ),
                Payment(
                    subscription_id=port.id,
                    method=PaymentMethod.LIGHTNING,
                    status=PaymentStatus.PAID,
                    amount_sats=200,
                    paid_at=now - timedelta(days=35),
                ),
                Payment(
                    subscription_id=relay.id,
                    method=PaymentMethod.NWC,
                    status=PaymentStatus.PROCESSING,
                    amount_sats=300,
                    created_at=now - timedelta(hours=2),
                ),
                Payment(
                    subscription_id=pending.id,
                    method=PaymentMethod.LIGHTNING,
                    status=PaymentStatus.PENDING,
                    amount_sats=400,
                    created_at=now - timedelta(minutes=30),
                ),
                Payment(
                    subscription_id=admin_subscription.id,
                    method=PaymentMethod.LIGHTNING,
                    status=PaymentStatus.PAID,
                    amount_sats=9_999,
                ),
                RelayHeartbeat(
                    edge_id="edge-a",
                    ready=True,
                    authorization="ok",
                    certificate="ok",
                    lifecycle="serving",
                    listeners="ok",
                    wireguard="disabled",
                    active_tunnels=2,
                    active_streams=3,
                    accepted_connections_total=4,
                    forwarded_bytes_total=5,
                    received_at=now - timedelta(seconds=10),
                ),
                RelayHeartbeat(
                    edge_id="edge-b",
                    ready=True,
                    authorization="ok",
                    certificate="ok",
                    lifecycle="serving",
                    listeners="ok",
                    wireguard="disabled",
                    active_tunnels=99,
                    active_streams=99,
                    accepted_connections_total=4,
                    forwarded_bytes_total=5,
                    received_at=now - timedelta(seconds=91),
                ),
                DnsObservation(
                    hostname="edge.example.com",
                    expected_ips="1.1.1.1",
                    observed_ips="1.1.1.1",
                    healthy=True,
                    resolver_count=2,
                    successful_resolvers=2,
                    checked_at=now - timedelta(seconds=5),
                ),
            ]
        )
        session.commit()

        summary = build_operations_summary(session, now=now)

    capacities = {capacity.product: capacity for capacity in summary.capacities}
    assert summary.active_subscriptions == 3
    assert summary.active_customers == 3
    assert summary.settled_gross_sats == 300
    assert summary.open_payments == 2
    assert summary.oldest_open_payment_age == "2h 0m"
    assert summary.active_accounts_24h == 1
    assert summary.active_accounts_7d == 2
    assert summary.ever_paying_customers == 2
    assert summary.active_paying_customers == 2
    assert summary.lapsed_paying_customers == 0
    assert summary.new_paying_customers_30d == 1
    assert summary.active_relay_tunnels == 2
    assert summary.active_relay_streams == 3
    assert [edge.state for edge in summary.relay_edges] == ["healthy", "stale"]
    assert summary.relay_edges[1].active_tunnels is None
    assert summary.dns_targets[0].state == "healthy"
    assert capacities["ip"].availability == "1 of 2 addresses available"
    assert capacities["port"].availability == "3 of 4 mappings available"
    assert capacities["relay"].availability == "1 of 2 managed names available"
    assert capacities["relay"].detail == "Customer domains available"
