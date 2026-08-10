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
    assert summary.total_subscriptions == 0
    assert summary.pending_subscriptions == 0
    assert summary.expired_subscriptions == 0
    assert summary.accounts_without_subscriptions == 0
    assert summary.settled_gross_sats_30d == 0
    assert summary.active_subscription_accounts_7d == 0
    assert [(row.key, row.value, row.percent) for row in summary.status_breakdown] == [
        ("active", 0, 0),
        ("pending", 0, 0),
        ("expired", 0, 0),
        ("cancelled", 0, 0),
    ]
    assert [(row.key, row.value, row.percent) for row in summary.active_product_breakdown] == [
        ("ip", 0, 0),
        ("port", 0, 0),
        ("relay", 0, 0),
    ]
    assert len(summary.weekly_activity) == 8
    assert all(
        row.new_subscriptions
        == row.paid_sats
        == row.subscription_percent
        == row.revenue_percent
        == 0
        for row in summary.weekly_activity
    )
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
            created_at=now - timedelta(days=1),
        )
        port = Subscription(
            user_id=weekly_active.id,
            product=ProductType.PORT,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="203.0.113.20",
            assigned_port=10000,
            transport=Transport.TCP,
            monthly_price_sats=1,
            created_at=now - timedelta(days=10),
        )
        relay = Subscription(
            user_id=inactive.id,
            product=ProductType.RELAY,
            status=SubscriptionStatus.ACTIVE,
            domain="operations.relay.test",
            domain_is_managed=True,
            monthly_price_sats=1,
            created_at=now - timedelta(days=17),
        )
        pending = Subscription(
            user_id=pending_customer.id,
            product=ProductType.PORT,
            monthly_price_sats=1,
            created_at=now - timedelta(days=2),
        )
        admin_subscription = Subscription(
            user_id=admin.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1,
            created_at=now - timedelta(days=1),
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
    assert summary.total_subscriptions == 4
    assert summary.pending_subscriptions == 1
    assert summary.expired_subscriptions == 0
    assert summary.accounts_without_subscriptions == 0
    assert summary.settled_gross_sats_30d == 100
    assert summary.active_subscription_accounts_7d == 2
    assert [(row.key, row.value, row.percent) for row in summary.status_breakdown] == [
        ("active", 3, 75),
        ("pending", 1, 25),
        ("expired", 0, 0),
        ("cancelled", 0, 0),
    ]
    assert [(row.key, row.value, row.percent) for row in summary.active_product_breakdown] == [
        ("ip", 1, 33),
        ("port", 1, 33),
        ("relay", 1, 33),
    ]
    assert [row.label for row in summary.weekly_activity] == [
        "Nov 17",
        "Nov 24",
        "Dec 1",
        "Dec 8",
        "Dec 15",
        "Dec 22",
        "Dec 29",
        "Jan 5",
    ]
    assert [row.new_subscriptions for row in summary.weekly_activity] == [0, 0, 0, 0, 0, 1, 1, 2]
    assert [row.paid_sats for row in summary.weekly_activity] == [0, 0, 200, 0, 0, 0, 100, 0]
    assert [row.subscription_percent for row in summary.weekly_activity] == [
        0,
        0,
        0,
        0,
        0,
        50,
        50,
        100,
    ]
    assert [row.revenue_percent for row in summary.weekly_activity] == [0, 0, 100, 0, 0, 0, 50, 0]
    assert [edge.state for edge in summary.relay_edges] == ["healthy", "stale"]
    assert summary.relay_edges[1].active_tunnels is None
    assert summary.dns_targets[0].state == "healthy"
    assert capacities["ip"].availability == "8 of 8 addresses available"
    assert capacities["port"].availability == "3 of 4 mappings available"
    assert capacities["relay"].availability == "1 of 2 managed names available"
    assert capacities["relay"].detail == "Customer domains available"


def test_subscription_rows_combine_customer_account_and_payment_state() -> None:
    from blindport.core.models import (
        BillingTerm,
        Payment,
        PaymentMethod,
        PaymentStatus,
        ProductType,
        Subscription,
        SubscriptionStatus,
        Transport,
        User,
    )
    from blindport.services.admin_dashboard import build_subscription_rows

    now = datetime(2026, 1, 8, 12, 0, tzinfo=UTC)
    active_user = User(
        id=1, hashed_token="admin-row-active", has_nwc=True, last_seen_at=now - timedelta(days=1)
    )
    awaiting_user = User(
        id=2, hashed_token="admin-row-awaiting", last_seen_at=now - timedelta(days=8)
    )
    suspended_user = User(id=3, hashed_token="admin-row-suspended", is_suspended=True)
    account_only = User(id=4, hashed_token="admin-row-account-only")
    paid_pending_user = User(id=5, hashed_token="admin-row-paid-pending")
    payment_needed_user = User(id=6, hashed_token="admin-row-payment-needed")
    admin = User(id=7, hashed_token="admin-row-admin", is_admin=True)
    pending_payment_user = User(id=8, hashed_token="admin-row-pending-payment")
    active = Subscription(
        id=11,
        user_id=active_user.id,
        product=ProductType.IP,
        status=SubscriptionStatus.ACTIVE,
        assigned_ip="203.0.113.10",
        billing_term=BillingTerm.YEARLY,
        monthly_price_sats=100,
        current_period_end=datetime(2026, 2, 1, 0, 0),
    )
    awaiting = Subscription(
        id=12,
        user_id=awaiting_user.id,
        product=ProductType.PORT,
        status=SubscriptionStatus.PENDING,
        assigned_ip="203.0.113.20",
        assigned_port=10000,
        transport=Transport.UDP,
        monthly_price_sats=200,
    )
    suspended = Subscription(
        id=13,
        user_id=suspended_user.id,
        product=ProductType.RELAY,
        status=SubscriptionStatus.ACTIVE,
        domain="service.example.test",
        monthly_price_sats=300,
    )
    paid_pending = Subscription(
        id=14,
        user_id=paid_pending_user.id,
        product=ProductType.IP,
        status=SubscriptionStatus.PENDING,
        monthly_price_sats=400,
    )
    payment_needed = Subscription(
        id=15,
        user_id=payment_needed_user.id,
        product=ProductType.RELAY,
        status=SubscriptionStatus.PENDING,
        monthly_price_sats=500,
    )
    pending_payment = Subscription(
        id=16,
        user_id=pending_payment_user.id,
        product=ProductType.PORT,
        status=SubscriptionStatus.PENDING,
        monthly_price_sats=550,
    )
    expired = Subscription(
        id=17,
        user_id=active_user.id,
        product=ProductType.IP,
        status=SubscriptionStatus.EXPIRED,
        monthly_price_sats=700,
    )
    cancelled = Subscription(
        id=18,
        user_id=active_user.id,
        product=ProductType.RELAY,
        status=SubscriptionStatus.CANCELLED,
        monthly_price_sats=800,
    )
    admin_subscription = Subscription(
        id=19,
        user_id=admin.id,
        product=ProductType.IP,
        status=SubscriptionStatus.PENDING,
        monthly_price_sats=600,
    )
    rows = build_subscription_rows(
        [
            active_user,
            awaiting_user,
            suspended_user,
            account_only,
            paid_pending_user,
            payment_needed_user,
            admin,
            pending_payment_user,
        ],
        [
            active,
            awaiting,
            suspended,
            paid_pending,
            payment_needed,
            pending_payment,
            expired,
            cancelled,
            admin_subscription,
        ],
        [
            Payment(
                id=21,
                subscription_id=active.id,
                method=PaymentMethod.LIGHTNING,
                status=PaymentStatus.PAID,
                amount_sats=100,
                paid_at=now - timedelta(hours=1),
            ),
            Payment(
                id=22,
                subscription_id=awaiting.id,
                method=PaymentMethod.NWC,
                status=PaymentStatus.PROCESSING,
                amount_sats=200,
                created_at=now - timedelta(minutes=30),
            ),
            Payment(
                id=23,
                subscription_id=paid_pending.id,
                method=PaymentMethod.LIGHTNING,
                status=PaymentStatus.PAID,
                amount_sats=400,
                paid_at=now - timedelta(minutes=10),
            ),
            Payment(
                id=24,
                subscription_id=pending_payment.id,
                method=PaymentMethod.LIGHTNING,
                status=PaymentStatus.PENDING,
                amount_sats=550,
                created_at=now - timedelta(minutes=5),
            ),
        ],
        now=now,
    )

    by_subscription = {row.subscription_public_id: row for row in rows}
    active_row = by_subscription[str(active.public_id)]
    awaiting_row = by_subscription[str(awaiting.public_id)]
    suspended_row = by_subscription[str(suspended.public_id)]
    paid_pending_row = by_subscription[str(paid_pending.public_id)]
    payment_needed_row = by_subscription[str(payment_needed.public_id)]
    pending_payment_row = by_subscription[str(pending_payment.public_id)]
    expired_row = by_subscription[str(expired.public_id)]
    cancelled_row = by_subscription[str(cancelled.public_id)]
    assert active_row.account_public_id == str(active_user.public_id)
    assert active_row.activity_key == "recent"
    assert active_row.activity_label == "Recent account activity"
    assert active_row.nwc_state == "configured"
    assert active_row.assigned_resource == "203.0.113.10"
    assert active_row.billing_term == "yearly"
    assert active_row.period_end == datetime(2026, 2, 1, tzinfo=UTC)
    assert active_row.latest_payment_status == "paid"
    assert awaiting_row.status_detail == "Processing payment"
    assert awaiting_row.activity_key == "idle"
    assert awaiting_row.assigned_resource == "UDP 203.0.113.20:10000"
    assert awaiting_row.latest_payment_method == "nwc"
    assert awaiting_row.latest_payment_amount_sats == 200
    assert awaiting_row.latest_payment_at == now - timedelta(minutes=30)
    assert paid_pending_row.status_detail == "Activation pending"
    assert payment_needed_row.status_detail == "Payment needed"
    assert pending_payment_row.status_detail == "Awaiting payment"
    assert expired_row.status_label == "Expired"
    assert cancelled_row.status_label == "Cancelled"
    assert suspended_row.account_suspended is True
    assert suspended_row.status_detail == "Account access suspended"
    assert suspended_row.activity_key == "suspended"
    assert suspended_row.assigned_resource == "service.example.test"
    assert [row.status_key for row in rows] == [
        "active",
        "pending",
        "pending",
        "pending",
        "pending",
        "expired",
        "cancelled",
        "active",
        "account_only",
    ]
    account_only_row = rows[-1]
    assert account_only_row.account_public_id == str(account_only.public_id)
    assert account_only_row.subscription_public_id is None
    assert account_only_row.status_key == "account_only"
    assert account_only_row.activity_key == "never"
    assert str(admin.public_id) not in {row.account_public_id for row in rows}
