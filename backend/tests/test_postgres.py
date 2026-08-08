"""Focused PostgreSQL schema and model lifecycle coverage for CI."""

from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import MetaData, Table, delete, func, inspect, text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlmodel import Session, SQLModel, create_engine, select

from blindport.core.auth import _touch_last_seen
from blindport.core.models import (
    AgentOrder,
    BillingTerm,
    ClientCredential,
    DeliveryMode,
    IPLease,
    IPLeaseDelivery,
    IPLeaseState,
    Payment,
    PaymentMethod,
    PaymentStatus,
    ProductType,
    RateLimitBucket,
    RateLimitMaintenance,
    ReminderDelivery,
    ReminderKind,
    Subscription,
    SubscriptionStatus,
    Transport,
    User,
)
from blindport.migrations import database_revisions, downgrade_database, upgrade_database
from blindport.services.agent_orders import AgentOrderSpec, put_agent_order
from blindport.services.catalog import ProductUnavailableError
from blindport.services.client_enrollment import enroll_client_certificate
from blindport.services.nwc_credentials import store_nwc_credential
from blindport.services.payments import (
    _claim_nwc_lease,
    check_and_settle_payment,
    create_payment,
    ensure_lightning_invoice,
)
from blindport.services.rate_limits import (
    RateLimitExceeded,
    RateLimitScope,
    RateLimitSpec,
    enforce_rate_limit,
    hash_identifier,
)
from blindport.services.reminder_reconciliation import _claim_due_delivery
from blindport.services.subscriptions import (
    AccountLimitError,
    SubscriptionCancellationConflict,
    cancel_pending_subscription,
    create_subscription,
    reap_elapsed_resource_holds,
    reserve_subscription_resource,
)

POSTGRES_URL = os.getenv("TEST_POSTGRES_DATABASE_URL")
pytestmark = pytest.mark.skipif(not POSTGRES_URL, reason="PostgreSQL test URL is not configured")


def test_postgres_concurrent_last_seen_refresh_has_one_winner() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-last-seen-{uuid4()}"
    with Session(engine) as session:
        user = User(
            hashed_token=marker,
            last_seen_at=datetime.now(UTC) - timedelta(minutes=10),
        )
        session.add(user)
        session.commit()
        user_id = user.id
    assert user_id is not None
    barrier = threading.Barrier(2)

    def touch() -> bool:
        with Session(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            barrier.wait(timeout=5)
            return _touch_last_seen(session, user, datetime.now(UTC))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            winners = list(executor.map(lambda _: touch(), range(2)))
        assert winners.count(True) == 1
    finally:
        with Session(engine) as session:
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_identical_agent_orders_create_one_payment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-agent-order-{uuid4()}"

    from blindport.adapters.mock import MockLightningAdapter, MockNwcAdapter
    from blindport.services import payments as payments_service

    lightning = MockLightningAdapter()
    nwc = MockNwcAdapter(settle_callback=lightning.mark_paid)
    monkeypatch.setattr(payments_service, "get_lightning_adapter", lambda: lightning)
    monkeypatch.setattr(payments_service, "get_nwc_adapter", lambda: nwc)
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        store_nwc_credential(
            user,
            "nostr+walletconnect://postgres-agent-order",
            ("pay_invoice", "lookup_invoice"),
        )
        session.add(user)
        session.commit()
        user_id = user.id
    assert user_id is not None
    barrier = threading.Barrier(2)
    spec = AgentOrderSpec(
        product=ProductType.RELAY,
        billing_term=BillingTerm.MONTHLY,
        delivery=DeliveryMode.FRAMED,
        transport=Transport.TCP,
        domain=f"{uuid4().hex}.relay.test",
    )

    def put() -> tuple[int | None, int | None, int | None]:
        with Session(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            barrier.wait(timeout=10)
            result = put_agent_order(session, user, "primary", spec)
            return (
                result.order.id,
                result.subscription.id,
                result.payment.id if result.payment else None,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: put(), range(2)))
        assert results[0] == results[1]
        assert all(identifier is not None for identifier in results[0])
        with Session(engine) as session:
            orders = session.exec(select(AgentOrder).where(AgentOrder.user_id == user_id)).all()
            subscriptions = session.exec(
                select(Subscription).where(Subscription.user_id == user_id)
            ).all()
            payments = session.exec(
                select(Payment).join(AgentOrder).where(AgentOrder.user_id == user_id)
            ).all()
            assert len(orders) == len(subscriptions) == len(payments) == 1
    finally:
        with Session(engine) as session:
            order_ids = select(AgentOrder.id).where(AgentOrder.user_id == user_id)
            session.execute(delete(Payment).where(Payment.agent_order_id.in_(order_ids)))
            session.execute(delete(AgentOrder).where(AgentOrder.user_id == user_id))
            session.execute(delete(Subscription).where(Subscription.user_id == user_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_nwc_lease_allows_one_concurrent_wallet_worker() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = uuid4().hex
    with Session(engine) as session:
        user = User(hashed_token=f"nwc-lease-{marker}")
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            yearly_price_sats=10000,
        )
        session.add(subscription)
        session.flush()
        payment = Payment(
            subscription_id=subscription.id,
            method=PaymentMethod.NWC,
            status=PaymentStatus.PENDING,
            amount_sats=1000,
            payment_hash=uuid4().hex + uuid4().hex,
        )
        session.add(payment)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id
        payment_id = payment.id

    barrier = threading.Barrier(2)

    def claim() -> bool:
        with Session(engine) as session:
            payment = session.get(Payment, payment_id)
            assert payment is not None
            barrier.wait(timeout=5)
            return _claim_nwc_lease(session, payment) is not None

    with ThreadPoolExecutor(max_workers=2) as executor:
        claimed = list(executor.map(lambda _: claim(), range(2)))

    assert claimed.count(True) == 1
    with engine.begin() as connection:
        connection.execute(delete(Payment).where(Payment.id == payment_id))
        connection.execute(delete(Subscription).where(Subscription.id == subscription_id))
        connection.execute(delete(User).where(User.id == user_id))


def test_postgres_reminder_lease_allows_one_concurrent_worker(monkeypatch) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = uuid4().hex
    with Session(engine) as session:
        user = User(
            hashed_token=f"reminder-lease-{marker}",
            has_reminder_email=True,
            reminder_email_generation=1,
        )
        session.add(user)
        session.flush()
        period_end = datetime.now(UTC) + timedelta(days=6)
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=period_end,
        )
        session.add(subscription)
        session.flush()
        delivery = ReminderDelivery(
            subscription_id=subscription.id,
            current_period_end=period_end,
            recipient_generation=1,
            kind=ReminderKind.SEVEN_DAY,
        )
        session.add(delivery)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id
        delivery_id = delivery.id

    from blindport.services import reminder_reconciliation

    monkeypatch.setattr(reminder_reconciliation.db, "engine", engine)
    barrier = threading.Barrier(2)

    def claim() -> tuple[int, str] | None:
        barrier.wait(timeout=5)
        return _claim_due_delivery(datetime.now(UTC))

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            claimed = list(executor.map(lambda _: claim(), range(2)))
        matching = [claim for claim in claimed if claim is not None and claim[0] == delivery_id]
        assert len(matching) == 1
    finally:
        with engine.begin() as connection:
            connection.execute(delete(ReminderDelivery).where(ReminderDelivery.id == delivery_id))
            connection.execute(delete(Subscription).where(Subscription.id == subscription_id))
            connection.execute(delete(User).where(User.id == user_id))


def test_postgres_migration_and_database_lifecycle() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    downgrade_database(engine, "0007")
    legacy_user = Table("user", MetaData(), autoload_with=engine)
    legacy_marker = f"postgres-public-id-backfill-{uuid4()}"
    with engine.begin() as connection:
        legacy_user_id = connection.execute(
            legacy_user.insert().values(
                hashed_token=legacy_marker,
                is_admin=False,
                is_suspended=False,
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]

    upgrade_database(engine, "0008")
    assert database_revisions(engine) == ("0008", "0019")
    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        backfilled = connection.execute(
            select(upgraded_user.c.public_id).where(upgraded_user.c.id == legacy_user_id)
        ).scalar_one()
    assert UUID(str(backfilled)).version == 4

    legacy_subscription = Table("subscription", MetaData(), autoload_with=engine)
    legacy_payment = Table("payment", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        legacy_subscription_id = connection.execute(
            legacy_subscription.insert().values(
                user_id=legacy_user_id,
                product="port",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1234,
                auto_renew=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]
        legacy_payment_id = connection.execute(
            legacy_payment.insert().values(
                subscription_id=legacy_subscription_id,
                method="LIGHTNING",
                status="PAID",
                amount_sats=1234,
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]

    with engine.begin() as connection:
        connection.execute(
            upgraded_user.update()
            .where(upgraded_user.c.id == legacy_user_id)
            .values(nwc_uri="nostr+walletconnect://postgres-revoked")
        )
    upgrade_database(engine, "0009")
    upgrade_database(engine, "0012")
    _replace_postgres_reminders_with_deployed_0012_shape(
        engine,
        legacy_subscription_id,
        datetime.now(UTC),
    )
    upgrade_database(engine, "0013")
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_subscription_public_id"))
        connection.execute(text("ALTER TABLE subscription DROP COLUMN public_id"))
    upgrade_database(engine)
    assert database_revisions(engine) == ("0019", "0019")
    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        assert (
            connection.execute(
                select(upgraded_user.c.nwc_uri).where(upgraded_user.c.id == legacy_user_id)
            ).scalar_one()
            is None
        )
        connection.execute(
            upgraded_user.update()
            .where(upgraded_user.c.id == legacy_user_id)
            .values(nwc_uri="nostr+walletconnect://rolling-write")
        )
    with engine.connect() as connection:
        assert (
            connection.execute(
                select(upgraded_user.c.nwc_uri).where(upgraded_user.c.id == legacy_user_id)
            ).scalar_one()
            is None
        )
    upgraded_subscription = Table("subscription", MetaData(), autoload_with=engine)
    upgraded_payment = Table("payment", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        billing_sub = connection.execute(
            select(upgraded_subscription).where(
                upgraded_subscription.c.id == legacy_subscription_id
            )
        ).one()
        billing_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == legacy_payment_id)
        ).one()
    assert (billing_sub.billing_term, billing_sub.yearly_price_sats) == ("monthly", 12340)
    assert UUID(str(billing_sub.public_id)).version == 4
    assert (billing_payment.billing_term, billing_payment.period_days) == ("monthly", 30)
    assert billing_payment.markup_sats == 0
    with engine.connect() as connection:
        payment_methods = (
            connection.execute(
                text(
                    "SELECT enumlabel FROM pg_enum JOIN pg_type ON pg_type.oid = enumtypid "
                    "WHERE typname = 'paymentmethod' ORDER BY enumsortorder"
                )
            )
            .scalars()
            .all()
        )
        reminder_audit = connection.execute(
            text("SELECT state, error_code FROM reminderdelivery")
        ).one()
    assert payment_methods == ["LIGHTNING", "CASHU", "NWC", "STABLECOIN_SWAP"]
    assert reminder_audit == ("cancelled", "legacy_delivery_cancelled")

    post_migration_marker = f"postgres-legacy-insert-{uuid4()}"
    with engine.begin() as connection:
        inserted_user_id = connection.execute(
            upgraded_user.insert().values(
                hashed_token=post_migration_marker,
                is_admin=False,
                is_suspended=False,
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]
    with engine.connect() as connection:
        generated = connection.execute(
            select(upgraded_user.c.public_id).where(upgraded_user.c.id == inserted_user_id)
        ).scalar_one()
    assert UUID(str(generated)).version == 4

    with engine.begin() as connection:
        rolling_subscription_id = connection.execute(
            upgraded_subscription.insert().values(
                user_id=inserted_user_id,
                product="ip",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=777,
                auto_renew=False,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]
        rolling_payment_id = connection.execute(
            upgraded_payment.insert().values(
                subscription_id=rolling_subscription_id,
                method="LIGHTNING",
                status="PAID",
                amount_sats=777,
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]
    with engine.connect() as connection:
        rolling_sub = connection.execute(
            select(upgraded_subscription).where(
                upgraded_subscription.c.id == rolling_subscription_id
            )
        ).one()
        rolling_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == rolling_payment_id)
        ).one()
    assert (rolling_sub.billing_term, rolling_sub.yearly_price_sats) == ("monthly", 7770)
    assert (rolling_payment.billing_term, rolling_payment.period_days) == ("monthly", 30)

    with (
        pytest.raises(ProgrammingError, match="public_id is immutable"),
        engine.begin() as connection,
    ):
        connection.execute(
            upgraded_user.update()
            .where(upgraded_user.c.id == inserted_user_id)
            .values(public_id=uuid4())
        )

    with (
        pytest.raises(ProgrammingError, match="subscription public_id is immutable"),
        engine.begin() as connection,
    ):
        connection.execute(
            upgraded_subscription.update()
            .where(upgraded_subscription.c.id == rolling_subscription_id)
            .values(public_id=uuid4())
        )

    with engine.begin() as connection:
        connection.execute(text("DELETE FROM reminderdelivery"))
        connection.execute(
            delete(upgraded_payment).where(
                upgraded_payment.c.id.in_([legacy_payment_id, rolling_payment_id])
            )
        )
        connection.execute(
            delete(upgraded_subscription).where(
                upgraded_subscription.c.id.in_([legacy_subscription_id, rolling_subscription_id])
            )
        )
        connection.execute(
            delete(upgraded_user).where(upgraded_user.c.id.in_([legacy_user_id, inserted_user_id]))
        )
    downgrade_database(engine, "0008")
    assert "billing_term" not in {
        column["name"] for column in inspect(engine).get_columns("subscription")
    }
    upgrade_database(engine)
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, SQLModel.metadata) == []
        assert (
            connection.execute(text("SELECT enum_range(NULL::producttype)::text")).scalar_one()
            == "{ip,port,relay}"
        )
        assert (
            connection.execute(text("SELECT enum_range(NULL::billingterm)::text")).scalar_one()
            == "{monthly,yearly}"
        )

    indexes = inspect(engine).get_indexes("subscription")
    assert any(index["name"] == "uq_subscription_dedicated_ip" for index in indexes)
    assert any(
        constraint["column_names"] == ["assigned_ip", "assigned_port", "transport"]
        for constraint in inspect(engine).get_unique_constraints("subscription")
    )

    payment_indexes = inspect(engine).get_indexes("payment")
    assert any(index["name"] == "uq_payment_open_subscription" for index in payment_indexes)

    marker = "postgres-lifecycle-user"
    with Session(engine) as session:
        existing = session.exec(select(User).where(User.hashed_token == marker)).first()
        if existing is not None:
            session.delete(existing)
            session.commit()

        user = User(hashed_token=marker)
        session.add(user)
        session.commit()
        session.refresh(user)

        subscriptions = [
            Subscription(
                user_id=user.id,
                product=ProductType.IP,
                monthly_price_sats=1,
            )
            for _ in range(2)
        ]
        session.add_all(subscriptions)
        session.commit()
        for subscription in subscriptions:
            session.refresh(subscription)

        payments = [
            Payment(
                subscription_id=subscription.id,
                method=PaymentMethod.LIGHTNING,
                amount_sats=1,
            )
            for subscription in subscriptions
        ]
        session.add_all(payments)
        session.commit()
        for payment in payments:
            session.refresh(payment)

        for subscription, payment in zip(subscriptions, payments, strict=True):
            assert payment.id is not None
            assert reserve_subscription_resource(session, subscription, payment.id)
            session.commit()
            session.refresh(subscription)
            assert subscription.reservation_payment_id == payment.id
        assert {subscription.assigned_ip for subscription in subscriptions} == {
            "203.0.113.10",
            "203.0.113.11",
        }

        for payment in payments:
            session.delete(payment)
        session.execute(
            delete(IPLease).where(
                IPLease.subscription_id.in_([subscription.id for subscription in subscriptions])  # type: ignore[union-attr]
            )
        )
        for subscription in subscriptions:
            session.delete(subscription)
        session.delete(user)
        session.commit()


def test_postgres_0017_backfills_deployed_ip_assignment_enums() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    downgrade_database(engine, "0016")
    now = datetime.now(UTC)
    marker = f"postgres-0017-backfill-{uuid4()}"
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,  # type: ignore[arg-type]
            product=ProductType.IP,
            delivery=DeliveryMode.WIREGUARD,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="198.51.100.201",
            billing_term=BillingTerm.MONTHLY,
            monthly_price_sats=7500,
            yearly_price_sats=75000,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
        )
        session.add(subscription)
        session.commit()
        subscription_id = subscription.id
        user_id = user.id

    upgrade_database(engine)
    with Session(engine) as session:
        lease = session.exec(
            select(IPLease).where(IPLease.subscription_id == subscription_id)
        ).one()
        assert lease.delivery == IPLeaseDelivery.WIREGUARD
        assert lease.state == IPLeaseState.ACTIVE
        assert lease.imported is True
        assert lease.smtp_enabled is False
        session.delete(lease)
        subscription = session.get(Subscription, subscription_id)
        user = session.get(User, user_id)
        assert subscription is not None and user is not None
        session.delete(subscription)
        session.delete(user)
        session.commit()


def test_postgres_0015_scrubs_direct_rate_limit_rows_and_recounts() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    downgrade_database(engine, "0014")
    buckets = Table("ratelimitbucket", MetaData(), autoload_with=engine)
    maintenance = Table("ratelimitmaintenance", MetaData(), autoload_with=engine)
    marker = uuid4().hex
    now = datetime.now(UTC)

    with engine.begin() as connection:
        connection.execute(
            buckets.delete().where(buckets.c.scope.in_(("signup", "admin-login", "browser-login")))
        )
        for index, scope in enumerate(("signup", "admin-login", "browser-login", "payment-create")):
            connection.execute(
                buckets.insert().values(
                    scope=scope,
                    identifier_hash=f"{marker}{index:032x}",
                    window_start=now,
                    request_count=1,
                    expires_at=now,
                )
            )
        actual_count = connection.execute(select(func.count()).select_from(buckets)).scalar_one()
        updated = connection.execute(
            maintenance.update()
            .where(maintenance.c.name == "rate-limit-buckets")
            .values(bucket_count=actual_count)
        )
        if updated.rowcount == 0:
            connection.execute(
                maintenance.insert().values(
                    name="rate-limit-buckets",
                    next_cleanup_at=now,
                    bucket_count=actual_count,
                )
            )

    try:
        upgrade_database(engine)
        with engine.connect() as connection:
            direct_count = connection.execute(
                select(func.count())
                .select_from(buckets)
                .where(buckets.c.scope.in_(("signup", "admin-login", "browser-login")))
            ).scalar_one()
            durable_marker_count = connection.execute(
                select(func.count())
                .select_from(buckets)
                .where(buckets.c.identifier_hash == f"{marker}{3:032x}")
            ).scalar_one()
            bucket_count = connection.execute(
                select(maintenance.c.bucket_count).where(maintenance.c.name == "rate-limit-buckets")
            ).scalar_one()
            actual_count = connection.execute(
                select(func.count()).select_from(buckets)
            ).scalar_one()
        assert direct_count == 0
        assert durable_marker_count == 1
        assert bucket_count == actual_count
    finally:
        with engine.begin() as connection:
            connection.execute(buckets.delete().where(buckets.c.identifier_hash.like(f"{marker}%")))
            actual_count = connection.execute(
                select(func.count()).select_from(buckets)
            ).scalar_one()
            connection.execute(
                maintenance.update()
                .where(maintenance.c.name == "rate-limit-buckets")
                .values(bucket_count=actual_count)
            )


def _replace_postgres_reminders_with_deployed_0012_shape(
    engine, subscription_id: int, period_end: datetime
) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP TABLE reminderdelivery"))
        connection.execute(text("DROP TYPE reminderdeliverystate"))
        connection.execute(
            text(
                "CREATE TYPE reminderdeliverystate AS ENUM ("
                "'queued', 'creating_invoice', 'invoice_creation_ambiguous', "
                "'invoice_created', 'paying', 'payment_ambiguous', "
                "'awaiting_delivery', 'delivered', 'cancelled', 'failed', 'expired')"
            )
        )
        connection.execute(
            text(
                """
                CREATE TABLE reminderdelivery (
                    id SERIAL PRIMARY KEY,
                    subscription_id INTEGER NOT NULL REFERENCES subscription(id),
                    current_period_end TIMESTAMPTZ NOT NULL,
                    recipient_generation INTEGER NOT NULL,
                    kind reminderkind NOT NULL,
                    state reminderdeliverystate NOT NULL DEFAULT 'queued',
                    attempt_count INTEGER NOT NULL DEFAULT 0,
                    invoice_ciphertext TEXT,
                    invoice_key_version VARCHAR(32),
                    payment_hash VARCHAR(64),
                    price_sats INTEGER,
                    provider VARCHAR(64),
                    provider_payment_status VARCHAR(32),
                    provider_delivery_status VARCHAR(32),
                    nwc_state VARCHAR(32),
                    nwc_preimage_hash VARCHAR(64),
                    nwc_retry_blocked BOOLEAN NOT NULL DEFAULT FALSE,
                    error_code VARCHAR(64),
                    created_at TIMESTAMPTZ NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL,
                    last_attempt_at TIMESTAMPTZ,
                    next_attempt_at TIMESTAMPTZ,
                    invoice_created_at TIMESTAMPTZ,
                    paid_at TIMESTAMPTZ,
                    delivered_at TIMESTAMPTZ,
                    terminal_at TIMESTAMPTZ,
                    lease_token VARCHAR(32),
                    lease_until TIMESTAMPTZ,
                    CONSTRAINT ck_reminderdelivery_attempt_count
                        CHECK (attempt_count >= 0 AND attempt_count <= 20),
                    CONSTRAINT uq_reminderdelivery_subscription_period_kind
                        UNIQUE (subscription_id, current_period_end, kind)
                )
                """
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_reminderdelivery_subscription_id "
                "ON reminderdelivery (subscription_id)"
            )
        )
        connection.execute(
            text(
                "CREATE INDEX ix_reminderdelivery_due "
                "ON reminderdelivery (state, next_attempt_at, id)"
            )
        )
        connection.execute(
            text(
                "CREATE UNIQUE INDEX uq_reminderdelivery_payment_hash "
                "ON reminderdelivery (payment_hash) WHERE payment_hash IS NOT NULL"
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO reminderdelivery (
                    subscription_id, current_period_end, recipient_generation, kind,
                    state, attempt_count, payment_hash, provider, created_at, updated_at
                ) VALUES (
                    :subscription_id, :period_end, 1, '7_day', 'awaiting_delivery',
                    2, :payment_hash, 'legacy', :period_end, :period_end
                )
                """
            ),
            {
                "subscription_id": subscription_id,
                "period_end": period_end,
                "payment_hash": uuid4().hex + uuid4().hex,
            },
        )


def test_postgres_rate_limit_increment_is_atomic_across_sessions() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    identifier = f"account:{uuid4()}"
    spec = RateLimitSpec(RateLimitScope.PAYMENT_CREATE, requests=7, window_seconds=60)
    start = threading.Barrier(20)

    def consume() -> bool:
        start.wait(timeout=10)
        with Session(engine) as session:
            try:
                enforce_rate_limit(session, spec, identifier)
            except RateLimitExceeded:
                return False
        return True

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            allowed = list(executor.map(lambda _: consume(), range(20)))
        assert sum(allowed) == 7
        with Session(engine) as session:
            bucket = session.exec(
                select(RateLimitBucket).where(
                    RateLimitBucket.scope == spec.scope.value,
                    RateLimitBucket.identifier_hash == hash_identifier(spec.scope, identifier),
                )
            ).one()
        assert bucket.request_count == 20
    finally:
        with Session(engine) as session:
            deleted = session.execute(
                delete(RateLimitBucket).where(
                    RateLimitBucket.identifier_hash == hash_identifier(spec.scope, identifier)
                )
            )
            maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
            if maintenance is not None and deleted.rowcount:
                maintenance.bucket_count = max(0, maintenance.bucket_count - deleted.rowcount)
                session.add(maintenance)
            session.commit()


def test_postgres_rate_limit_cardinality_cap_is_atomic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    from blindport.services import rate_limits as rate_limit_service

    monkeypatch.setattr(rate_limit_service.settings, "RATE_LIMIT_MAX_BUCKETS", 5)
    with Session(engine) as session:
        session.execute(delete(RateLimitBucket))
        maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
        if maintenance is None:
            maintenance = RateLimitMaintenance(
                name="rate-limit-buckets",
                next_cleanup_at=datetime.now(UTC) + timedelta(hours=1),
            )
        maintenance.bucket_count = 0
        session.add(maintenance)
        session.commit()

    barrier = threading.Barrier(20)
    spec = RateLimitSpec(RateLimitScope.PAYMENT_CREATE, requests=10, window_seconds=60)

    def consume(index: int) -> bool:
        barrier.wait(timeout=10)
        with Session(engine) as session:
            try:
                enforce_rate_limit(session, spec, f"account:cardinality:{index}")
            except RateLimitExceeded:
                return False
        return True

    try:
        with ThreadPoolExecutor(max_workers=20) as executor:
            allowed = list(executor.map(consume, range(20)))
        assert sum(allowed) == 5
        with Session(engine) as session:
            maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
            assert len(session.exec(select(RateLimitBucket)).all()) == 5
            assert maintenance is not None and maintenance.bucket_count == 5
    finally:
        with Session(engine) as session:
            session.execute(delete(RateLimitBucket))
            maintenance = session.get(RateLimitMaintenance, "rate-limit-buckets")
            if maintenance is not None:
                maintenance.bucket_count = 0
                session.add(maintenance)
            session.commit()


def test_postgres_concurrent_subscription_cap_is_per_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    monkeypatch.setattr(
        "blindport.services.subscriptions.settings.ACCOUNT_MAX_NON_CANCELLED_SUBSCRIPTIONS",
        1,
    )
    marker = f"postgres-subscription-cap-{uuid4()}"
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.commit()
        user_id = user.id
    assert user_id is not None
    barrier = threading.Barrier(2)

    def create(index: int) -> str:
        with Session(engine) as session:
            user = session.get(User, user_id)
            assert user is not None
            barrier.wait(timeout=10)
            try:
                create_subscription(
                    session,
                    user,
                    ProductType.RELAY,
                    domain=f"account-{index}.example.com",
                )
            except AccountLimitError:
                return "limited"
        return "created"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(create, range(2)))
        assert sorted(results) == ["created", "limited"]
    finally:
        with Session(engine) as session:
            session.execute(delete(Subscription).where(Subscription.user_id == user_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_managed_domain_cap_is_global(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    monkeypatch.setattr(
        "blindport.services.catalog.settings.RELAY_MANAGED_DOMAIN_CAP",
        1,
    )
    marker = f"postgres-managed-domain-cap-{uuid4()}"
    with Session(engine) as session:
        users = [User(hashed_token=f"{marker}-{index}") for index in range(2)]
        session.add_all(users)
        session.commit()
        user_ids = [user.id for user in users]
    assert all(identifier is not None for identifier in user_ids)
    barrier = threading.Barrier(2)

    def create(index: int) -> str:
        with Session(engine) as session:
            user = session.get(User, user_ids[index])
            assert user is not None
            barrier.wait(timeout=10)
            try:
                create_subscription(
                    session,
                    user,
                    ProductType.RELAY,
                    domain=f"managed-{index}.relay.test",
                )
            except ProductUnavailableError:
                return "sold-out"
        return "created"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(create, range(2)))
        assert sorted(results) == ["created", "sold-out"]
    finally:
        with Session(engine) as session:
            session.execute(delete(Subscription).where(Subscription.user_id.in_(user_ids)))
            session.execute(delete(User).where(User.id.in_(user_ids)))
            session.commit()


def test_postgres_concurrent_open_payment_cap_is_per_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    monkeypatch.setattr("blindport.services.payments.settings.ACCOUNT_MAX_OPEN_PAYMENTS", 1)
    marker = f"postgres-payment-cap-{uuid4()}"
    now = datetime.now(UTC)
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscriptions = [
            Subscription(
                user_id=user.id,
                product=ProductType.RELAY,
                status=SubscriptionStatus.ACTIVE,
                domain=f"payment-{index}.relay.test",
                domain_is_managed=True,
                relay_pool_domain="relay1.test",
                monthly_price_sats=1,
                current_period_start=now,
                current_period_end=now + timedelta(days=1),
            )
            for index in range(2)
        ]
        session.add_all(subscriptions)
        session.commit()
        user_id = user.id
        subscription_ids = [subscription.id for subscription in subscriptions]
    assert user_id is not None
    assert all(identifier is not None for identifier in subscription_ids)
    barrier = threading.Barrier(2)

    def create(subscription_id: int) -> str:
        with Session(engine) as session:
            subscription = session.get(Subscription, subscription_id)
            assert subscription is not None
            barrier.wait(timeout=10)
            try:
                create_payment(session, subscription, PaymentMethod.LIGHTNING)
            except AccountLimitError:
                return "limited"
        return "created"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(create, subscription_ids))
        assert sorted(results) == ["created", "limited"]
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.subscription_id.in_(subscription_ids)))
            session.execute(delete(Subscription).where(Subscription.id.in_(subscription_ids)))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_tcp_and_udp_leases_can_share_ip_and_port() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-transport-identity-{uuid4()}"

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        tcp = Subscription(
            user_id=user.id,
            product=ProductType.PORT,
            assigned_ip="198.51.100.247",
            assigned_port=45679,
            transport=Transport.TCP,
            monthly_price_sats=1,
        )
        udp = Subscription(
            user_id=user.id,
            product=ProductType.PORT,
            assigned_ip="198.51.100.247",
            assigned_port=45679,
            transport=Transport.UDP,
            monthly_price_sats=1,
        )
        session.add_all([tcp, udp])
        session.commit()
        user_id = user.id

    try:
        with pytest.raises(RuntimeError, match="cannot downgrade while UDP subscriptions exist"):
            downgrade_database(engine, "0003")
        assert database_revisions(engine) == ("0019", "0019")

        with Session(engine) as session:
            rows = session.exec(select(Subscription).where(Subscription.user_id == user_id)).all()
            assert {row.transport for row in rows} == {Transport.TCP, Transport.UDP}
    finally:
        with Session(engine) as session:
            session.execute(delete(Subscription).where(Subscription.user_id == user_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_datetimes_preserve_instants_in_non_utc_session_timezone() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-timezone-{uuid4()}"
    active_deadline = datetime(
        2032, 1, 2, 3, 4, 5, tzinfo=timezone(-timedelta(hours=3, minutes=30))
    )
    reservation_deadline = datetime(
        2032, 6, 7, 8, 9, 10, tzinfo=timezone(timedelta(hours=9, minutes=30))
    )

    with Session(engine) as session:
        session.execute(text("SET TIME ZONE 'Pacific/Chatham'"))
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        active = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1,
            current_period_end=active_deadline,
        )
        reserved = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            monthly_price_sats=1,
            reservation_expires_at=reservation_deadline,
        )
        session.add_all([active, reserved])
        session.commit()
        active_id = active.id
        reserved_id = reserved.id

        session.execute(text("SET TIME ZONE 'Pacific/Chatham'"))
        loaded_active = session.get(Subscription, active_id)
        loaded_reserved = session.get(Subscription, reserved_id)
        assert loaded_active is not None
        assert loaded_reserved is not None
        assert loaded_active.current_period_end is not None
        assert loaded_reserved.reservation_expires_at is not None
        assert loaded_active.current_period_end.utcoffset() != timedelta(0)
        assert loaded_reserved.reservation_expires_at.utcoffset() != timedelta(0)
        assert loaded_active.current_period_end.astimezone(UTC) == active_deadline.astimezone(UTC)
        assert loaded_reserved.reservation_expires_at.astimezone(
            UTC
        ) == reservation_deadline.astimezone(UTC)

        session.delete(active)
        session.delete(reserved)
        session.delete(user)
        session.commit()


def test_postgres_concurrent_scarce_reservations_use_distinct_assignments() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-reservation-race-{uuid4()}"

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscriptions = [
            Subscription(
                user_id=user.id,
                product=ProductType.IP,
                monthly_price_sats=1,
            )
            for _ in range(2)
        ]
        session.add_all(subscriptions)
        session.flush()
        payments = [
            Payment(
                subscription_id=subscription.id,
                method=PaymentMethod.LIGHTNING,
                amount_sats=1,
            )
            for subscription in subscriptions
        ]
        session.add_all(payments)
        session.commit()
        user_id = user.id
        subscription_ids = [subscription.id for subscription in subscriptions]
        payment_ids = [payment.id for payment in payments]

    assert user_id is not None
    assert all(identifier is not None for identifier in subscription_ids)
    assert all(identifier is not None for identifier in payment_ids)
    barrier = threading.Barrier(2)

    def reserve(subscription_id: int, payment_id: int) -> tuple[str | None, bool]:
        with Session(engine) as session:
            subscription = session.get(Subscription, subscription_id)
            assert subscription is not None
            barrier.wait(timeout=10)
            assert reserve_subscription_resource(session, subscription, payment_id)
            outer_transaction_usable = session.execute(text("SELECT 1")).scalar_one() == 1
            assignment = subscription.assigned_ip
            session.commit()
            return assignment, outer_transaction_usable

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(reserve, subscription_id, payment_id)
                for subscription_id, payment_id in zip(subscription_ids, payment_ids, strict=True)
            ]
            results = [future.result(timeout=20) for future in futures]

        assert {assignment for assignment, _ in results} == {
            "203.0.113.10",
            "203.0.113.11",
        }
        assert all(outer_transaction_usable for _, outer_transaction_usable in results)
        with Session(engine) as session:
            leases = session.exec(
                select(IPLease).where(IPLease.subscription_id.in_(subscription_ids))  # type: ignore[union-attr]
            ).all()
            assert {lease.address for lease in leases} == {
                "203.0.113.10",
                "203.0.113.11",
            }
            assert all(lease.released_at is None for lease in leases)
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.subscription_id.in_(subscription_ids)))
            session.execute(delete(IPLease).where(IPLease.subscription_id.in_(subscription_ids)))
            session.execute(delete(Subscription).where(Subscription.id.in_(subscription_ids)))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_open_payments_allow_one_insert() -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-payment-race-{uuid4()}"

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.RELAY,
            monthly_price_sats=1,
        )
        session.add(subscription)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id

    assert user_id is not None
    assert subscription_id is not None
    barrier = threading.Barrier(2)

    def insert_open_payment() -> str:
        with Session(engine) as session:
            payment = Payment(
                subscription_id=subscription_id,
                method=PaymentMethod.LIGHTNING,
                status=PaymentStatus.PENDING,
                amount_sats=1,
            )
            session.add(payment)
            barrier.wait(timeout=10)
            try:
                session.commit()
            except IntegrityError as error:
                session.rollback()
                assert error.orig.sqlstate == "23505"
                return "uniqueness failure"
            return "success"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(insert_open_payment) for _ in range(2)]
            results = [future.result(timeout=20) for future in futures]

        assert sorted(results) == ["success", "uniqueness failure"]
        with Session(engine) as session:
            open_payments = session.exec(
                select(Payment).where(
                    Payment.subscription_id == subscription_id,
                    Payment.status.in_((PaymentStatus.PENDING, PaymentStatus.PROCESSING)),  # type: ignore[union-attr]
                )
            ).all()
            assert len(open_payments) == 1
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.subscription_id == subscription_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_cancel_and_payment_creation_have_one_winner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-cancel-payment-race-{uuid4()}"

    from blindport.adapters.mock import MockLightningAdapter
    from blindport.services import payments as payments_service

    monkeypatch.setattr(payments_service.settings, "RELAY_PUBLIC_IPS", "198.51.100.247")
    monkeypatch.setattr(
        payments_service,
        "get_lightning_adapter",
        lambda: MockLightningAdapter(),
    )
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            monthly_price_sats=1,
            yearly_price_sats=10,
        )
        session.add(subscription)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id

    assert user_id is not None
    assert subscription_id is not None
    barrier = threading.Barrier(2)

    def create() -> str:
        with Session(engine) as session:
            stored = session.get(Subscription, subscription_id)
            assert stored is not None
            barrier.wait(timeout=10)
            try:
                create_payment(session, stored, PaymentMethod.LIGHTNING)
            except ValueError as error:
                assert "cancelled subscription cannot be paid" in str(error)
                return "creation rejected"
            return "payment created"

    def cancel() -> str:
        with Session(engine) as session:
            stored = session.get(Subscription, subscription_id)
            assert stored is not None
            barrier.wait(timeout=10)
            try:
                cancel_pending_subscription(session, stored)
            except SubscriptionCancellationConflict:
                return "cancellation rejected"
            return "subscription cancelled"

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            creation = executor.submit(create)
            cancellation = executor.submit(cancel)
            result = (creation.result(timeout=20), cancellation.result(timeout=20))

        assert result in {
            ("creation rejected", "subscription cancelled"),
            ("payment created", "cancellation rejected"),
        }
        with Session(engine) as session:
            stored = session.get(Subscription, subscription_id)
            assert stored is not None
            payments = session.exec(
                select(Payment).where(Payment.subscription_id == subscription_id)
            ).all()
            if stored.status == SubscriptionStatus.CANCELLED:
                assert payments == []
            else:
                assert stored.status == SubscriptionStatus.PENDING
                assert len(payments) == 1
                assert payments[0].status == PaymentStatus.PENDING
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.subscription_id == subscription_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_identical_client_enrollment_returns_winner(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-client-enrollment-race-{uuid4()}"
    instance_id = str(uuid4())
    key = Ed25519PrivateKey.generate()
    csr_pem = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([]))
        .sign(key, None)
        .public_bytes(serialization.Encoding.PEM)
        .decode("ascii")
    )
    monkeypatch.setattr("blindport.core.ca.settings.CA_DIR", str(tmp_path / "ca"))

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.commit()
        user_id = user.id
        account_id = user.public_id
    assert user_id is not None

    def enroll(generation: int, barrier: threading.Barrier) -> tuple[int, str]:
        with Session(engine) as session:
            barrier.wait(timeout=10)
            result = enroll_client_certificate(
                session,
                user_id,
                account_id,
                instance_id,
                generation,
                csr_pem,
            )
            return result.generation, result.serial

    try:
        for generation in (1, 2):
            barrier = threading.Barrier(2)
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = [
                    future.result(timeout=20)
                    for future in [
                        executor.submit(enroll, generation, barrier),
                        executor.submit(enroll, generation, barrier),
                    ]
                ]
            assert results[0] == results[1]
            assert results[0][0] == generation
    finally:
        with Session(engine) as session:
            session.execute(delete(ClientCredential).where(ClientCredential.user_id == user_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_invoice_issuance_calls_provider_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-invoice-issuance-race-{uuid4()}"

    from blindport.adapters.base import LightningInvoice
    from blindport.services import payments as payments_service

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            monthly_price_sats=1,
        )
        session.add(subscription)
        session.flush()
        payment = Payment(
            subscription_id=subscription.id,
            method=PaymentMethod.LIGHTNING,
            amount_sats=1,
            invoice_idempotency_key=str(uuid4()),
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        payment.payment_hash = payments_service.hashlib.sha256(
            payments_service._invoice_preimage(payment)
        ).hexdigest()
        session.add(payment)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id
        payment_id = payment.id
        payment_hash = payment.payment_hash

    assert user_id is not None
    assert subscription_id is not None
    assert payment_id is not None
    assert payment_hash is not None

    provider_entered = threading.Event()
    release_provider = threading.Event()
    provider_calls = 0
    provider_lock = threading.Lock()

    class BlockingAdapter:
        def create_or_lookup_invoice(self, *args, **kwargs) -> LightningInvoice:
            nonlocal provider_calls
            with provider_lock:
                provider_calls += 1
            provider_entered.set()
            assert release_provider.wait(timeout=10)
            return LightningInvoice("lnbc1postgresdurable", payment_hash, 1, 300)

    monkeypatch.setattr(payments_service, "get_lightning_adapter", lambda: BlockingAdapter())

    def issue() -> str | None:
        with Session(engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            return ensure_lightning_invoice(session, stored).invoice

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            first = executor.submit(issue)
            assert provider_entered.wait(timeout=10)
            second = executor.submit(issue)
            release_provider.set()
            assert first.result(timeout=20) == "lnbc1postgresdurable"
            assert second.result(timeout=20) == "lnbc1postgresdurable"
        assert provider_calls == 1
    finally:
        release_provider.set()
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.id == payment_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_same_method_creation_returns_winning_payment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-payment-service-race-{uuid4()}"

    from blindport.adapters.mock import MockLightningAdapter
    from blindport.services import payments as payments_service

    now = datetime.now(UTC)
    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="198.51.100.248",
            monthly_price_sats=1,
            current_period_start=now,
            current_period_end=now + timedelta(days=5),
        )
        session.add(subscription)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id

    assert user_id is not None
    assert subscription_id is not None
    adapter = MockLightningAdapter()
    original_create = adapter.create_or_lookup_invoice
    provider_calls = 0
    provider_lock = threading.Lock()

    def counting_create(*args, **kwargs):
        nonlocal provider_calls
        with provider_lock:
            provider_calls += 1
        return original_create(*args, **kwargs)

    monkeypatch.setattr(adapter, "create_or_lookup_invoice", counting_create)
    monkeypatch.setattr(payments_service, "get_lightning_adapter", lambda: adapter)
    barrier = threading.Barrier(2)

    def create() -> int | None:
        with Session(engine) as session:
            stored_subscription = session.get(Subscription, subscription_id)
            assert stored_subscription is not None
            barrier.wait(timeout=10)
            return create_payment(session, stored_subscription, PaymentMethod.LIGHTNING).id

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [
                future.result(timeout=20) for future in [executor.submit(create) for _ in range(2)]
            ]
        assert results[0] is not None
        assert results[0] == results[1]
        assert provider_calls == 1
        with Session(engine) as session:
            stored_payments = session.exec(
                select(Payment).where(Payment.subscription_id == subscription_id)
            ).all()
            assert len(stored_payments) == 1
            assert stored_payments[0].invoice is not None
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.subscription_id == subscription_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_concurrent_settlement_renews_once(monkeypatch: pytest.MonkeyPatch) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-settlement-race-{uuid4()}"
    payment_hash = uuid4().hex
    period_end = datetime.now(UTC) + timedelta(days=5)

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            assigned_ip="198.51.100.250",
            monthly_price_sats=1,
            yearly_price_sats=10,
            current_period_start=datetime.now(UTC),
            current_period_end=period_end,
        )
        session.add(subscription)
        session.flush()
        session.add(
            IPLease(
                subscription_id=subscription.id,
                address=subscription.assigned_ip,
                delivery=IPLeaseDelivery.FRAMED,
                state=IPLeaseState.ACTIVE,
                reserved_at=subscription.current_period_start,
                activated_at=subscription.current_period_start,
            )
        )
        payment = Payment(
            subscription_id=subscription.id,
            method=PaymentMethod.LIGHTNING,
            billing_term=BillingTerm.YEARLY,
            period_days=365,
            amount_sats=10,
            invoice="lnbc1postgressettlement",
            payment_hash=payment_hash,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        session.add(payment)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id
        payment_id = payment.id

    assert user_id is not None
    assert subscription_id is not None
    assert payment_id is not None
    barrier = threading.Barrier(2)

    class SettledAdapter:
        def is_invoice_paid(self, checked_hash: str) -> bool:
            assert checked_hash == payment_hash
            barrier.wait(timeout=10)
            return True

    monkeypatch.setattr(
        "blindport.services.payments.get_lightning_adapter",
        lambda: SettledAdapter(),
    )

    def settle() -> PaymentStatus:
        with Session(engine) as session:
            stored = session.get(Payment, payment_id)
            assert stored is not None
            return check_and_settle_payment(session, stored).status

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = [
                future.result(timeout=20) for future in [executor.submit(settle) for _ in range(2)]
            ]

        assert results == [PaymentStatus.PAID, PaymentStatus.PAID]
        with Session(engine) as session:
            stored_subscription = session.get(Subscription, subscription_id)
            assert stored_subscription is not None
            assert stored_subscription.current_period_end == period_end + timedelta(days=365)
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.id == payment_id))
            session.execute(delete(IPLease).where(IPLease.subscription_id == subscription_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()


def test_postgres_elapsed_quarantine_settles_renewal_before_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_URL is not None
    engine = create_engine(POSTGRES_URL, pool_pre_ping=True)
    upgrade_database(engine)
    marker = f"postgres-quarantine-renewal-{uuid4()}"
    payment_hash = uuid4().hex
    now = datetime.now(UTC)

    with Session(engine) as session:
        user = User(hashed_token=marker)
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.PORT,
            status=SubscriptionStatus.EXPIRED,
            assigned_ip="198.51.100.249",
            assigned_port=45678,
            monthly_price_sats=1,
            current_period_end=now - timedelta(seconds=1),
            resource_quarantined_until=now - timedelta(seconds=1),
        )
        session.add(subscription)
        session.flush()
        payment = Payment(
            subscription_id=subscription.id,
            method=PaymentMethod.LIGHTNING,
            amount_sats=1,
            invoice="lnbc1postgresquarantinerenewal",
            payment_hash=payment_hash,
            created_at=now - timedelta(seconds=10),
            expires_at=now + timedelta(minutes=5),
        )
        session.add(payment)
        session.commit()
        user_id = user.id
        subscription_id = subscription.id
        payment_id = payment.id

    assert user_id is not None
    assert subscription_id is not None
    assert payment_id is not None

    class SettledAdapter:
        def is_invoice_paid(self, checked_hash: str) -> bool:
            assert checked_hash == payment_hash
            return True

    monkeypatch.setattr(
        "blindport.services.payments.get_lightning_adapter",
        lambda: SettledAdapter(),
    )

    try:
        with Session(engine) as session:
            reap_elapsed_resource_holds(session)
            stored_subscription = session.get(Subscription, subscription_id)
            stored_payment = session.get(Payment, payment_id)
            assert stored_subscription is not None
            assert stored_payment is not None
            assert stored_payment.status == PaymentStatus.PAID
            assert stored_subscription.status == SubscriptionStatus.ACTIVE
            assert stored_subscription.assigned_ip == "198.51.100.249"
            assert stored_subscription.assigned_port == 45678
            assert stored_subscription.resource_quarantined_until is None
    finally:
        with Session(engine) as session:
            session.execute(delete(Payment).where(Payment.id == payment_id))
            session.execute(delete(Subscription).where(Subscription.id == subscription_id))
            session.execute(delete(User).where(User.id == user_id))
            session.commit()
