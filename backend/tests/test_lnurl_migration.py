"""LNURL and referral migration regression tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import MetaData, Table, create_engine, select
from sqlalchemy.engine import Engine
from sqlmodel import SQLModel

from blindport.core import models  # noqa: F401
from blindport.migrations import database_revisions, downgrade_database, upgrade_database


def _sqlite_engine(tmp_path) -> Engine:
    return create_engine(f"sqlite:///{tmp_path / 'lnurl-migration.db'}")


def _insert_legacy_payment(
    engine: Engine,
    *,
    marker: str,
    status: str,
    invoice: str,
    payment_hash: str,
) -> tuple[int, int]:
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)

    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                public_id=uuid4().hex,
                hashed_token=marker,
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
                public_id=uuid4().hex,
                user_id=user_id,
                product="ip",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                billing_term="monthly",
                monthly_price_sats=1000,
                yearly_price_sats=10000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        payment_id = connection.execute(
            payment.insert().values(
                subscription_id=subscription_id,
                method="LIGHTNING",
                status=status,
                billing_term="monthly",
                period_days=30,
                amount_sats=1000,
                invoice=invoice,
                payment_hash=payment_hash,
                created_at=created_at,
                paid_at=created_at if status == "PAID" else None,
            )
        ).inserted_primary_key[0]

    return subscription_id, payment_id


def test_0033_preserves_legacy_invoices_and_defaults_rolling_inserts(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0032")
    pending_subscription_id, pending_payment_id = _insert_legacy_payment(
        engine,
        marker="lnurl-legacy-pending",
        status="PENDING",
        invoice="lnbc1000legacy-pending",
        payment_hash="01" * 32,
    )
    paid_subscription_id, paid_payment_id = _insert_legacy_payment(
        engine,
        marker="lnurl-legacy-paid",
        status="PAID",
        invoice="lnbc1000legacy-paid",
        payment_hash="02" * 32,
    )

    upgrade_database(engine)

    assert database_revisions(engine) == ("0033", "0033")
    metadata = MetaData()
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    referral_credit = Table("referralcredit", metadata, autoload_with=engine)
    referral_payout = Table("referralpayout", metadata, autoload_with=engine)
    with engine.connect() as connection:
        payments = {
            row.id: row
            for row in connection.execute(
                select(payment).where(payment.c.id.in_((pending_payment_id, paid_payment_id)))
            )
        }
        subscriptions = {
            row.id: row
            for row in connection.execute(
                select(subscription).where(
                    subscription.c.id.in_((pending_subscription_id, paid_subscription_id))
                )
            )
        }
        assert connection.execute(select(referral_credit)).all() == []
        assert connection.execute(select(referral_payout)).all() == []

    assert [
        (
            payments[payment_id].status,
            payments[payment_id].invoice,
            payments[payment_id].payment_hash,
        )
        for payment_id in (pending_payment_id, paid_payment_id)
    ] == [
        ("PENDING", "lnbc1000legacy-pending", "01" * 32),
        ("PAID", "lnbc1000legacy-paid", "02" * 32),
    ]
    for payment_id in (pending_payment_id, paid_payment_id):
        payment_row = payments[payment_id]
        assert (
            payment_row.invoice_provider,
            payment_row.lnurl_attempted_at,
            payment_row.lnurl_last_checked_at,
            payment_row.settlement_review_required,
            payment_row.referral_address,
            payment_row.referral_commission_bps,
        ) == (None, None, None, False, None, 0)
    assert all(
        subscriptions[subscription_id].referral_address is None
        for subscription_id in (
            pending_subscription_id,
            paid_subscription_id,
        )
    )

    rolling_subscription_id, rolling_payment_id = _insert_legacy_payment(
        engine,
        marker="lnurl-rolling-legacy-insert",
        status="PENDING",
        invoice="lnbc1000rolling",
        payment_hash="03" * 32,
    )
    with engine.connect() as connection:
        rolling_subscription = connection.execute(
            select(subscription).where(subscription.c.id == rolling_subscription_id)
        ).one()
        rolling_payment = connection.execute(
            select(payment).where(payment.c.id == rolling_payment_id)
        ).one()
    assert rolling_subscription.referral_address is None
    assert (
        rolling_payment.invoice_provider,
        rolling_payment.lnurl_attempted_at,
        rolling_payment.lnurl_last_checked_at,
        rolling_payment.settlement_review_required,
        rolling_payment.referral_address,
        rolling_payment.referral_commission_bps,
    ) == (None, None, None, False, None, 0)


@pytest.fixture
def upgraded_0033_legacy_payment(tmp_path) -> tuple[Engine, int, int]:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0032")
    subscription_id, payment_id = _insert_legacy_payment(
        engine,
        marker="lnurl-downgrade-guard",
        status="PENDING",
        invoice="lnbc1000downgrade",
        payment_hash="04" * 32,
    )
    upgrade_database(engine)
    return engine, subscription_id, payment_id


@pytest.mark.parametrize(
    "blocker",
    ("lnurl-invoice", "referral-credit", "referral-payout", "subscription-attribution"),
)
def test_0033_rejects_downgrade_when_lnurl_or_referral_data_exists(
    upgraded_0033_legacy_payment: tuple[Engine, int, int], blocker: str
) -> None:
    engine, subscription_id, payment_id = upgraded_0033_legacy_payment
    metadata = MetaData()
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    referral_credit = Table("referralcredit", metadata, autoload_with=engine)
    referral_payout = Table("referralpayout", metadata, autoload_with=engine)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    with engine.begin() as connection:
        if blocker == "lnurl-invoice":
            connection.execute(
                payment.update()
                .where(payment.c.id == payment_id)
                .values(invoice_provider="lnurl", lnurl_attempted_at=now)
            )
        elif blocker == "referral-credit":
            connection.execute(
                referral_credit.insert().values(
                    payment_id=payment_id,
                    address="referrer@example.com",
                    amount_sats=100,
                    created_at=now,
                )
            )
        elif blocker == "referral-payout":
            connection.execute(
                referral_payout.insert().values(
                    id=uuid4().hex,
                    address="referrer@example.com",
                    amount_sats=10000,
                    status="reserved",
                    created_at=now,
                )
            )
        else:
            connection.execute(
                subscription.update()
                .where(subscription.c.id == subscription_id)
                .values(referral_address="referrer@example.com")
            )

    with pytest.raises(
        RuntimeError, match="cannot downgrade while LNURL or referral records exist"
    ):
        downgrade_database(engine, "0032")
    assert database_revisions(engine) == ("0033", "0033")


def test_0033_fresh_schema_matches_orm_metadata(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    assert database_revisions(engine) == ("0033", "0033")
    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, SQLModel.metadata) == []
