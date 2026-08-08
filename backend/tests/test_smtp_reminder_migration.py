"""Fresh and deployed-schema SMTP reminder migrations."""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from sqlalchemy import create_engine, inspect, text

from blindport.migrations import database_revisions, upgrade_database

_GENERIC_COLUMNS = {
    "id",
    "subscription_id",
    "current_period_end",
    "recipient_generation",
    "kind",
    "state",
    "attempt_count",
    "error_code",
    "created_at",
    "updated_at",
    "last_attempt_at",
    "next_attempt_at",
    "sent_at",
    "terminal_at",
    "lease_token",
    "lease_until",
}


def test_fresh_sqlite_chain_creates_generic_outbox(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'fresh.db'}")
    upgrade_database(engine)
    inspector = inspect(engine)
    assert database_revisions(engine) == ("0018", "0018")
    assert {
        column["name"] for column in inspector.get_columns("reminderdelivery")
    } == _GENERIC_COLUMNS
    assert {index["name"] for index in inspector.get_indexes("reminderdelivery")} == {
        "ix_reminderdelivery_due",
        "ix_reminderdelivery_subscription_id",
    }


def test_deployed_0012_sqlite_rows_are_preserved_scrubbed_and_not_replayed(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    upgrade_database(engine, "0010")
    _install_legacy_0012_reminders(engine)

    upgrade_database(engine)

    assert database_revisions(engine) == ("0018", "0018")
    columns = {column["name"] for column in inspect(engine).get_columns("reminderdelivery")}
    assert columns == _GENERIC_COLUMNS
    with engine.connect() as connection:
        rows = (
            connection.execute(
                text(
                    "SELECT id, state, error_code, sent_at, terminal_at "
                    "FROM reminderdelivery ORDER BY id"
                )
            )
            .mappings()
            .all()
        )
        user = connection.execute(
            text(
                "SELECT reminder_email_ciphertext, reminder_email_key_version "
                'FROM "user" WHERE id = 1'
            )
        ).one()
        legacy_admin = connection.execute(
            text('SELECT is_admin, is_suspended FROM "user" WHERE hashed_token = :token'),
            {"token": "legacy-admin"},
        ).one()
    assert rows[0]["state"] == "sent"
    assert rows[0]["sent_at"] is not None
    assert rows[1]["state"] == "cancelled"
    assert rows[1]["error_code"] == "legacy_delivery_cancelled"
    assert all(row["terminal_at"] is not None for row in rows)
    assert user == ("v1.encrypted-recipient", "key-version")
    assert legacy_admin == (True, True)


def _install_legacy_0012_reminders(engine) -> None:
    metadata = sa.MetaData()
    user = sa.Table("user", metadata, autoload_with=engine)
    subscription = sa.Table("subscription", metadata, autoload_with=engine)
    now = datetime.now(UTC)
    with engine.begin() as connection:
        connection.execute(
            text('ALTER TABLE "user" ADD COLUMN has_reminder_email BOOLEAN NOT NULL DEFAULT 0')
        )
        connection.execute(text('ALTER TABLE "user" ADD COLUMN reminder_email_ciphertext TEXT'))
        connection.execute(
            text('ALTER TABLE "user" ADD COLUMN reminder_email_key_version VARCHAR(32)')
        )
        connection.execute(
            text(
                'ALTER TABLE "user" ADD COLUMN reminder_email_generation INTEGER NOT NULL DEFAULT 0'
            )
        )
    legacy = sa.Table(
        "reminderdelivery",
        sa.MetaData(),
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("subscription_id", sa.Integer, nullable=False),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("recipient_generation", sa.Integer, nullable=False),
        sa.Column("kind", sa.String, nullable=False),
        sa.Column("state", sa.String, nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False),
        sa.Column("invoice_ciphertext", sa.Text),
        sa.Column("invoice_key_version", sa.String(32)),
        sa.Column("payment_hash", sa.String(64)),
        sa.Column("price_sats", sa.Integer),
        sa.Column("provider", sa.String(64)),
        sa.Column("provider_payment_status", sa.String(32)),
        sa.Column("provider_delivery_status", sa.String(32)),
        sa.Column("nwc_state", sa.String(32)),
        sa.Column("nwc_preimage_hash", sa.String(64)),
        sa.Column("nwc_retry_blocked", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True)),
        sa.Column("invoice_created_at", sa.DateTime(timezone=True)),
        sa.Column("paid_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("terminal_at", sa.DateTime(timezone=True)),
        sa.Column("lease_token", sa.String(32)),
        sa.Column("lease_until", sa.DateTime(timezone=True)),
        sa.UniqueConstraint(
            "subscription_id",
            "current_period_end",
            "kind",
            name="uq_reminderdelivery_subscription_period_kind",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 20",
            name="ck_reminderdelivery_attempt_count",
        ),
    )
    legacy.create(engine)
    sa.Index("ix_reminderdelivery_subscription_id", legacy.c.subscription_id).create(engine)
    sa.Index(
        "ix_reminderdelivery_due", legacy.c.state, legacy.c.next_attempt_at, legacy.c.id
    ).create(engine)
    sa.Index(
        "uq_reminderdelivery_payment_hash",
        legacy.c.payment_hash,
        unique=True,
        sqlite_where=legacy.c.payment_hash.is_not(None),
    ).create(engine)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="legacy", is_admin=False, is_suspended=False, created_at=now
            )
        ).inserted_primary_key[0]
        connection.execute(
            user.insert().values(
                hashed_token="legacy-admin",
                is_admin=True,
                is_suspended=False,
                created_at=now,
            )
        )
        connection.execute(
            text(
                'UPDATE "user" SET has_reminder_email = 1, '
                "reminder_email_ciphertext = 'v1.encrypted-recipient', "
                "reminder_email_key_version = 'key-version', reminder_email_generation = 1 "
                "WHERE id = :id"
            ),
            {"id": user_id},
        )
        subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="ip",
                delivery="FRAMED",
                status="ACTIVE",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                yearly_price_sats=10000,
                billing_term="monthly",
                auto_renew=False,
                created_at=now,
                updated_at=now,
                current_period_end=now,
            )
        ).inserted_primary_key[0]
        connection.execute(
            legacy.insert().values(
                id=1,
                subscription_id=subscription_id,
                current_period_end=now,
                recipient_generation=1,
                kind="7_day",
                state="delivered",
                attempt_count=3,
                created_at=now,
                updated_at=now,
                delivered_at=now,
            )
        )
        connection.execute(
            legacy.insert().values(
                id=2,
                subscription_id=subscription_id,
                current_period_end=now,
                recipient_generation=1,
                kind="1_day",
                state="awaiting_delivery",
                attempt_count=2,
                created_at=now,
                updated_at=now,
                payment_hash="ab" * 32,
                provider="legacy",
            )
        )
        connection.execute(text("UPDATE alembic_version SET version_num = '0012'"))
