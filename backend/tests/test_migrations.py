"""Schema migration and SQLModel metadata consistency tests."""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import DateTime, MetaData, Table, create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, SQLModel

import blindport.migrations as migrations
from blindport.core import models  # noqa: F401
from blindport.migrations import (
    DatabaseRevisionError,
    cli,
    database_revisions,
    downgrade_database,
    upgrade_database,
    verify_database_current,
)

EXPECTED_COLUMNS = {
    "dnsobservation": {
        "hostname",
        "expected_ips",
        "observed_ips",
        "healthy",
        "resolver_count",
        "successful_resolvers",
        "error_code",
        "checked_at",
    },
    "relayheartbeat": {
        "edge_id",
        "ready",
        "authorization",
        "certificate",
        "lifecycle",
        "listeners",
        "wireguard",
        "active_tunnels",
        "active_streams",
        "accepted_connections_total",
        "forwarded_bytes_total",
        "received_at",
    },
    "relaysubscriptionconnection": {
        "edge_id",
        "subscription_id",
        "active",
        "observed_at",
        "last_connected_at",
    },
    "subscriptiondailybandwidth": {
        "subscription_id",
        "day",
        "ingress_bytes",
        "egress_bytes",
    },
    "relaybandwidthcursor": {
        "edge_id",
        "boot_id",
        "subscription_id",
        "day",
        "sequence",
        "ingress_bytes",
        "egress_bytes",
    },
    "announcement": {
        "id",
        "state",
        "subject",
        "body",
        "author_marker",
        "recipient_count",
        "recipient_cursor",
        "recipient_max_user_id",
        "expansion_complete",
        "created_at",
        "queued_at",
        "completed_at",
        "cancelled_at",
    },
    "announcementdelivery": {
        "id",
        "announcement_id",
        "user_id",
        "recipient_generation",
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
    },
    "announcementrecipientsnapshot": {
        "announcement_id",
        "user_id",
        "recipient_generation",
    },
    "iplease": {
        "id",
        "public_id",
        "subscription_id",
        "reservation_payment_id",
        "address",
        "delivery",
        "state",
        "reserved_at",
        "activated_at",
        "expired_at",
        "quarantined_at",
        "quarantine_until",
        "released_at",
        "release_reason",
        "imported",
        "smtp_enabled",
        "smtp_intended_use",
        "smtp_fee_paid_sats",
        "smtp_reviewed_at",
        "smtp_reviewed_by",
        "smtp_review_reference",
        "smtp_revoked_at",
        "smtp_revocation_reason",
        "created_at",
        "updated_at",
    },
    "agentorder": {
        "id",
        "user_id",
        "order_key",
        "subscription_id",
        "product",
        "billing_term",
        "delivery",
        "transport",
        "domain",
        "relay_hostname_scope",
        "created_at",
        "updated_at",
    },
    "ratelimitbucket": {
        "id",
        "scope",
        "identifier_hash",
        "window_start",
        "request_count",
        "expires_at",
    },
    "ratelimitmaintenance": {
        "name",
        "next_cleanup_at",
        "bucket_count",
    },
    "wireguardpeer": {
        "user_id",
        "instance_id",
        "public_key",
        "generation",
        "created_at",
        "updated_at",
    },
    "clientcredential": {
        "user_id",
        "instance_id",
        "public_key_fingerprint",
        "generation",
        "client_cert_pem",
        "serial",
        "not_before",
        "not_after",
        "renew_after",
        "created_at",
        "updated_at",
    },
    "user": {
        "id",
        "public_id",
        "display_token",
        "hashed_token",
        "is_admin",
        "is_suspended",
        "created_at",
        "last_seen_at",
        "nwc_uri",
        "has_nwc",
        "nwc_ciphertext",
        "nwc_key_version",
        "nwc_generation",
        "nwc_capabilities",
        "nwc_last_validated_at",
        "has_notification_email",
        "notification_email_ciphertext",
        "notification_email_key_version",
        "notification_email_generation",
    },
    "subscription": {
        "id",
        "public_id",
        "user_id",
        "product",
        "delivery",
        "status",
        "assigned_ip",
        "assigned_port",
        "transport",
        "domain",
        "relay_hostname_scope",
        "relay_pool_domain",
        "domain_is_managed",
        "domain_verification_token",
        "domain_verified_at",
        "domain_claim_expires_at",
        "domain_renewal_grace_expires_at",
        "reservation_expires_at",
        "reservation_payment_id",
        "resource_quarantined_until",
        "billing_term",
        "monthly_price_sats",
        "yearly_price_sats",
        "current_period_start",
        "current_period_end",
        "auto_renew",
        "created_at",
        "updated_at",
    },
    "payment": {
        "id",
        "subscription_id",
        "agent_order_id",
        "method",
        "status",
        "billing_term",
        "period_days",
        "amount_sats",
        "markup_sats",
        "invoice",
        "payment_hash",
        "invoice_idempotency_key",
        "cashu_token",
        "nwc_request_id",
        "nwc_state",
        "nwc_attempt_count",
        "nwc_first_attempt_at",
        "nwc_last_attempt_at",
        "nwc_next_attempt_at",
        "nwc_last_lookup_at",
        "nwc_lease_until",
        "nwc_lease_token",
        "nwc_error_code",
        "nwc_preimage_hash",
        "nwc_fees_paid_msats",
        "nwc_credential_generation",
        "stablecoin_provider",
        "stablecoin_checkout_origin",
        "stablecoin_asset",
        "created_at",
        "paid_at",
        "expires_at",
    },
    "reminderdelivery": {
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
    },
    "notificationdelivery": {
        "id",
        "user_id",
        "subscription_id",
        "payment_id",
        "announcement_id",
        "category",
        "kind",
        "idempotency_key",
        "recipient_generation",
        "event_at",
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
    },
    "passkeycredential": {
        "id",
        "user_id",
        "credential_id",
        "credential_public_key",
        "sign_count",
        "name",
        "transports_json",
        "device_type",
        "backed_up",
        "created_at",
        "updated_at",
        "last_used_at",
    },
    "webauthnchallenge": {
        "id",
        "challenge",
        "ceremony_type",
        "user_id",
        "binding_hash",
        "expires_at",
        "created_at",
    },
    "browsersession": {
        "id",
        "user_id",
        "token_hash",
        "csrf_token_hash",
        "auth_method",
        "created_at",
        "expires_at",
        "last_seen_at",
    },
}

EXPECTED_DATETIME_COLUMNS = {
    ("dnsobservation", "checked_at"),
    ("relayheartbeat", "received_at"),
    ("relaysubscriptionconnection", "observed_at"),
    ("relaysubscriptionconnection", "last_connected_at"),
    ("announcement", "created_at"),
    ("announcement", "queued_at"),
    ("announcement", "completed_at"),
    ("announcement", "cancelled_at"),
    ("announcementdelivery", "created_at"),
    ("announcementdelivery", "updated_at"),
    ("announcementdelivery", "last_attempt_at"),
    ("announcementdelivery", "next_attempt_at"),
    ("announcementdelivery", "sent_at"),
    ("announcementdelivery", "terminal_at"),
    ("announcementdelivery", "lease_until"),
    ("iplease", "reserved_at"),
    ("iplease", "activated_at"),
    ("iplease", "expired_at"),
    ("iplease", "quarantined_at"),
    ("iplease", "quarantine_until"),
    ("iplease", "released_at"),
    ("iplease", "smtp_reviewed_at"),
    ("iplease", "smtp_revoked_at"),
    ("iplease", "created_at"),
    ("iplease", "updated_at"),
    ("agentorder", "created_at"),
    ("agentorder", "updated_at"),
    ("ratelimitbucket", "window_start"),
    ("ratelimitbucket", "expires_at"),
    ("ratelimitmaintenance", "next_cleanup_at"),
    ("wireguardpeer", "created_at"),
    ("wireguardpeer", "updated_at"),
    ("clientcredential", "not_before"),
    ("clientcredential", "not_after"),
    ("clientcredential", "renew_after"),
    ("clientcredential", "created_at"),
    ("clientcredential", "updated_at"),
    ("user", "created_at"),
    ("user", "last_seen_at"),
    ("user", "nwc_last_validated_at"),
    ("subscription", "domain_verified_at"),
    ("subscription", "domain_claim_expires_at"),
    ("subscription", "domain_renewal_grace_expires_at"),
    ("subscription", "reservation_expires_at"),
    ("subscription", "resource_quarantined_until"),
    ("subscription", "current_period_start"),
    ("subscription", "current_period_end"),
    ("subscription", "created_at"),
    ("subscription", "updated_at"),
    ("payment", "created_at"),
    ("payment", "paid_at"),
    ("payment", "expires_at"),
    ("payment", "nwc_first_attempt_at"),
    ("payment", "nwc_last_attempt_at"),
    ("payment", "nwc_next_attempt_at"),
    ("payment", "nwc_last_lookup_at"),
    ("payment", "nwc_lease_until"),
    ("reminderdelivery", "current_period_end"),
    ("reminderdelivery", "created_at"),
    ("reminderdelivery", "updated_at"),
    ("reminderdelivery", "last_attempt_at"),
    ("reminderdelivery", "next_attempt_at"),
    ("reminderdelivery", "sent_at"),
    ("reminderdelivery", "terminal_at"),
    ("reminderdelivery", "lease_until"),
    ("notificationdelivery", "event_at"),
    ("notificationdelivery", "created_at"),
    ("notificationdelivery", "updated_at"),
    ("notificationdelivery", "last_attempt_at"),
    ("notificationdelivery", "next_attempt_at"),
    ("notificationdelivery", "sent_at"),
    ("notificationdelivery", "terminal_at"),
    ("notificationdelivery", "lease_until"),
    ("passkeycredential", "created_at"),
    ("passkeycredential", "updated_at"),
    ("passkeycredential", "last_used_at"),
    ("webauthnchallenge", "expires_at"),
    ("webauthnchallenge", "created_at"),
    ("browsersession", "created_at"),
    ("browsersession", "expires_at"),
    ("browsersession", "last_seen_at"),
}


def _sqlite_engine(tmp_path):
    return create_engine(f"sqlite:///{tmp_path / 'migration.db'}")


def test_fresh_sqlite_upgrade_current_and_schema(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    assert database_revisions(engine) == ("0026", "0026")
    verify_database_current(engine)

    inspector = inspect(engine)
    assert set(inspector.get_table_names()) == {
        "alembic_version",
        "announcement",
        "announcementdelivery",
        "announcementrecipientsnapshot",
        "agentorder",
        "clientcredential",
        "dnsobservation",
        "iplease",
        "payment",
        "ratelimitbucket",
        "ratelimitmaintenance",
        "relayheartbeat",
        "relaysubscriptionconnection",
        "relaybandwidthcursor",
        "reminderdelivery",
        "notificationdelivery",
        "passkeycredential",
        "webauthnchallenge",
        "browsersession",
        "subscription",
        "subscriptiondailybandwidth",
        "user",
        "wireguardpeer",
    }
    for table, expected in EXPECTED_COLUMNS.items():
        assert {column["name"] for column in inspector.get_columns(table)} == expected
    assert {index["name"] for index in inspector.get_indexes("user")} == {
        "ix_user_hashed_token",
        "ix_user_public_id",
    }
    assert {index["name"] for index in inspector.get_indexes("subscription")} == {
        "ix_subscription_public_id",
        "ix_subscription_reservation_payment_id",
        "ix_subscription_user_id",
        "ix_subscription_relay_hostname_scope_domain",
        "uq_subscription_dedicated_ip",
    }
    assert {index["name"] for index in inspector.get_indexes("payment")} == {
        "ix_payment_subscription_id",
        "uq_payment_agent_order_id",
        "uq_payment_open_subscription",
        "uq_payment_invoice_idempotency_key",
        "uq_payment_payment_hash",
    }
    assert {index["name"] for index in inspector.get_indexes("iplease")} == {
        "ix_iplease_public_id",
        "ix_iplease_reservation_payment_id",
        "ix_iplease_subscription_created",
        "uq_iplease_unreleased_address",
        "uq_iplease_unreleased_subscription",
    }
    assert {index["name"] for index in inspector.get_indexes("agentorder")} == {
        "ix_agentorder_user_id"
    }
    assert {index["name"] for index in inspector.get_indexes("relayheartbeat")} == {
        "ix_relayheartbeat_received_at"
    }
    assert {index["name"] for index in inspector.get_indexes("relaysubscriptionconnection")} == {
        "ix_relaysubscriptionconnection_subscription_id"
    }
    assert {index["name"] for index in inspector.get_indexes("dnsobservation")} == {
        "ix_dnsobservation_checked_at"
    }
    assert {
        constraint["name"] for constraint in inspector.get_unique_constraints("agentorder")
    } == {None, "uq_agentorder_user_order_key"}
    assert {index["name"] for index in inspector.get_indexes("ratelimitbucket")} == {
        "ix_ratelimitbucket_expires_at_id"
    }
    assert {index["name"] for index in inspector.get_indexes("reminderdelivery")} == {
        "ix_reminderdelivery_due",
        "ix_reminderdelivery_subscription_id",
    }
    assert {index["name"] for index in inspector.get_indexes("announcementdelivery")} == {
        "ix_announcementdelivery_announcement_id",
        "ix_announcementdelivery_due",
        "ix_announcementdelivery_user_id",
    }
    assert {index["name"] for index in inspector.get_indexes("notificationdelivery")} == {
        "ix_notificationdelivery_announcement_id",
        "ix_notificationdelivery_announcement_state",
        "ix_notificationdelivery_due",
        "ix_notificationdelivery_payment_id",
        "ix_notificationdelivery_subscription_id",
        "ix_notificationdelivery_user_id",
    }
    assert {index["name"] for index in inspector.get_indexes("passkeycredential")} == {
        "ix_passkeycredential_credential_id",
        "ix_passkeycredential_user_id",
    }
    assert {index["name"] for index in inspector.get_indexes("webauthnchallenge")} == {
        "ix_webauthnchallenge_expires_at",
        "ix_webauthnchallenge_user_id",
    }
    assert {index["name"] for index in inspector.get_indexes("browsersession")} == {
        "ix_browsersession_expires_at",
        "ix_browsersession_token_hash",
        "ix_browsersession_user_id",
    }
    assert {
        constraint["name"] for constraint in inspector.get_unique_constraints("ratelimitbucket")
    } == {"uq_ratelimitbucket_scope_identifier_window"}
    with engine.connect() as connection:
        assert (
            connection.execute(text('SELECT COUNT(*) FROM "user" WHERE is_admin = 1')).scalar_one()
            == 0
        )
    subscription_foreign_keys = inspector.get_foreign_keys("subscription")
    assert [fk["referred_table"] for fk in subscription_foreign_keys] == ["user"]
    assert {fk["referred_table"] for fk in inspector.get_foreign_keys("payment")} == {
        "agentorder",
        "subscription",
    }
    assert {fk["referred_table"] for fk in inspector.get_foreign_keys("agentorder")} == {
        "subscription",
        "user",
    }
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("reminderdelivery")] == [
        "subscription"
    ]
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("clientcredential")] == [
        "user"
    ]
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("iplease")] == [
        "subscription"
    ]
    assert {fk["referred_table"] for fk in inspector.get_foreign_keys("announcementdelivery")} == {
        "announcement",
        "user",
    }
    assert {
        fk["referred_table"] for fk in inspector.get_foreign_keys("announcementrecipientsnapshot")
    } == {"announcement", "user"}
    assert tuple(
        inspector.get_pk_constraint("announcementrecipientsnapshot")["constrained_columns"]
    ) == ("announcement_id", "user_id")
    assert {fk["referred_table"] for fk in inspector.get_foreign_keys("notificationdelivery")} == {
        "announcement",
        "payment",
        "subscription",
        "user",
    }
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("passkeycredential")] == [
        "user"
    ]
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("webauthnchallenge")] == [
        "user"
    ]
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("browsersession")] == ["user"]
    assert {
        constraint["name"] for constraint in inspector.get_unique_constraints("clientcredential")
    } == {"uq_clientcredential_instance_id"}


def test_0013_suspends_legacy_admin_rows_without_demoting_them(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0012")
    user = Table("user", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        admin_id = connection.execute(
            user.insert().values(
                hashed_token="legacy-admin",
                is_admin=True,
                is_suspended=False,
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)

    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(select(upgraded_user).where(upgraded_user.c.id == admin_id)).one()
    assert row.is_admin is True
    assert row.is_suspended is True


def test_0014_upgrades_deployed_0013_subscription_identity(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0013")
    with engine.begin() as connection:
        connection.execute(text("DROP INDEX ix_subscription_public_id"))
        connection.execute(text("ALTER TABLE subscription DROP COLUMN public_id"))

    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="subscription-public-id-backfill",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        for product in ("ip", "relay"):
            connection.execute(
                subscription.insert().values(
                    user_id=user_id,
                    product=product,
                    delivery="FRAMED",
                    status="PENDING",
                    transport="TCP",
                    domain_is_managed=False,
                    monthly_price_sats=1000,
                    auto_renew=False,
                    created_at=created_at,
                    updated_at=created_at,
                )
            )

    upgrade_database(engine)
    upgraded = Table("subscription", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        rows = connection.execute(select(upgraded)).all()
        inserted_pk = connection.execute(
            upgraded.insert().values(
                user_id=user_id,
                product="port",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
    public_ids = [UUID(str(row.public_id)) for row in rows]
    assert len(set(public_ids)) == 2
    assert all(public_id.version == 4 for public_id in public_ids)

    with engine.connect() as connection:
        inserted_public_id = connection.execute(
            select(upgraded.c.public_id).where(upgraded.c.id == inserted_pk)
        ).scalar_one()
    assert UUID(str(inserted_public_id)).version == 4
    with (
        pytest.raises(IntegrityError, match="public_id is immutable"),
        engine.begin() as connection,
    ):
        connection.execute(
            upgraded.update().where(upgraded.c.id == inserted_pk).values(public_id=uuid4().hex)
        )

    original_public_ids = {row.id: str(row.public_id) for row in rows}
    downgrade_database(engine, "0013")
    assert database_revisions(engine) == ("0013", "0026")
    downgraded = Table("subscription", MetaData(), autoload_with=engine)
    assert "public_id" in downgraded.c
    assert any(
        index["name"] == "ix_subscription_public_id" and index["unique"]
        for index in inspect(engine).get_indexes("subscription")
    )
    with engine.begin() as connection:
        downgraded_pk = connection.execute(
            downgraded.insert().values(
                user_id=user_id,
                product="port",
                delivery="FRAMED",
                status="PENDING",
                transport="UDP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)
    reupgraded = Table("subscription", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        reupgraded_rows = connection.execute(select(reupgraded)).all()
    reupgraded_by_pk = {row.id: str(row.public_id) for row in reupgraded_rows}
    assert all(reupgraded_by_pk[row_id] == value for row_id, value in original_public_ids.items())
    assert UUID(reupgraded_by_pk[downgraded_pk]).version == 4
    with (
        pytest.raises(IntegrityError, match="public_id is immutable"),
        engine.begin() as connection,
    ):
        connection.execute(
            reupgraded.update()
            .where(reupgraded.c.id == downgraded_pk)
            .values(public_id=uuid4().hex)
        )


def test_0010_revokes_plaintext_and_preserves_unmapped_rolling_column(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0009")
    legacy_user = Table("user", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        user_id = connection.execute(
            legacy_user.insert().values(
                hashed_token="legacy-plaintext-nwc",
                public_id=uuid4().hex,
                is_admin=False,
                is_suspended=False,
                nwc_uri="nostr+walletconnect://revoked-plaintext",
                created_at=datetime.now(UTC),
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)
    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        row = connection.execute(select(upgraded_user).where(upgraded_user.c.id == user_id)).one()
        connection.execute(
            upgraded_user.update()
            .where(upgraded_user.c.id == user_id)
            .values(nwc_uri="nostr+walletconnect://old-backend-write")
        )
    with engine.connect() as connection:
        guarded = connection.execute(
            select(upgraded_user.c.nwc_uri).where(upgraded_user.c.id == user_id)
        ).scalar_one()

    assert row.nwc_uri is None
    assert row.has_nwc is False
    assert guarded is None
    assert not hasattr(models.User, "nwc_uri")
    assert not hasattr(models.Payment, "nwc_request_id")


def test_product_type_uses_neutral_storage_values(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    with Session(engine) as session:
        user = models.User(hashed_token="neutral-product-storage")
        session.add(user)
        session.flush()
        subscription = models.Subscription(
            user_id=user.id,
            product=models.ProductType.IP,
            monthly_price_sats=1,
        )
        session.add(subscription)
        session.commit()
        session.refresh(subscription)
        assert subscription.product is models.ProductType.IP

    with engine.connect() as connection:
        assert connection.execute(text("SELECT product FROM subscription")).scalar_one() == "ip"

    product_column = SQLModel.metadata.tables["subscription"].c.product
    assert product_column.type.enums == ["ip", "port", "relay"]


def test_sqlite_upgrade_from_0001_preserves_existing_payment(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0001")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)

    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="migration-existing-user",
                is_admin=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="ip",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        payment_id = connection.execute(
            payment.insert().values(
                subscription_id=subscription_id,
                method="LIGHTNING",
                status="PENDING",
                amount_sats=1000,
                invoice="lnbc1000existing",
                payment_hash="ab" * 32,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)

    upgraded_payment = Table("payment", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == payment_id)
        ).one()
    assert row.invoice == "lnbc1000existing"
    assert row.payment_hash == "ab" * 32
    assert row.invoice_idempotency_key is None
    assert row.markup_sats == 0
    assert {index["name"] for index in inspect(engine).get_indexes("payment")} >= {
        "uq_payment_invoice_idempotency_key",
        "uq_payment_payment_hash",
    }


def test_sqlite_upgrade_from_0002_preserves_existing_user(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0002")
    user = Table("user", MetaData(), autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="credential-migration-existing-user",
                is_admin=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)

    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    credential = Table("clientcredential", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(select(upgraded_user).where(upgraded_user.c.id == user_id)).one()
        credentials = connection.execute(select(credential)).all()
    assert row.hashed_token == "credential-migration-existing-user"
    assert credentials == []


def test_sqlite_upgrade_from_0003_preserves_tcp_lease_and_adds_transport_identity(
    tmp_path,
) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0003")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)

    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="udp-migration-existing-user",
                is_admin=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="port",
                status="ACTIVE",
                assigned_ip="203.0.113.20",
                assigned_port=10000,
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    upgrade_database(engine)
    upgraded = Table("subscription", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        tcp_row = connection.execute(select(upgraded)).one()
        connection.execute(
            upgraded.insert().values(
                user_id=user_id,
                product="port",
                status="PENDING",
                assigned_ip="203.0.113.20",
                assigned_port=10000,
                transport="UDP",
                delivery="FRAMED",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        )
    assert tcp_row.transport == "TCP"
    assert any(
        constraint["column_names"] == ["assigned_ip", "assigned_port", "transport"]
        for constraint in inspect(engine).get_unique_constraints("subscription")
    )

    with pytest.raises(RuntimeError, match="cannot downgrade while UDP subscriptions exist"):
        downgrade_database(engine, "0003")
    assert database_revisions(engine) == ("0026", "0026")
    assert any(
        constraint["column_names"] == ["assigned_ip", "assigned_port", "transport"]
        for constraint in inspect(engine).get_unique_constraints("subscription")
    )


def test_sqlite_upgrade_from_0006_adds_empty_rate_limit_tables(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0006")
    inspector = inspect(engine)
    assert not inspector.has_table("ratelimitbucket")

    upgrade_database(engine)

    inspector = inspect(engine)
    assert inspector.has_table("ratelimitbucket")
    assert inspector.has_table("ratelimitmaintenance")
    buckets = Table("ratelimitbucket", MetaData(), autoload_with=engine)
    maintenance = Table("ratelimitmaintenance", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        assert connection.execute(select(buckets)).all() == []
        assert connection.execute(select(maintenance)).all() == []


def test_0015_scrubs_only_direct_client_rate_limit_rows(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0014")
    buckets = Table("ratelimitbucket", MetaData(), autoload_with=engine)
    maintenance = Table("ratelimitmaintenance", MetaData(), autoload_with=engine)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        connection.execute(
            maintenance.insert().values(
                name="rate-limit-buckets",
                next_cleanup_at=now,
                bucket_count=4,
            )
        )
        for index, scope in enumerate(("signup", "admin-login", "browser-login", "payment-create")):
            connection.execute(
                buckets.insert().values(
                    scope=scope,
                    identifier_hash=f"{index:064x}",
                    window_start=now,
                    request_count=1,
                    expires_at=now,
                )
            )
        connection.execute(
            maintenance.insert().values(
                name="unrelated-maintenance",
                next_cleanup_at=now,
                bucket_count=99,
            )
        )

    upgrade_database(engine)

    with engine.connect() as connection:
        scopes = connection.execute(select(buckets.c.scope)).scalars().all()
        counts = dict(
            connection.execute(select(maintenance.c.name, maintenance.c.bucket_count)).all()
        )
    assert scopes == ["payment-create"]
    assert counts == {"rate-limit-buckets": 1, "unrelated-maintenance": 99}


def test_0016_rejects_downgrade_with_stablecoin_payments(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="stablecoin-migration-user",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
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
                method="STABLECOIN_SWAP",
                status="PENDING",
                billing_term="monthly",
                period_days=30,
                amount_sats=1100,
                markup_sats=100,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    with pytest.raises(RuntimeError, match="stablecoin swap payments exist"):
        downgrade_database(engine, "0015")
    assert database_revisions(engine) == ("0026", "0026")

    with engine.begin() as connection:
        connection.execute(payment.delete().where(payment.c.id == payment_id))
    downgrade_database(engine, "0015")
    assert database_revisions(engine) == ("0015", "0026")
    assert "markup_sats" not in {
        column["name"] for column in inspect(engine).get_columns("payment")
    }


def test_0017_backfills_current_ip_lease_and_downgrades_cleanly(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0016")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="ip-lease-backfill",
                is_admin=False,
                is_suspended=False,
                created_at=now,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="ip",
                delivery="WIREGUARD",
                status="ACTIVE",
                assigned_ip="198.51.100.20",
                transport="TCP",
                domain_is_managed=False,
                billing_term="monthly",
                monthly_price_sats=7500,
                yearly_price_sats=75000,
                current_period_start=now,
                current_period_end=now + timedelta(days=30),
                auto_renew=False,
                created_at=now,
                updated_at=now,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)
    lease = Table("iplease", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        row = connection.execute(select(lease)).one()
    assert row.subscription_id == subscription_id
    assert row.address == "198.51.100.20"
    assert row.delivery == "wireguard"
    assert row.state == "active"
    assert row.imported is True
    assert row.smtp_enabled is False

    downgrade_database(engine, "0016")
    assert database_revisions(engine) == ("0016", "0026")
    assert not inspect(engine).has_table("iplease")
    with engine.connect() as connection:
        assert (
            connection.execute(select(subscription.c.assigned_ip)).scalar_one() == "198.51.100.20"
        )


def test_0018_service_announcements_downgrade_cleanly_on_sqlite(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    downgrade_database(engine, "0017")

    assert database_revisions(engine) == ("0017", "0026")
    inspector = inspect(engine)
    assert not inspector.has_table("announcement")
    assert not inspector.has_table("announcementdelivery")
    columns = {column["name"] for column in inspector.get_columns("user")}
    assert {
        "has_service_email",
        "service_email_ciphertext",
        "service_email_key_version",
        "service_email_generation",
    }.isdisjoint(columns)

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_0019_production_observations_downgrade_cleanly_on_sqlite(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    downgrade_database(engine, "0018")

    assert database_revisions(engine) == ("0018", "0026")
    inspector = inspect(engine)
    assert not inspector.has_table("relayheartbeat")
    assert not inspector.has_table("dnsobservation")

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_0020_relay_hostname_scope_defaults_existing_rows_and_downgrades_cleanly(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0019")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    agent_order = Table("agentorder", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="relay-scope-migration-user",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="relay",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain="existing.example",
                domain_is_managed=False,
                billing_term="monthly",
                monthly_price_sats=3000,
                yearly_price_sats=30000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        agent_order_id = connection.execute(
            agent_order.insert().values(
                user_id=user_id,
                order_key="existing-relay",
                subscription_id=subscription_id,
                product="relay",
                billing_term="monthly",
                delivery="FRAMED",
                transport="TCP",
                domain="existing.example",
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)
    upgraded_subscription = Table("subscription", MetaData(), autoload_with=engine)
    upgraded_order = Table("agentorder", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        stored_subscription_scope = connection.execute(
            select(upgraded_subscription.c.relay_hostname_scope).where(
                upgraded_subscription.c.id == subscription_id
            )
        ).scalar_one()
        stored_order_scope = connection.execute(
            select(upgraded_order.c.relay_hostname_scope).where(
                upgraded_order.c.id == agent_order_id
            )
        ).scalar_one()
    assert (stored_subscription_scope, stored_order_scope) == ("exact", "exact")
    assert "ix_subscription_relay_hostname_scope_domain" in {
        index["name"] for index in inspect(engine).get_indexes("subscription")
    }

    downgrade_database(engine, "0019")
    assert database_revisions(engine) == ("0019", "0026")
    assert "relay_hostname_scope" not in {
        column["name"] for column in inspect(engine).get_columns("subscription")
    }
    assert "relay_hostname_scope" not in {
        column["name"] for column in inspect(engine).get_columns("agentorder")
    }


def test_0021_daily_bandwidth_upgrade_and_downgrade_ordering(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0020")
    assert not inspect(engine).has_table("subscriptiondailybandwidth")
    assert not inspect(engine).has_table("relaybandwidthcursor")

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")
    inspector = inspect(engine)
    assert [
        fk["referred_table"] for fk in inspector.get_foreign_keys("subscriptiondailybandwidth")
    ] == ["subscription"]
    assert [fk["referred_table"] for fk in inspector.get_foreign_keys("relaybandwidthcursor")] == [
        "subscription"
    ]
    assert tuple(
        inspector.get_pk_constraint("subscriptiondailybandwidth")["constrained_columns"]
    ) == ("subscription_id", "day")

    downgrade_database(engine, "0020")
    assert database_revisions(engine) == ("0020", "0026")
    assert not inspect(engine).has_table("subscriptiondailybandwidth")
    assert not inspect(engine).has_table("relaybandwidthcursor")


def test_0022_notification_outbox_downgrades_to_0021_on_sqlite(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    downgrade_database(engine, "0021")

    assert database_revisions(engine) == ("0021", "0026")
    inspector = inspect(engine)
    assert not inspector.has_table("notificationdelivery")
    assert not inspector.has_table("announcementrecipientsnapshot")
    assert inspector.has_table("reminderdelivery")
    assert inspector.has_table("announcementdelivery")
    announcement_columns = {column["name"] for column in inspector.get_columns("announcement")}
    assert {"recipient_cursor", "recipient_max_user_id", "expansion_complete"}.isdisjoint(
        announcement_columns
    )

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_0023_passkey_persistence_downgrades_to_0022_on_sqlite(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    downgrade_database(engine, "0022")

    assert database_revisions(engine) == ("0022", "0026")
    inspector = inspect(engine)
    assert not inspector.has_table("passkeycredential")
    assert not inspector.has_table("webauthnchallenge")
    assert not inspector.has_table("browsersession")
    assert inspector.has_table("notificationdelivery")

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_0024_unified_notification_email_cancels_queued_rows_and_drops_old_columns(
    tmp_path,
) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0023")
    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO notificationdelivery "
                "(user_id, category, kind, idempotency_key, recipient_generation, state, "
                "attempt_count, created_at, updated_at) "
                "VALUES (1, 'account', 'expiration_7_day', 'cutover-notification', 1, 'queued', "
                "0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO reminderdelivery "
                "(subscription_id, current_period_end, recipient_generation, kind, state, "
                "attempt_count, created_at, updated_at) "
                "VALUES (1, CURRENT_TIMESTAMP, 1, 'seven_day', 'queued', 0, "
                "CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )
        connection.execute(
            text(
                "INSERT INTO announcementdelivery "
                "(announcement_id, user_id, recipient_generation, state, attempt_count, "
                "created_at, updated_at) "
                "VALUES (1, 1, 1, 'queued', 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
        )

    upgrade_database(engine)

    inspector = inspect(engine)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    assert {
        "has_notification_email",
        "notification_email_ciphertext",
        "notification_email_key_version",
        "notification_email_generation",
    }.issubset(user_columns)
    assert {
        "has_reminder_email",
        "reminder_email_ciphertext",
        "reminder_email_key_version",
        "reminder_email_generation",
        "has_service_email",
        "service_email_ciphertext",
        "service_email_key_version",
        "service_email_generation",
    }.isdisjoint(user_columns)
    with engine.connect() as connection:
        for table_name in ("notificationdelivery", "reminderdelivery", "announcementdelivery"):
            row = connection.execute(
                text(f"SELECT state, error_code, terminal_at FROM {table_name}")
            ).one()
            assert row.state == "cancelled"
            assert row.error_code == "notification_preference_cutover"
            assert row.terminal_at is not None

    downgrade_database(engine, "0023")
    downgraded_columns = {column["name"] for column in inspect(engine).get_columns("user")}
    assert "has_notification_email" not in downgraded_columns
    assert "has_reminder_email" in downgraded_columns
    assert "has_service_email" in downgraded_columns


def test_0025_relay_subscription_connections_upgrades_and_downgrades_cleanly(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0024")

    assert not inspect(engine).has_table("relaysubscriptionconnection")
    upgrade_database(engine, "0025")
    connection_table = Table("relaysubscriptionconnection", MetaData(), autoload_with=engine)
    assert {column.name for column in connection_table.columns} == {
        "edge_id",
        "subscription_id",
        "active",
        "observed_at",
        "last_connected_at",
    }
    assert {column.name for column in connection_table.primary_key.columns} == {
        "edge_id",
        "subscription_id",
    }

    downgrade_database(engine, "0024")
    assert database_revisions(engine) == ("0024", "0026")
    assert not inspect(engine).has_table("relaysubscriptionconnection")


def test_0026_backfills_stablecoin_checkout_snapshots_and_downgrades_cleanly(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0025")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="stablecoin-checkout-snapshot-user",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        stablecoin_subscription_id = connection.execute(
            subscription.insert().values(
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
        lightning_subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="port",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                billing_term="monthly",
                monthly_price_sats=1001,
                yearly_price_sats=10010,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        stablecoin_payment_id = connection.execute(
            payment.insert().values(
                subscription_id=stablecoin_subscription_id,
                method="STABLECOIN_SWAP",
                status="PENDING",
                billing_term="monthly",
                period_days=30,
                amount_sats=1100,
                markup_sats=100,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        lightning_payment_id = connection.execute(
            payment.insert().values(
                subscription_id=lightning_subscription_id,
                method="LIGHTNING",
                status="PENDING",
                billing_term="monthly",
                period_days=30,
                amount_sats=1001,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine, "0026")

    upgraded_payment = Table("payment", MetaData(), autoload_with=engine)
    columns = {column.name: column for column in upgraded_payment.columns}
    assert {
        name: (columns[name].type.length, columns[name].nullable)
        for name in (
            "stablecoin_provider",
            "stablecoin_checkout_origin",
            "stablecoin_asset",
        )
    } == {
        "stablecoin_provider": (32, True),
        "stablecoin_checkout_origin": (2048, True),
        "stablecoin_asset": (64, True),
    }
    with engine.connect() as connection:
        stablecoin_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == stablecoin_payment_id)
        ).one()
        lightning_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == lightning_payment_id)
        ).one()
    assert (
        stablecoin_payment.stablecoin_provider,
        stablecoin_payment.stablecoin_checkout_origin,
        stablecoin_payment.stablecoin_asset,
    ) == ("boltz", None, None)
    assert (
        lightning_payment.stablecoin_provider,
        lightning_payment.stablecoin_checkout_origin,
        lightning_payment.stablecoin_asset,
    ) == (None, None, None)

    with pytest.raises(RuntimeError, match="stablecoin swap payments exist"):
        downgrade_database(engine, "0025")
    assert database_revisions(engine) == ("0026", "0026")

    with engine.begin() as connection:
        connection.execute(
            upgraded_payment.delete().where(upgraded_payment.c.id == stablecoin_payment_id)
        )
    downgrade_database(engine, "0025")
    assert database_revisions(engine) == ("0025", "0026")
    downgraded_payment = Table("payment", MetaData(), autoload_with=engine)
    assert {
        "stablecoin_provider",
        "stablecoin_checkout_origin",
        "stablecoin_asset",
    }.isdisjoint(downgraded_payment.c.keys())
    with engine.connect() as connection:
        assert set(connection.execute(select(downgraded_payment.c.id)).scalars()) == {
            lightning_payment_id
        }


def test_sqlite_0008_backfills_unique_uuid4_public_ids_and_enforces_immutability(
    tmp_path,
) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0007")
    user = Table("user", MetaData(), autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        for index in range(3):
            connection.execute(
                user.insert().values(
                    hashed_token=f"public-id-backfill-{index}",
                    is_admin=False,
                    is_suspended=False,
                    created_at=created_at,
                )
            )

    upgrade_database(engine)

    upgraded_user = Table("user", MetaData(), autoload_with=engine)
    with engine.connect() as connection:
        rows = connection.execute(select(upgraded_user).order_by(upgraded_user.c.id)).all()
    public_ids = [UUID(str(row.public_id)) for row in rows]
    assert len(set(public_ids)) == 3
    assert all(public_id.version == 4 for public_id in public_ids)

    with engine.begin() as connection:
        legacy_insert_id = connection.execute(
            upgraded_user.insert().values(
                hashed_token="post-migration-legacy-insert",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
    with engine.connect() as connection:
        generated = connection.execute(
            select(upgraded_user.c.public_id).where(upgraded_user.c.id == legacy_insert_id)
        ).scalar_one()
    assert UUID(str(generated)).version == 4

    with (
        pytest.raises(IntegrityError, match="public_id is immutable"),
        engine.begin() as connection,
    ):
        connection.execute(
            upgraded_user.update()
            .where(upgraded_user.c.id == rows[0].id)
            .values(public_id=uuid4().hex)
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            upgraded_user.insert().values(
                public_id=public_ids[0].hex,
                hashed_token="duplicate-public-id",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        )


def test_sqlite_0009_backfills_billing_snapshots_and_supports_rolling_inserts(
    tmp_path,
) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine, "0008")
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    payment = Table("payment", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="billing-backfill-user",
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        subscription_id = connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="port",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1234,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        payment_id = connection.execute(
            payment.insert().values(
                subscription_id=subscription_id,
                method="LIGHTNING",
                status="PAID",
                amount_sats=1234,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    upgrade_database(engine)
    upgraded_subscription = Table("subscription", MetaData(), autoload_with=engine)
    upgraded_payment = Table("payment", MetaData(), autoload_with=engine)
    with engine.begin() as connection:
        backfilled_sub = connection.execute(
            select(upgraded_subscription).where(upgraded_subscription.c.id == subscription_id)
        ).one()
        backfilled_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == payment_id)
        ).one()
        rolling_sub_id = connection.execute(
            upgraded_subscription.insert().values(
                user_id=user_id,
                product="ip",
                delivery="FRAMED",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=777,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        ).inserted_primary_key[0]
        rolling_payment_id = connection.execute(
            upgraded_payment.insert().values(
                subscription_id=rolling_sub_id,
                method="LIGHTNING",
                status="PAID",
                amount_sats=777,
                created_at=created_at,
            )
        ).inserted_primary_key[0]

    assert (backfilled_sub.billing_term, backfilled_sub.yearly_price_sats) == (
        "monthly",
        12340,
    )
    assert (backfilled_payment.billing_term, backfilled_payment.period_days) == (
        "monthly",
        30,
    )
    with engine.connect() as connection:
        rolling_sub = connection.execute(
            select(upgraded_subscription).where(upgraded_subscription.c.id == rolling_sub_id)
        ).one()
        rolling_payment = connection.execute(
            select(upgraded_payment).where(upgraded_payment.c.id == rolling_payment_id)
        ).one()
    assert (rolling_sub.billing_term, rolling_sub.yearly_price_sats) == ("monthly", 7770)
    assert (rolling_payment.billing_term, rolling_payment.period_days) == ("monthly", 30)

    downgrade_database(engine, "0008")
    assert database_revisions(engine) == ("0008", "0026")
    assert "billing_term" not in {
        column["name"] for column in inspect(engine).get_columns("subscription")
    }
    assert "period_days" not in {
        column["name"] for column in inspect(engine).get_columns("payment")
    }


def test_sqlite_downgrade_rejects_wireguard_subscriptions(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)
    metadata = MetaData()
    user = Table("user", metadata, autoload_with=engine)
    subscription = Table("subscription", metadata, autoload_with=engine)
    created_at = datetime(2026, 1, 1, tzinfo=UTC)
    with engine.begin() as connection:
        user_id = connection.execute(
            user.insert().values(
                hashed_token="wireguard-downgrade-existing-user",
                public_id=uuid4().hex,
                is_admin=False,
                is_suspended=False,
                created_at=created_at,
            )
        ).inserted_primary_key[0]
        connection.execute(
            subscription.insert().values(
                user_id=user_id,
                product="ip",
                delivery="WIREGUARD",
                status="PENDING",
                transport="TCP",
                domain_is_managed=False,
                monthly_price_sats=1000,
                auto_renew=False,
                created_at=created_at,
                updated_at=created_at,
            )
        )

    with pytest.raises(RuntimeError, match="cannot downgrade while WireGuard subscriptions exist"):
        downgrade_database(engine, "0004")

    assert database_revisions(engine) == ("0026", "0026")
    assert "delivery" in {column["name"] for column in inspect(engine).get_columns("subscription")}
    assert inspect(engine).has_table("wireguardpeer")


def test_sqlite_downgrade_and_upgrade_round_trip(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)
    downgrade_database(engine, "base")

    assert inspect(engine).get_table_names() == ["alembic_version"]
    assert database_revisions(engine) == (None, "0026")

    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_sqlite_failed_migration_rolls_back_ddl_and_can_retry(tmp_path, monkeypatch) -> None:
    engine = _sqlite_engine(tmp_path)

    def fail_after_ddl(config, revision) -> None:
        del revision
        connection = config.attributes["connection"]
        connection.exec_driver_sql("CREATE TABLE injected_migration_failure (id INTEGER)")
        raise RuntimeError("injected migration failure")

    with monkeypatch.context() as patch:
        patch.setattr(migrations.command, "upgrade", fail_after_ddl)
        with pytest.raises(RuntimeError, match="injected migration failure"):
            upgrade_database(engine)

    assert not inspect(engine).has_table("injected_migration_failure")
    upgrade_database(engine)
    assert database_revisions(engine) == ("0026", "0026")


def test_all_persisted_datetimes_are_timezone_aware_in_metadata() -> None:
    datetime_columns = {
        (table.name, column.name): column
        for table in SQLModel.metadata.tables.values()
        for column in table.columns
        if isinstance(column.type, DateTime)
    }

    assert set(datetime_columns) == EXPECTED_DATETIME_COLUMNS
    assert all(column.type.timezone for column in datetime_columns.values())


def test_migration_head_matches_sqlmodel_metadata(tmp_path) -> None:
    engine = _sqlite_engine(tmp_path)
    upgrade_database(engine)

    with engine.connect() as connection:
        context = MigrationContext.configure(connection, opts={"compare_type": True})
        assert compare_metadata(context, SQLModel.metadata) == []


def test_payment_method_metadata_includes_stablecoin_swap() -> None:
    method_column = SQLModel.metadata.tables["payment"].c.method

    assert method_column.type.enums == ["LIGHTNING", "CASHU", "NWC", "STABLECOIN_SWAP"]


def test_current_cli_can_check_head(tmp_path, monkeypatch, capsys) -> None:
    engine = _sqlite_engine(tmp_path)
    monkeypatch.setattr(cli, "engine", engine)

    assert cli.main(["upgrade"]) == 0
    assert cli.main(["current", "--check"]) == 0
    assert "current: 0026\nhead: 0026" in capsys.readouterr().out

    cli.main(["downgrade", "base"])
    capsys.readouterr()
    assert cli.main(["current", "--check"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "current: unversioned\nhead: 0026\n"
    assert captured.err == (
        "error: database revision is unversioned, expected migration head 0026\n"
    )
    assert "Traceback" not in captured.err

    with pytest.raises(DatabaseRevisionError, match="unversioned"):
        verify_database_current(engine)


def test_current_cli_check_subprocess_exits_without_traceback(tmp_path) -> None:
    database_path = tmp_path / "subprocess.db"
    backend_src = Path(__file__).parents[1] / "src"
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{database_path}"
    env["DATABASE_MIGRATE_ON_STARTUP"] = "false"
    env["PYTHONPATH"] = os.pathsep.join(
        part for part in (str(backend_src), env.get("PYTHONPATH")) if part
    )

    result = subprocess.run(
        [sys.executable, "-m", "blindport.migrations.cli", "current", "--check"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == "current: unversioned\nhead: 0026\n"
    assert result.stderr == (
        "error: database revision is unversioned, expected migration head 0026\n"
    )
    assert "Traceback" not in result.stderr
