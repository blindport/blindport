"""Payment reminder migration compatibility and privacy boundaries."""

from __future__ import annotations

from sqlalchemy import create_engine, inspect

from blindport.migrations import database_revisions, downgrade_database, upgrade_database


def test_0011_sqlite_upgrade_and_downgrade(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'reminders.db'}")
    upgrade_database(engine, "0010")

    upgrade_database(engine)

    inspector = inspect(engine)
    assert database_revisions(engine) == ("0012", "0012")
    assert inspector.has_table("reminderdelivery")
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    assert {
        "has_reminder_email",
        "reminder_email_ciphertext",
        "reminder_email_key_version",
        "reminder_email_generation",
    } <= user_columns
    delivery_columns = {column["name"] for column in inspector.get_columns("reminderdelivery")}
    assert {"recipient", "subject", "body"}.isdisjoint(delivery_columns)
    assert {
        "recipient_generation",
        "invoice_ciphertext",
        "invoice_key_version",
        "payment_hash",
        "provider_payment_status",
        "provider_delivery_status",
        "nwc_state",
        "nwc_preimage_hash",
        "nwc_retry_blocked",
        "lease_token",
        "lease_until",
        "terminal_at",
    } <= delivery_columns
    assert "invoice" not in delivery_columns
    assert {
        constraint["name"] for constraint in inspector.get_unique_constraints("reminderdelivery")
    } == {"uq_reminderdelivery_subscription_period_kind"}
    assert {
        constraint["name"] for constraint in inspector.get_check_constraints("reminderdelivery")
    } == {"ck_reminderdelivery_attempt_count"}
    assert {index["name"] for index in inspector.get_indexes("reminderdelivery")} == {
        "ix_reminderdelivery_due",
        "ix_reminderdelivery_subscription_id",
        "uq_reminderdelivery_payment_hash",
    }

    downgrade_database(engine, "0010")

    inspector = inspect(engine)
    assert not inspector.has_table("reminderdelivery")
    assert "reminder_email_ciphertext" not in {
        column["name"] for column in inspector.get_columns("user")
    }
