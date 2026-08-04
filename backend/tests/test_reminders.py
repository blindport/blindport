"""Encrypted reminder preferences and provider-neutral delivery transitions."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select

from blindport.adapters.smtp import SmtpDeliveryError
from blindport.core.credentials import CredentialCipher, CredentialError, EncryptedCredential
from blindport.core.models import (
    ProductType,
    ReminderDelivery,
    ReminderDeliveryState,
    ReminderKind,
    Subscription,
    User,
)
from blindport.services.reminders import (
    ReminderEmailError,
    cancel_pending_reminders,
    clear_reminder_email,
    decrypt_reminder_email,
    fence_reminder_lease,
    normalize_reminder_email,
    queue_reminder,
    reminder_message_id,
    render_expiration_reminder,
    send_reminder,
    store_reminder_email,
)


@pytest.mark.parametrize(
    "value",
    [
        "Person <person@example.com>",
        "person@example.com\nBcc: victim@example.com",
        " person@example.com",
        "person@example.com ",
        "person@localhost",
        "person..name@example.com",
        "person@-example.com",
        "person@example.c",
        "a" * 250 + "@example.com",
    ],
)
def test_email_validation_rejects_unsafe_values_without_reflection(value: str) -> None:
    with pytest.raises(ReminderEmailError, match="address is invalid") as exc_info:
        normalize_reminder_email(value)
    assert value not in str(exc_info.value)


def test_email_preference_is_normalized_encrypted_and_clearable() -> None:
    user = User(hashed_token="hash")
    cipher = CredentialCipher("44" * 32)
    normalized = store_reminder_email(user, "Person@EXAMPLE.COM", cipher=cipher)
    assert normalized == "Person@example.com"
    assert normalized not in (user.reminder_email_ciphertext or "")
    assert decrypt_reminder_email(user, cipher=cipher) == normalized
    with pytest.raises(CredentialError, match="authentication failed"):
        cipher.decrypt(
            user.public_id,
            EncryptedCredential(user.reminder_email_ciphertext, user.reminder_email_key_version),
        )
    generation = user.reminder_email_generation
    clear_reminder_email(user)
    assert user.has_reminder_email is False
    assert user.reminder_email_generation == generation + 1


def test_rendering_is_deterministic_and_contains_no_account_secret() -> None:
    period_end = datetime(2026, 8, 9, 12, 30, tzinfo=UTC)
    reminder = render_expiration_reminder(ReminderKind.SEVEN_DAY, period_end)
    assert reminder.subject == "Blindport subscription expires within 7 days"
    assert "2026-08-09 12:30 UTC" in reminder.body
    assert "account-token" not in reminder.body
    assert render_expiration_reminder(ReminderKind.SEVEN_DAY, period_end) == reminder


def _delivery_fixture(
    cipher: CredentialCipher | None = None,
) -> tuple[Session, User, Subscription, ReminderDelivery]:
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    session = Session(engine)
    user = User(hashed_token="reminder-user")
    store_reminder_email(user, "person@example.com", cipher=cipher)
    session.add(user)
    session.flush()
    subscription = Subscription(
        user_id=user.id,
        product=ProductType.IP,
        monthly_price_sats=1000,
        current_period_end=datetime(2026, 8, 9, 12, 30, tzinfo=UTC),
    )
    session.add(subscription)
    session.commit()
    session.refresh(subscription)
    delivery = queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
    session.commit()
    return session, user, subscription, delivery


def test_queue_is_idempotent_and_outbox_contains_no_message_or_payment_data() -> None:
    session, _, subscription, first = _delivery_fixture()
    try:
        second = queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        assert first.id == second.id
        assert len(session.exec(select(ReminderDelivery)).all()) == 1
        assert {column.name for column in ReminderDelivery.__table__.columns}.isdisjoint(
            {"recipient", "subject", "body", "invoice", "payment_hash", "provider", "nwc_state"}
        )
    finally:
        session.close()


class _Smtp:
    def __init__(self, error: SmtpDeliveryError | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str, str, str, str]] = []

    def send_message(self, recipient: str, subject: str, body: str, message_id: str) -> None:
        self.calls.append((recipient, subject, body, message_id))
        if self.error:
            raise self.error


def test_smtp_acceptance_marks_sent_with_deterministic_message_id(monkeypatch) -> None:
    monkeypatch.setattr("blindport.config.settings.SMTP_FROM_EMAIL", "notices@example.com")
    cipher = CredentialCipher("55" * 32)
    session, user, _, delivery = _delivery_fixture(cipher)
    adapter = _Smtp()
    try:
        first_id = reminder_message_id(delivery)
        send_reminder(session, delivery, user, adapter, cipher=cipher)
        assert delivery.state == ReminderDeliveryState.SENT
        assert delivery.sent_at is not None
        assert adapter.calls[0][3] == first_id == reminder_message_id(delivery)
    finally:
        session.close()


@pytest.mark.parametrize(
    "error,expected,next_attempt",
    [
        (SmtpDeliveryError("smtp_transient", retryable=True), ReminderDeliveryState.QUEUED, True),
        (SmtpDeliveryError("smtp_rejected", retryable=False), ReminderDeliveryState.FAILED, False),
        (
            SmtpDeliveryError("smtp_ambiguous", retryable=False, ambiguous=True),
            ReminderDeliveryState.DELIVERY_AMBIGUOUS,
            False,
        ),
    ],
)
def test_smtp_failure_transitions(error, expected, next_attempt) -> None:
    session, user, _, delivery = _delivery_fixture()
    try:
        send_reminder(session, delivery, user, _Smtp(error))
        assert delivery.state == expected
        assert (delivery.next_attempt_at is not None) is next_attempt
        assert delivery.error_code == error.code
    finally:
        session.close()


def test_unexpected_smtp_failure_is_sanitized_and_terminal() -> None:
    session, user, _, delivery = _delivery_fixture()

    class UnexpectedSmtp:
        def send_message(self, *args) -> None:
            raise RuntimeError("private recipient and server response")

    try:
        send_reminder(session, delivery, user, UnexpectedSmtp())  # type: ignore[arg-type]
        assert delivery.state == ReminderDeliveryState.FAILED
        assert delivery.error_code == "smtp_internal_error"
    finally:
        session.close()


def test_preference_change_cancels_only_queued_delivery() -> None:
    session, user, _, delivery = _delivery_fixture()
    try:
        cancel_pending_reminders(session, user)
        session.commit()
        assert delivery.state == ReminderDeliveryState.CANCELLED
        delivery.state = ReminderDeliveryState.SENDING
        session.add(delivery)
        session.commit()
        cancel_pending_reminders(session, user)
        session.commit()
        assert delivery.state == ReminderDeliveryState.SENDING
    finally:
        session.close()


def test_stale_worker_cannot_write_after_lease_token_changes() -> None:
    session, _, _, delivery = _delivery_fixture()
    try:
        delivery.lease_token = "new-owner"
        session.add(delivery)
        session.commit()
        assert fence_reminder_lease(session, delivery, "old-owner") is False
        assert delivery.lease_token == "new-owner"
    finally:
        session.close()
