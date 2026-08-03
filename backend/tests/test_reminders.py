"""Encrypted reminder preferences, rendering, and delivery transitions."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select

from blindport.adapters.lnemail import (
    LnemailInvoice,
    LnemailStatus,
    LnemailTransportError,
)
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
    begin_nwc_payment,
    cancel_unfunded_reminders,
    clear_reminder_email,
    create_reminder_invoice,
    decrypt_reminder_email,
    decrypt_reminder_invoice,
    fence_reminder_lease,
    normalize_reminder_email,
    poll_reminder_status,
    queue_payment_reminder,
    record_nwc_payment_result,
    render_payment_reminder,
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
def test_email_validation_rejects_unsafe_or_non_addr_spec_values(value: str) -> None:
    with pytest.raises(ReminderEmailError, match="address is invalid") as exc_info:
        normalize_reminder_email(value)
    assert value not in str(exc_info.value)


def test_email_preference_is_normalized_encrypted_and_clearable() -> None:
    user = User(hashed_token="hash")
    cipher = CredentialCipher("44" * 32)

    normalized = store_reminder_email(user, "Person@EXAMPLE.COM", cipher=cipher)

    assert normalized == "Person@example.com"
    assert user.has_reminder_email is True
    assert normalized not in (user.reminder_email_ciphertext or "")
    assert decrypt_reminder_email(user, cipher=cipher) == normalized
    with pytest.raises(CredentialError, match="authentication failed"):
        CredentialCipher("44" * 32).decrypt(
            user.public_id,
            # The default purpose remains NWC and cannot decrypt an email.
            EncryptedCredential(
                user.reminder_email_ciphertext,
                user.reminder_email_key_version,
            ),
        )

    generation = user.reminder_email_generation
    clear_reminder_email(user)
    assert user.has_reminder_email is False
    assert user.reminder_email_ciphertext is None
    assert user.reminder_email_generation == generation + 1
    with pytest.raises(CredentialError, match="unavailable"):
        decrypt_reminder_email(user, cipher=cipher)
    clear_reminder_email(user)
    assert user.reminder_email_generation == generation + 1


def test_rendering_is_deterministic_and_contains_no_account_secret() -> None:
    period_end = datetime(2026, 8, 9, 12, 30, tzinfo=UTC)

    seven_day = render_payment_reminder(ReminderKind.SEVEN_DAY, period_end)
    one_day = render_payment_reminder(ReminderKind.ONE_DAY, period_end)

    assert seven_day.subject == "Blindport subscription expires within 7 days"
    assert one_day.subject == "Blindport subscription expires within 1 day"
    assert "2026-08-09 12:30 UTC" in seven_day.body
    assert "account-token" not in seven_day.body
    assert render_payment_reminder(ReminderKind.SEVEN_DAY, period_end) == seven_day
    with pytest.raises(ValueError, match="kind is invalid"):
        render_payment_reminder("unexpected", period_end)  # type: ignore[arg-type]


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
    delivery = queue_payment_reminder(session, subscription, ReminderKind.SEVEN_DAY)
    session.commit()
    return session, user, subscription, delivery


def test_queue_is_idempotent_and_outbox_has_no_message_plaintext() -> None:
    session, _, subscription, first = _delivery_fixture()
    try:
        second = queue_payment_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        rows = session.exec(select(ReminderDelivery)).all()
        assert first.id == second.id
        assert len(rows) == 1
        assert {column.name for column in ReminderDelivery.__table__.columns}.isdisjoint(
            {"recipient", "subject", "body", "invoice"}
        )
    finally:
        session.close()


def test_unfunded_cancelled_notice_can_follow_reenabled_preference() -> None:
    session, user, subscription, delivery = _delivery_fixture()
    try:
        clear_reminder_email(user)
        cancel_unfunded_reminders(session, user)
        session.add(user)
        session.commit()
        assert delivery.state == ReminderDeliveryState.CANCELLED

        store_reminder_email(user, "new@example.com")
        session.add(user)
        session.commit()
        resumed = queue_payment_reminder(session, subscription, ReminderKind.SEVEN_DAY)

        assert resumed.id == delivery.id
        assert resumed.state == ReminderDeliveryState.QUEUED
        assert resumed.recipient_generation == user.reminder_email_generation
    finally:
        session.close()


class _SuccessfulAdapter:
    def create_send_invoice(self, recipient: str, subject: str, body: str) -> LnemailInvoice:
        assert recipient == "person@example.com"
        assert "within 7 days" in subject
        assert "2026-08-09 12:30 UTC" in body
        return LnemailInvoice("lnbc1u1reminder", "ab" * 32, 100, "nwc-1")

    def send_status(self, payment_hash: str) -> LnemailStatus:
        assert payment_hash == "ab" * 32
        return LnemailStatus(
            "paid",
            "sent",
            datetime(2026, 8, 2, 12, 1, tzinfo=UTC),
            0,
        )


def test_invoice_ambiguous_payment_and_delivery_flow() -> None:
    cipher = CredentialCipher("55" * 32)
    session, user, _, delivery = _delivery_fixture(cipher)
    try:
        create_reminder_invoice(
            session,
            delivery,
            user,
            _SuccessfulAdapter(),  # type: ignore[arg-type]
            cipher=cipher,
            now=datetime(2026, 8, 2, 12, 0, tzinfo=UTC),
        )
        assert delivery.state == ReminderDeliveryState.INVOICE_CREATED
        assert "lnbc1u1reminder" not in (delivery.invoice_ciphertext or "")
        assert decrypt_reminder_invoice(delivery, user, cipher=cipher) == "lnbc1u1reminder"

        begin_nwc_payment(
            session,
            delivery,
            now=datetime(2026, 8, 2, 12, 0, 5, tzinfo=UTC),
        )
        assert delivery.state == ReminderDeliveryState.PAYING

        record_nwc_payment_result(
            delivery,
            "unknown",
            now=datetime(2026, 8, 2, 12, 0, 10, tzinfo=UTC),
        )
        assert delivery.state == ReminderDeliveryState.PAYMENT_AMBIGUOUS

        poll_reminder_status(
            delivery,
            _SuccessfulAdapter(),  # type: ignore[arg-type]
            now=datetime(2026, 8, 2, 12, 1, tzinfo=UTC),
        )
        assert delivery.state == ReminderDeliveryState.DELIVERED
        assert delivery.terminal_at is not None
        assert delivery.provider_payment_status == "paid"
        assert delivery.provider_delivery_status == "sent"
    finally:
        session.close()


class _LostPostAdapter:
    def create_send_invoice(self, recipient: str, subject: str, body: str) -> LnemailInvoice:
        del recipient, subject, body
        raise LnemailTransportError("timeout", "LNemail request timed out", retryable=True)


def test_lost_invoice_response_is_not_retried_as_a_duplicate_send() -> None:
    cipher = CredentialCipher("66" * 32)
    session, user, _, delivery = _delivery_fixture(cipher)
    try:
        create_reminder_invoice(
            session,
            delivery,
            user,
            _LostPostAdapter(),  # type: ignore[arg-type]
            cipher=cipher,
            now=datetime(2026, 8, 2, 12, 0, tzinfo=UTC),
        )
        assert delivery.state == ReminderDeliveryState.INVOICE_CREATION_AMBIGUOUS
        assert delivery.terminal_at is not None
        assert delivery.next_attempt_at is None
        assert delivery.error_code == "timeout"
    finally:
        session.close()


def test_nwc_requires_valid_preimage_proof_and_persists_only_its_hash() -> None:
    session, _, _, delivery = _delivery_fixture()
    preimage = "42" * 32
    payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()
    try:
        delivery.payment_hash = payment_hash
        delivery.state = ReminderDeliveryState.PAYING

        record_nwc_payment_result(delivery, "settled")
        assert delivery.state == ReminderDeliveryState.PAYMENT_AMBIGUOUS
        assert delivery.nwc_retry_blocked is True
        assert delivery.nwc_preimage_hash is None

        delivery.state = ReminderDeliveryState.PAYING
        delivery.nwc_retry_blocked = False
        record_nwc_payment_result(delivery, "pending", preimage=preimage)
        assert delivery.state == ReminderDeliveryState.AWAITING_DELIVERY
        assert delivery.nwc_preimage_hash == payment_hash
        assert preimage not in (delivery.nwc_preimage_hash or "")
    finally:
        session.close()


def test_stale_worker_cannot_write_after_lease_token_changes() -> None:
    session, _, _, delivery = _delivery_fixture()
    try:
        delivery.lease_token = "new-owner"
        session.add(delivery)
        session.commit()
        delivery.state = ReminderDeliveryState.PAYING

        assert fence_reminder_lease(session, delivery, "old-owner") is False
        assert delivery.state == ReminderDeliveryState.QUEUED
        assert delivery.lease_token == "new-owner"
    finally:
        session.close()
