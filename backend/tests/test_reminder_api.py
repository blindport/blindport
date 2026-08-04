"""Account reminder preference API behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_reminder_email_api_encrypts_and_never_returns_address(
    app_client,
    monkeypatch,
) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]

    saved = client.post(
        "/api/v1/me/reminder-email",
        json={"email": "Person@EXAMPLE.COM"},
        headers=_auth(token),
    )

    assert saved.status_code == 200
    assert saved.json() == {"configured": True}
    assert saved.headers["cache-control"] == "no-store"
    assert "example.com" not in saved.text.lower()

    from blindport.core.models import User
    from blindport.db import engine

    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_reminder_email)).one()
        assert "Person@example.com" not in (user.reminder_email_ciphertext or "")

    status = client.get("/api/v1/me/reminder-email", headers=_auth(token))
    assert status.json() == {"configured": True}
    assert "example.com" not in status.text.lower()

    deleted = client.delete("/api/v1/me/reminder-email", headers=_auth(token))
    assert deleted.json() == {"configured": False}


def test_reminder_email_api_rejects_invalid_address(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post(
        "/api/v1/me/reminder-email",
        json={"email": "Person <person@example.com>"},
        headers=_auth(token),
    )

    assert response.status_code == 400
    assert "person@example.com" not in response.text


def test_reminder_email_validation_never_reflects_pii(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    invalid_email = f"person@{'a' * 250}.example"

    response = client.post(
        "/api/v1/me/reminder-email",
        json={"email": invalid_email},
        headers=_auth(token),
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "reminder email address is invalid"}
    assert invalid_email not in response.text
    assert response.headers["cache-control"] == "no-store"


def test_reminder_email_api_is_hidden_when_disabled(app_client) -> None:
    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]

    response = client.get("/api/v1/me/reminder-email", headers=_auth(token))

    assert response.status_code == 404


def test_deleting_preference_cancels_unfunded_delivery_and_is_idempotent(
    app_client, monkeypatch
) -> None:
    from blindport import config
    from blindport.core.models import (
        ProductType,
        ReminderDelivery,
        ReminderDeliveryState,
        ReminderKind,
        Subscription,
        SubscriptionStatus,
        User,
    )
    from blindport.db import engine
    from blindport.services.reminders import queue_reminder

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    assert (
        client.post(
            "/api/v1/me/reminder-email",
            json={"email": "person@example.com"},
            headers=_auth(token),
        ).status_code
        == 200
    )

    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_reminder_email)).one()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=datetime.now(UTC) + timedelta(days=6),
        )
        session.add(subscription)
        session.commit()
        session.refresh(subscription)
        queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        session.commit()
        generation = user.reminder_email_generation

    assert client.delete("/api/v1/me/reminder-email", headers=_auth(token)).status_code == 200
    assert client.delete("/api/v1/me/reminder-email", headers=_auth(token)).status_code == 200

    with Session(engine) as session:
        user = session.exec(
            select(User).where(User.reminder_email_generation == generation + 1)
        ).one()
        delivery = session.exec(select(ReminderDelivery)).one()
        assert user.reminder_email_ciphertext is None
        assert user.reminder_email_generation == generation + 1
        assert delivery.state == ReminderDeliveryState.CANCELLED


def test_replacing_preference_cancels_queued_notice_for_previous_recipient(
    app_client,
    monkeypatch,
) -> None:
    from datetime import UTC, datetime, timedelta

    from blindport import config
    from blindport.core.models import (
        ProductType,
        ReminderDelivery,
        ReminderDeliveryState,
        ReminderKind,
        Subscription,
        SubscriptionStatus,
        User,
    )
    from blindport.db import engine
    from blindport.services.reminders import queue_reminder

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    assert (
        client.post(
            "/api/v1/me/reminder-email",
            json={"email": "old@example.com"},
            headers=_auth(token),
        ).status_code
        == 200
    )
    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_reminder_email)).one()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=1000,
            current_period_end=datetime.now(UTC) + timedelta(days=6),
        )
        session.add(subscription)
        session.flush()
        delivery = queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        session.add(delivery)
        session.commit()

    response = client.post(
        "/api/v1/me/reminder-email",
        json={"email": "new@example.com"},
        headers=_auth(token),
    )

    assert response.status_code == 200
    with Session(engine) as session:
        delivery = session.exec(select(ReminderDelivery)).one()
        assert delivery.state == ReminderDeliveryState.CANCELLED
        assert delivery.lease_token is None


def test_reminder_api_fails_closed_when_encryption_becomes_unavailable(
    app_client, monkeypatch
) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(config.settings, "CREDENTIAL_ENCRYPTION_KEY", "")
    token = client.post("/api/v1/signup").json()["token"]

    response = client.post(
        "/api/v1/me/reminder-email",
        json={"email": "person@example.com"},
        headers=_auth(token),
    )

    assert response.status_code == 503
    assert response.json() == {"detail": "reminder email encryption is unavailable"}
    assert "person@example.com" not in response.text


def test_admin_renders_generic_reminder_state_without_recipient_or_provider_data(
    app_client, monkeypatch
) -> None:
    from blindport import config
    from blindport.core.models import (
        ProductType,
        ReminderDeliveryState,
        ReminderKind,
        Subscription,
        User,
    )
    from blindport.db import engine
    from blindport.services.reminders import queue_reminder, store_reminder_email

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    with Session(engine) as session:
        user = User(hashed_token="admin-reminder-render")
        store_reminder_email(user, "private@example.com")
        session.add(user)
        session.flush()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            monthly_price_sats=1000,
            current_period_end=datetime.now(UTC) + timedelta(days=6),
        )
        session.add(subscription)
        session.flush()
        delivery = queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        delivery.state = ReminderDeliveryState.SENT
        delivery.sent_at = datetime.now(UTC)
        session.add(delivery)
        session.commit()

    client.post("/admin/login", data={"token": config.settings.ADMIN_TOKEN})
    response = client.get("/admin")
    assert response.status_code == 200
    assert "Reminder deliveries" in response.text
    assert 'data-label="Sent"' in response.text
    assert 'data-label="Provider"' not in response.text
    assert "private@example.com" not in response.text
