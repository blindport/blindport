"""Unified notification email API behavior."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _enable_email(client, token: str) -> None:
    response = client.post(
        "/api/v1/me/notification-email",
        json={"email": "Person@EXAMPLE.COM"},
        headers=_auth(token),
    )
    assert response.status_code == 200
    assert response.json() == {"configured": True}
    assert response.headers["cache-control"] == "no-store"
    assert "example.com" not in response.text.lower()


def test_notification_email_encrypts_and_old_routes_are_absent(app_client, monkeypatch) -> None:
    from blindport import config
    from blindport.core.models import User
    from blindport.db import engine

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    _enable_email(client, token)

    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_notification_email)).one()
        assert "Person@example.com" not in (user.notification_email_ciphertext or "")
        assert user.notification_email_generation == 1

    assert client.get("/api/v1/me/notification-email", headers=_auth(token)).json() == {
        "configured": True
    }
    for path in ("/api/v1/me/reminder-email", "/api/v1/me/service-email"):
        assert client.get(path, headers=_auth(token)).status_code == 404


def test_notification_email_rejects_invalid_input_without_pii(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    invalid_email = "Person <person@example.com>"

    response = client.post(
        "/api/v1/me/notification-email", json={"email": invalid_email}, headers=_auth(token)
    )

    assert response.status_code == 400
    assert response.json() == {"detail": "notification email address is invalid"}
    assert invalid_email not in response.text


def test_notification_email_change_cancels_all_queued_categories(app_client, monkeypatch) -> None:
    from blindport import config
    from blindport.core.models import (
        Announcement,
        AnnouncementDelivery,
        AnnouncementDeliveryState,
        NotificationCategory,
        NotificationDelivery,
        NotificationDeliveryState,
        NotificationKind,
        ProductType,
        ReminderDelivery,
        ReminderDeliveryState,
        ReminderKind,
        Subscription,
        SubscriptionStatus,
        User,
    )
    from blindport.db import engine
    from blindport.services.notifications import queue_notification
    from blindport.services.reminders import queue_reminder

    client, _ = app_client
    monkeypatch.setattr(config.settings, "REMINDER_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]
    _enable_email(client, token)
    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_notification_email)).one()
        subscription = Subscription(
            user_id=user.id,
            product=ProductType.IP,
            status=SubscriptionStatus.ACTIVE,
            monthly_price_sats=0,
            current_period_end=datetime.now(UTC) + timedelta(days=6),
        )
        announcement = Announcement(subject="Notice", body="Body", author_marker="test")
        session.add_all([subscription, announcement])
        session.flush()
        queue_reminder(session, subscription, ReminderKind.SEVEN_DAY)
        queue_notification(
            session,
            user,
            NotificationCategory.ACCOUNT,
            NotificationKind.EXPIRATION_7_DAY,
            "api-account",
            subscription=subscription,
            event_at=subscription.current_period_end,
        )
        queue_notification(
            session,
            user,
            NotificationCategory.SERVICE,
            NotificationKind.SERVICE_ANNOUNCEMENT,
            "api-service",
            announcement=announcement,
        )
        session.add(
            AnnouncementDelivery(
                announcement_id=announcement.id or 0,
                user_id=user.id or 0,
                recipient_generation=user.notification_email_generation,
            )
        )
        session.commit()
        generation = user.notification_email_generation

    response = client.delete("/api/v1/me/notification-email", headers=_auth(token))
    assert response.json() == {"configured": False}
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id.is_not(None))).one()
        assert user.notification_email_generation == generation + 1
        assert user.notification_email_ciphertext is None
        assert session.exec(select(ReminderDelivery)).one().state == ReminderDeliveryState.CANCELLED
        assert {
            delivery.state for delivery in session.exec(select(NotificationDelivery)).all()
        } == {NotificationDeliveryState.CANCELLED}
        assert (
            session.exec(select(AnnouncementDelivery)).one().state
            == AnnouncementDeliveryState.CANCELLED
        )
