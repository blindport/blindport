"""Service announcement consent, campaign API, and SMTP delivery behavior."""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlmodel import Session, SQLModel, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _admin_auth() -> dict[str, str]:
    return {"Authorization": "Bearer TESTADMIN0000"}


def test_service_email_api_encrypts_and_cancels_queued_deliveries(app_client, monkeypatch) -> None:
    from blindport import config
    from blindport.core.models import NotificationDelivery, NotificationDeliveryState, User
    from blindport.db import engine
    from blindport.services import notification_reconciliation
    from blindport.services.announcements import create_announcement, queue_announcement

    client, _ = app_client
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    token = client.post("/api/v1/signup").json()["token"]

    saved = client.post(
        "/api/v1/me/service-email",
        json={"email": "Person@EXAMPLE.COM"},
        headers=_auth(token),
    )
    assert saved.status_code == 200
    assert saved.json() == {"configured": True}
    assert saved.headers["cache-control"] == "no-store"
    assert "example.com" not in saved.text.lower()

    with Session(engine) as session:
        user = session.exec(select(User).where(User.has_service_email)).one()
        assert "Person@example.com" not in (user.service_email_ciphertext or "")
        announcement = create_announcement(session, "Maintenance", "Service work tonight.", "test")
        queued = queue_announcement(session, announcement.id or 0)
        user_id = user.id
        user_generation = user.service_email_generation
        assert queued.recipient_count == 1
        assert session.exec(select(NotificationDelivery)).all() == []

    monkeypatch.setattr(notification_reconciliation.db, "engine", engine)
    assert notification_reconciliation._expand_queued_announcements(1) == 1
    with Session(engine) as session:
        delivery = session.exec(select(NotificationDelivery)).one()
        assert delivery.recipient_generation == user_generation

    deleted = client.delete("/api/v1/me/service-email", headers=_auth(token))
    assert deleted.status_code == 200
    assert deleted.json() == {"configured": False}
    with Session(engine) as session:
        user = session.exec(select(User).where(User.id == user_id)).one()
        delivery = session.exec(select(NotificationDelivery)).one()
        assert user.service_email_ciphertext is None
        assert delivery.state == NotificationDeliveryState.CANCELLED
        assert delivery.lease_token is None


def test_service_email_api_is_feature_gated_and_bounded(app_client, monkeypatch) -> None:
    from blindport import config

    client, _ = app_client
    token = client.post("/api/v1/signup").json()["token"]
    assert client.get("/api/v1/me/service-email", headers=_auth(token)).status_code == 404

    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    invalid = client.post(
        "/api/v1/me/service-email",
        content=b'{"email":"person@example.com"}' + b" " * 1024,
        headers={**_auth(token), "Content-Type": "application/json"},
    )
    assert invalid.status_code == 400
    assert invalid.headers["cache-control"] == "no-store"
    assert "person@example.com" not in invalid.text


def test_admin_announcement_api_uses_bearer_and_never_exports_addresses(
    app_client, monkeypatch
) -> None:
    from blindport import config
    from blindport.core.models import User
    from blindport.db import engine
    from blindport.services.announcements import store_service_announcement_email

    client, _ = app_client
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    with Session(engine) as session:
        eligible = User(hashed_token="eligible")
        suspended = User(hashed_token="suspended", is_suspended=True)
        administrator = User(hashed_token="administrator", is_admin=True)
        for user, address in (
            (eligible, "eligible@example.com"),
            (suspended, "suspended@example.com"),
            (administrator, "administrator@example.com"),
        ):
            store_service_announcement_email(user, address)
            session.add(user)
        session.commit()

    assert client.get("/api/v1/admin/announcements").status_code == 401
    created = client.post(
        "/api/v1/admin/announcements",
        json={"subject": "Scheduled maintenance", "body": "The service will restart at 02:00 UTC."},
        headers=_admin_auth(),
    )
    assert created.status_code == 201
    campaign = created.json()
    assert campaign["state"] == "draft"
    assert campaign["author_marker"] == "blindport-admin-api-v1"
    assert "example.com" not in created.text

    queued = client.post(
        f"/api/v1/admin/announcements/{campaign['id']}/queue", headers=_admin_auth()
    )
    assert queued.status_code == 200
    assert queued.json()["recipient_count"] == 1
    assert queued.json()["delivery_counts"] == {"queued": 1}
    assert "example.com" not in queued.text

    detail = client.get(f"/api/v1/admin/announcements/{campaign['id']}", headers=_admin_auth())
    assert detail.status_code == 200
    assert detail.json()["body"] == "The service will restart at 02:00 UTC."
    assert "example.com" not in detail.text


def test_browser_admin_announcements_require_session_and_separate_draft_queue_cancel(
    app_client, monkeypatch
) -> None:
    from blindport import config
    from blindport.core.models import (
        Announcement,
        AnnouncementDelivery,
        NotificationDelivery,
        NotificationDeliveryState,
        User,
    )
    from blindport.db import engine
    from blindport.services import notification_reconciliation
    from blindport.services.announcements import store_service_announcement_email

    client, _ = app_client
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    address = "browser-admin-recipient@example.com"
    with Session(engine) as session:
        recipient = User(hashed_token="browser-admin-recipient")
        store_service_announcement_email(recipient, address)
        session.add(recipient)
        session.commit()

    for path in (
        "/admin/announcements",
        "/admin/announcements/1/queue",
        "/admin/announcements/1/cancel",
    ):
        response = client.post(
            path,
            data={"subject": "Maintenance", "body": "Scheduled service work."},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/admin"
    with Session(engine) as session:
        assert session.exec(select(Announcement)).all() == []

    login = client.post("/admin/login", data={"token": "TESTADMIN0000"}, follow_redirects=False)
    assert login.status_code == 303
    created = client.post(
        "/admin/announcements",
        data={"subject": "Maintenance", "body": "Scheduled service work."},
        follow_redirects=False,
    )
    assert created.status_code == 303
    with Session(engine) as session:
        campaign = session.exec(select(Announcement)).one()
        assert campaign.state.value == "draft"
        assert session.exec(select(AnnouncementDelivery)).all() == []

    admin = client.get("/admin")
    assert admin.status_code == 200
    assert address not in admin.text
    assert "browser-admin-recipient@example.com" not in admin.text

    for _ in range(2):
        queued = client.post(f"/admin/announcements/{campaign.id}/queue", follow_redirects=False)
        assert queued.status_code == 303
    with Session(engine) as session:
        queued_campaign = session.get(Announcement, campaign.id)
        deliveries = session.exec(select(AnnouncementDelivery)).all()
        assert queued_campaign is not None
        assert queued_campaign.state.value == "queued"
        assert queued_campaign.recipient_count == 1
        assert deliveries == []

    monkeypatch.setattr(notification_reconciliation.db, "engine", engine)
    assert notification_reconciliation._expand_queued_announcements(1) == 1
    with Session(engine) as session:
        assert len(session.exec(select(NotificationDelivery)).all()) == 1

    for _ in range(2):
        cancelled = client.post(
            f"/admin/announcements/{campaign.id}/cancel", follow_redirects=False
        )
        assert cancelled.status_code == 303
    with Session(engine) as session:
        cancelled_campaign = session.get(Announcement, campaign.id)
        delivery = session.exec(select(NotificationDelivery)).one()
        assert cancelled_campaign is not None
        assert cancelled_campaign.state.value == "cancelled"
        assert delivery.state == NotificationDeliveryState.CANCELLED

    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", False)
    assert "announcementEmailForm" not in client.get("/dashboard").text
    gated_admin = client.get("/admin")
    assert "Service announcements" not in gated_admin.text
    rejected = client.post("/admin/announcements", data={"subject": "No", "body": "No"})
    assert rejected.status_code == 404


def test_legacy_announcement_delivery_send_and_validation() -> None:
    from blindport.core.credentials import CredentialCipher
    from blindport.core.models import AnnouncementDelivery, AnnouncementDeliveryState, User
    from blindport.services.announcements import (
        AnnouncementError,
        announcement_message_id,
        create_announcement,
        send_announcement,
        store_service_announcement_email,
    )

    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    cipher = CredentialCipher("11" * 32)

    class Smtp:
        calls: list[tuple[str, str, str, str]] = []

        def send_message(self, recipient: str, subject: str, body: str, message_id: str) -> None:
            self.calls.append((recipient, subject, body, message_id))

    with Session(engine) as session:
        user = User(hashed_token="announcement-user")
        store_service_announcement_email(user, "person@example.com", cipher=cipher)
        session.add(user)
        session.commit()
        campaign = create_announcement(session, "Notice", "Plain text only.\n", "test")
        delivery = AnnouncementDelivery(
            announcement_id=campaign.id or 0,
            user_id=user.id or 0,
            recipient_generation=user.service_email_generation,
        )
        session.add(delivery)
        session.commit()
        message_id = announcement_message_id(delivery)
        sent = send_announcement(session, delivery, user, campaign, Smtp(), cipher=cipher)
        assert sent.state == AnnouncementDeliveryState.SENT
        assert Smtp.calls[0] == ("person@example.com", "Notice", "Plain text only.\n", message_id)
        assert message_id == announcement_message_id(delivery)

    with pytest.raises(AnnouncementError, match="subject is invalid"):
        create_announcement(Session(engine), "Notice\r\nBcc: victim@example.com", "body", "test")
    with pytest.raises(AnnouncementError, match="body is invalid"):
        create_announcement(Session(engine), "Notice", "bad\x00body", "test")


def test_announcement_reconciliation_is_bounded_and_recovers_sending(monkeypatch, tmp_path) -> None:
    from blindport import config
    from blindport.core.models import AnnouncementDelivery, AnnouncementDeliveryState, User
    from blindport.services import announcement_reconciliation
    from blindport.services.announcements import (
        create_announcement,
        queue_announcement,
        store_service_announcement_email,
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'announcements.db'}")
    SQLModel.metadata.create_all(engine)
    monkeypatch.setattr(announcement_reconciliation.db, "engine", engine)
    monkeypatch.setattr(config.settings, "ANNOUNCEMENT_EMAIL_ENABLED", True)
    with Session(engine) as session:
        user = User(hashed_token="announcement-worker")
        store_service_announcement_email(user, "person@example.com")
        session.add(user)
        session.commit()
        announcement = create_announcement(session, "Notice", "Maintenance", "test")
        announcement = queue_announcement(session, announcement.id or 0)
        delivery = AnnouncementDelivery(
            announcement_id=announcement.id or 0,
            user_id=user.id or 0,
            recipient_generation=user.service_email_generation,
        )
        session.add(delivery)
        session.commit()
        delivery.state = AnnouncementDeliveryState.SENDING
        delivery.attempt_count = 1
        session.add(delivery)
        session.commit()

    summary = announcement_reconciliation.reconcile_announcements_once(batch_size=1)
    assert (summary.scanned, summary.sent, summary.failed) == (1, 0, 1)
    with Session(engine) as session:
        delivery = session.exec(select(AnnouncementDelivery)).one()
        assert delivery.state == AnnouncementDeliveryState.DELIVERY_AMBIGUOUS
        assert delivery.error_code == "worker_interrupted"


def test_notification_worker_failure_isolated_from_payment_reconciliation(
    app_client, monkeypatch
) -> None:
    del app_client
    from blindport.services import notification_reconciliation, payment_reconciliation

    monkeypatch.setattr(payment_reconciliation.settings, "PAYMENT_ENABLED_METHODS", "lightning")
    monkeypatch.setattr(notification_reconciliation.config.settings, "REMINDER_EMAIL_ENABLED", True)
    monkeypatch.setattr(notification_reconciliation, "_queue_due_expirations", lambda now, size: 0)
    monkeypatch.setattr(
        notification_reconciliation,
        "reconcile_reminders_once",
        lambda batch_size: (_ for _ in ()).throw(RuntimeError("legacy drain failed")),
    )

    with pytest.raises(RuntimeError, match="legacy drain failed"):
        notification_reconciliation.reconcile_notifications_once(batch_size=1)
    summary = payment_reconciliation.reconcile_pending_payments_once(batch_size=3)
    assert (summary.scanned, summary.failed) == (0, 0)
