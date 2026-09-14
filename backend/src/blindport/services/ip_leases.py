"""Durable dedicated IP assignment episodes and SMTP exception audit state."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlmodel import Session, select

from ..config import settings
from ..core.models import IPLease, IPLeaseDelivery, IPLeaseState, ProductType, Subscription


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _bounded_reason(value: str, fallback: str) -> str:
    normalized = " ".join(value.split())
    sanitized = "".join(
        character for character in normalized if character.isascii() and character.isprintable()
    )
    return (sanitized or fallback)[:255]


def _audit_text(value: str, field_name: str, max_length: int) -> str:
    if (
        not value
        or value.strip() != value
        or len(value) > max_length
        or not value.isascii()
        or not value.isprintable()
    ):
        raise ValueError(f"{field_name} must be trimmed printable ASCII")
    return value


def current_lease(session: Session, subscription_id: int) -> IPLease | None:
    return session.exec(
        select(IPLease).where(
            IPLease.subscription_id == subscription_id,
            IPLease.released_at.is_(None),  # type: ignore[union-attr]
        )
    ).one_or_none()


def reserve(
    session: Session,
    subscription: Subscription,
    payment_id: int,
    address: str,
) -> IPLease | None:
    """Create an IP episode in the caller's reservation transaction."""
    if subscription.product != ProductType.IP or subscription.id is None:
        return None
    now = _utcnow()
    lease = IPLease(
        subscription_id=subscription.id,
        reservation_payment_id=payment_id,
        address=address,
        delivery=IPLeaseDelivery(subscription.delivery.value),
        state=IPLeaseState.RESERVED,
        reserved_at=now,
        created_at=now,
        updated_at=now,
    )
    session.add(lease)
    session.flush()
    return lease


def activate(session: Session, subscription: Subscription) -> None:
    if subscription.product != ProductType.IP or subscription.id is None:
        return
    lease = current_lease(session, subscription.id)
    if lease is None or lease.address != subscription.assigned_ip:
        raise ValueError("Blindport IP lease is no longer available")
    now = _utcnow()
    lease.state = IPLeaseState.ACTIVE
    lease.activated_at = lease.activated_at or now
    lease.expired_at = None
    lease.quarantined_at = None
    lease.quarantine_until = None
    lease.reservation_payment_id = None
    lease.updated_at = now
    session.add(lease)


def quarantine(
    session: Session,
    subscription: Subscription,
    quarantine_until: datetime,
) -> None:
    if subscription.product != ProductType.IP or subscription.id is None:
        return
    lease = current_lease(session, subscription.id)
    if lease is None:
        return
    now = _utcnow()
    lease.state = IPLeaseState.QUARANTINED
    lease.expired_at = lease.expired_at or now
    lease.quarantined_at = now
    lease.quarantine_until = quarantine_until
    lease.reservation_payment_id = None
    lease.smtp_enabled = False
    lease.updated_at = now
    session.add(lease)


def release(session: Session, subscription: Subscription, reason: str) -> bool:
    if subscription.product != ProductType.IP or subscription.id is None:
        return False
    lease = current_lease(session, subscription.id)
    if lease is None:
        return False
    now = _utcnow()
    lease.state = IPLeaseState.RELEASED
    lease.released_at = now
    lease.release_reason = _bounded_reason(reason, "released")
    lease.reservation_payment_id = None
    lease.smtp_enabled = False
    lease.updated_at = now
    session.add(lease)
    return True


def active_routed_lease(session: Session, subscription_id: int) -> IPLease:
    lease = session.exec(
        select(IPLease)
        .where(
            IPLease.subscription_id == subscription_id,
            IPLease.released_at.is_(None),  # type: ignore[union-attr]
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if (
        lease is None
        or lease.delivery != IPLeaseDelivery.WIREGUARD
        or lease.state != IPLeaseState.ACTIVE
    ):
        raise ValueError("subscription has no current active routed IP lease")
    return lease


def approve_smtp(
    session: Session,
    subscription: Subscription,
    *,
    intended_use: str,
    fee_paid_sats: int,
    review_reference: str,
    reviewed_by: str,
) -> IPLease:
    if fee_paid_sats < settings.WIREGUARD_SMTP_EGRESS_FEE_SATS:
        raise ValueError(
            f"fee_paid_sats must be at least {settings.WIREGUARD_SMTP_EGRESS_FEE_SATS}"
        )
    intended_use = _audit_text(intended_use, "intended_use", 500)
    review_reference = _audit_text(review_reference, "review_reference", 200)
    if subscription.id is None:
        raise ValueError("subscription has no id")
    lease = active_routed_lease(session, subscription.id)
    now = _utcnow()
    lease.smtp_enabled = True
    lease.smtp_intended_use = intended_use
    lease.smtp_fee_paid_sats = fee_paid_sats
    lease.smtp_reviewed_at = now
    lease.smtp_reviewed_by = reviewed_by[:100]
    lease.smtp_review_reference = review_reference
    lease.smtp_revoked_at = None
    lease.smtp_revocation_reason = None
    lease.updated_at = now
    session.add(lease)
    session.commit()
    session.refresh(lease)
    return lease


def revoke_smtp(
    session: Session,
    subscription: Subscription,
    *,
    reason: str,
) -> IPLease:
    if subscription.id is None:
        raise ValueError("subscription has no id")
    lease = active_routed_lease(session, subscription.id)
    now = _utcnow()
    lease.smtp_enabled = False
    lease.smtp_revoked_at = now
    lease.smtp_revocation_reason = _bounded_reason(reason, "revoked")
    lease.updated_at = now
    session.add(lease)
    session.commit()
    session.refresh(lease)
    return lease


def revoke_smtp_for_user(session: Session, user_id: int, *, reason: str) -> int:
    """Revoke every current SMTP exception in the caller's account transaction."""
    leases = session.exec(
        select(IPLease)
        .join(Subscription, Subscription.id == IPLease.subscription_id)
        .where(
            Subscription.user_id == user_id,
            IPLease.released_at.is_(None),  # type: ignore[union-attr]
            IPLease.smtp_enabled.is_(True),  # type: ignore[union-attr]
        )
        .with_for_update()
    ).all()
    now = _utcnow()
    bounded_reason = _bounded_reason(reason, "revoked")
    for lease in leases:
        lease.smtp_enabled = False
        lease.smtp_revoked_at = now
        lease.smtp_revocation_reason = bounded_reason
        lease.updated_at = now
        session.add(lease)
    return len(leases)
