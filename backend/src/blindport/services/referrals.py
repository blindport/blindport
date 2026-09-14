"""Referral credits and manually recorded payout reservations."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import case, func, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlmodel import Session, select

from ..core.lightning_address import validate_lightning_address
from ..core.models import Payment, PaymentStatus, ReferralCredit, ReferralPayout

MINIMUM_PAYOUT_SATS = 10_000
MAX_REFERRAL_COMMISSION_BPS = 10_000
_EXTERNAL_REFERENCE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


class ReferralPayoutNotFoundError(ValueError):
    """A payout ID does not identify a stored payout."""


class ReferralPayoutConflictError(ValueError):
    """A payout request conflicts with a reservation or recorded payment."""


class ReferralBalanceTooLowError(ValueError):
    """The address has not reached the manual payout minimum."""


@dataclass(frozen=True, slots=True)
class ReferralBalance:
    """Aggregated credit states for one referral address."""

    address: str
    available_sats: int
    reserved_sats: int
    paid_sats: int


@dataclass(frozen=True, slots=True)
class SettlementReviewPayment:
    """Minimal operator view of an LNURL settlement requiring review."""

    payment_id: int
    status: str
    amount_sats: int
    markup_sats: int
    referral_address: str | None
    settlement_verified_at: datetime | None
    created_at: datetime


def credit_settled_payment(session: Session, payment: Payment) -> ReferralCredit | None:
    """Stage the one referral credit allowed for an eligible settled payment.

    The caller owns the payment settlement transaction and must commit it. The
    credit primary key is the payment ID, so the database remains the final
    one-credit invariant even if this function is accidentally retried.
    """
    if (
        payment.status != PaymentStatus.PAID
        or payment.invoice_provider != "lnurl"
        or payment.settlement_verified_at is None
        or payment.settlement_review_required
        or not payment.referral_address
    ):
        return None

    commission_bps = payment.referral_commission_bps
    if not isinstance(commission_bps, int) or isinstance(commission_bps, bool):
        raise ValueError("referral commission must be an integer")
    if commission_bps <= 0:
        return None
    if commission_bps > MAX_REFERRAL_COMMISSION_BPS:
        raise ValueError("referral commission exceeds 10000 basis points")

    amount_sats = payment.amount_sats
    markup_sats = payment.markup_sats
    if (
        not isinstance(amount_sats, int)
        or isinstance(amount_sats, bool)
        or not isinstance(markup_sats, int)
        or isinstance(markup_sats, bool)
        or amount_sats < 0
        or markup_sats < 0
        or markup_sats > amount_sats
    ):
        raise ValueError("payment and markup amounts are outside the referral credit range")
    if payment.id is None:
        raise ValueError("settled payment must be stored before creating a referral credit")

    address = validate_lightning_address(payment.referral_address)
    commission_sats = ((amount_sats - markup_sats) * commission_bps) // 10_000
    if commission_sats == 0:
        return None

    existing = session.get(ReferralCredit, payment.id)
    if existing is not None:
        return existing

    credit = ReferralCredit(
        payment_id=payment.id,
        address=address,
        amount_sats=commission_sats,
    )
    session.add(credit)
    return credit


def reserve_payout(
    session: Session,
    *,
    payout_id: UUID,
    address: str,
) -> ReferralPayout:
    """Reserve every currently available credit for one address without committing."""
    canonical_address = validate_lightning_address(address)
    existing = session.get(ReferralPayout, payout_id)
    if existing is not None:
        return _idempotent_payout(existing, canonical_address)

    credits = session.exec(
        select(ReferralCredit)
        .where(
            ReferralCredit.address == canonical_address,
            ReferralCredit.payout_id.is_(None),  # type: ignore[union-attr]
        )
        .order_by(ReferralCredit.payment_id)
        .with_for_update()
    ).all()
    amount_sats = sum(credit.amount_sats for credit in credits)
    if amount_sats < MINIMUM_PAYOUT_SATS:
        raise ReferralBalanceTooLowError("available referral credit is below the payout minimum")

    payout = ReferralPayout(
        id=payout_id,
        address=canonical_address,
        amount_sats=amount_sats,
    )
    credit_ids = [credit.payment_id for credit in credits]
    try:
        session.add(payout)
        session.flush()
        claimed = session.execute(
            update(ReferralCredit)
            .where(
                ReferralCredit.payment_id.in_(credit_ids),
                ReferralCredit.payout_id.is_(None),  # type: ignore[union-attr]
            )
            .values(payout_id=payout_id)
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != len(credit_ids):  # type: ignore[attr-defined]
            session.rollback()
            return _resolve_reservation_after_conflict(session, payout_id, canonical_address)
    except IntegrityError:
        session.rollback()
        return _resolve_reservation_after_conflict(session, payout_id, canonical_address)
    except OperationalError as error:
        session.rollback()
        if _is_sqlite_lock_error(error):
            raise ReferralPayoutConflictError(
                "payout reservation conflicted; retry the request"
            ) from error
        raise
    return payout


def mark_payout_paid(
    session: Session,
    *,
    payout_id: UUID,
    external_reference: str,
) -> ReferralPayout:
    """Record an operator-completed payout without sending funds or committing."""
    _validate_external_reference(external_reference)
    payout = session.exec(
        select(ReferralPayout)
        .where(ReferralPayout.id == payout_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).one_or_none()
    if payout is None:
        raise ReferralPayoutNotFoundError("referral payout not found")
    if payout.status == "paid":
        if payout.external_reference == external_reference:
            return payout
        raise ReferralPayoutConflictError("payout was already recorded with another reference")

    reference_owner = session.exec(
        select(ReferralPayout.id).where(ReferralPayout.external_reference == external_reference)
    ).first()
    if reference_owner is not None and reference_owner != payout_id:
        raise ReferralPayoutConflictError("external reference belongs to another payout")

    try:
        updated = session.execute(
            update(ReferralPayout)
            .where(
                ReferralPayout.id == payout_id,
                ReferralPayout.status == "reserved",
                ReferralPayout.external_reference.is_(None),  # type: ignore[union-attr]
            )
            .values(
                status="paid",
                external_reference=external_reference,
                paid_at=datetime.now(UTC),
            )
            .execution_options(synchronize_session=False)
        )
        if updated.rowcount != 1:  # type: ignore[attr-defined]
            session.rollback()
            return _resolve_paid_after_conflict(session, payout_id, external_reference)
    except IntegrityError:
        session.rollback()
        return _resolve_paid_after_conflict(session, payout_id, external_reference)
    except OperationalError as error:
        session.rollback()
        if _is_sqlite_lock_error(error):
            raise ReferralPayoutConflictError(
                "payout payment conflicted; retry the request"
            ) from error
        raise
    session.refresh(payout)
    return payout


def list_referral_balances(
    session: Session,
    *,
    offset: int,
    limit: int,
) -> tuple[list[ReferralBalance], int]:
    """Return paginated referral balances grouped by canonical address."""
    available_sats = func.coalesce(
        func.sum(
            case(
                (ReferralCredit.payout_id.is_(None), ReferralCredit.amount_sats),  # type: ignore[union-attr]
                else_=0,
            )
        ),
        0,
    ).label("available_sats")
    reserved_sats = func.coalesce(
        func.sum(case((ReferralPayout.status == "reserved", ReferralCredit.amount_sats), else_=0)),
        0,
    ).label("reserved_sats")
    paid_sats = func.coalesce(
        func.sum(case((ReferralPayout.status == "paid", ReferralCredit.amount_sats), else_=0)),
        0,
    ).label("paid_sats")
    statement = (
        select(ReferralCredit.address, available_sats, reserved_sats, paid_sats)
        .select_from(ReferralCredit)
        .outerjoin(ReferralPayout, ReferralCredit.payout_id == ReferralPayout.id)
        .group_by(ReferralCredit.address)
        .order_by(ReferralCredit.address)
        .offset(offset)
        .limit(limit)
    )
    rows = session.exec(statement).all()
    balances = [
        ReferralBalance(
            address=str(address),
            available_sats=int(available),
            reserved_sats=int(reserved),
            paid_sats=int(paid),
        )
        for address, available, reserved, paid in rows
    ]
    total = int(
        session.exec(
            select(func.count()).select_from(select(ReferralCredit.address).distinct().subquery())
        ).one()
    )
    return balances, total


def list_referral_payouts(
    session: Session,
    *,
    offset: int,
    limit: int,
) -> tuple[list[ReferralPayout], int]:
    """Return paginated payout reservations in stable newest-first order."""
    payouts = session.exec(
        select(ReferralPayout)
        .order_by(ReferralPayout.created_at.desc(), ReferralPayout.id.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    total = int(session.exec(select(func.count()).select_from(ReferralPayout)).one())
    return payouts, total


def list_settlement_review_payments(
    session: Session,
    *,
    offset: int,
    limit: int,
) -> tuple[list[SettlementReviewPayment], int]:
    """Return LNURL payment summaries still awaiting an operator settlement review."""
    statement = (
        select(
            Payment.id,
            Payment.status,
            Payment.amount_sats,
            Payment.markup_sats,
            Payment.referral_address,
            Payment.settlement_verified_at,
            Payment.created_at,
        )
        .where(
            Payment.invoice_provider == "lnurl",
            Payment.settlement_review_required.is_(True),  # type: ignore[union-attr]
        )
        .order_by(Payment.created_at.desc(), Payment.id.desc())
        .offset(offset)
        .limit(limit)
    )
    rows = session.exec(statement).all()
    payments = [
        SettlementReviewPayment(
            payment_id=payment_id,
            status=str(payment_status),
            amount_sats=amount_sats,
            markup_sats=markup_sats,
            referral_address=referral_address,
            settlement_verified_at=settlement_verified_at,
            created_at=created_at,
        )
        for (
            payment_id,
            payment_status,
            amount_sats,
            markup_sats,
            referral_address,
            settlement_verified_at,
            created_at,
        ) in rows
        if payment_id is not None
    ]
    total = int(
        session.exec(
            select(func.count())
            .select_from(Payment)
            .where(
                Payment.invoice_provider == "lnurl",
                Payment.settlement_review_required.is_(True),  # type: ignore[union-attr]
            )
        ).one()
    )
    return payments, total


def _idempotent_payout(payout: ReferralPayout, address: str) -> ReferralPayout:
    if payout.address != address:
        raise ReferralPayoutConflictError("payout ID belongs to another address")
    return payout


def _resolve_reservation_after_conflict(
    session: Session,
    payout_id: UUID,
    address: str,
) -> ReferralPayout:
    existing = session.get(ReferralPayout, payout_id)
    if existing is not None:
        return _idempotent_payout(existing, address)
    raise ReferralPayoutConflictError("payout reservation conflicted; retry the request")


def _resolve_paid_after_conflict(
    session: Session,
    payout_id: UUID,
    external_reference: str,
) -> ReferralPayout:
    payout = session.get(ReferralPayout, payout_id)
    if (
        payout is not None
        and payout.status == "paid"
        and payout.external_reference == external_reference
    ):
        return payout
    raise ReferralPayoutConflictError("external reference belongs to another payout")


def _validate_external_reference(value: str) -> None:
    if not isinstance(value, str) or _EXTERNAL_REFERENCE_RE.fullmatch(value) is None:
        raise ValueError("external reference must be a 1-128 character ASCII identifier")


def _is_sqlite_lock_error(error: OperationalError) -> bool:
    return "database is locked" in str(error).lower()
