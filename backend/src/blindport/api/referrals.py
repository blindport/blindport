"""Bearer-authenticated referral payout administration API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import Session

from ..core.auth import AdminPrincipal, current_admin
from ..core.models import ReferralPayout
from ..db import get_session
from ..services import referrals as referrals_svc

router = APIRouter(prefix="/api/v1/admin/referrals")


class PayoutReservationRequest(BaseModel):
    """The only operator input required to reserve an address's credits."""

    model_config = ConfigDict(extra="forbid")

    address: str = Field(strict=True, min_length=1, max_length=254)


class PayoutPaidRequest(BaseModel):
    """A durable external reference recorded after an operator pays manually."""

    model_config = ConfigDict(extra="forbid")

    external_reference: str = Field(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9_.:-]{1,128}$",
    )


class ReferralBalanceResponse(BaseModel):
    address: str
    available_sats: int
    reserved_sats: int
    paid_sats: int
    payout_eligible: bool


class ReferralBalancePageResponse(BaseModel):
    items: list[ReferralBalanceResponse]
    offset: int
    limit: int
    total: int
    minimum_payout_sats: int


class ReferralPayoutResponse(BaseModel):
    id: UUID
    address: str
    amount_sats: int
    status: Literal["reserved", "paid"]
    external_reference: str | None
    created_at: datetime
    paid_at: datetime | None


class ReferralPayoutPageResponse(BaseModel):
    items: list[ReferralPayoutResponse]
    offset: int
    limit: int
    total: int


class SettlementReviewPaymentResponse(BaseModel):
    payment_id: int
    status: str
    amount_sats: int
    markup_sats: int
    referral_address: str | None
    settlement_verified_at: datetime | None
    created_at: datetime


class SettlementReviewPaymentPageResponse(BaseModel):
    items: list[SettlementReviewPaymentResponse]
    offset: int
    limit: int
    total: int


@router.get("/balances", response_model=ReferralBalancePageResponse)
def list_balances(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> ReferralBalancePageResponse:
    balances, total = referrals_svc.list_referral_balances(session, offset=offset, limit=limit)
    return ReferralBalancePageResponse(
        items=[
            ReferralBalanceResponse(
                address=balance.address,
                available_sats=balance.available_sats,
                reserved_sats=balance.reserved_sats,
                paid_sats=balance.paid_sats,
                payout_eligible=balance.available_sats >= referrals_svc.MINIMUM_PAYOUT_SATS,
            )
            for balance in balances
        ],
        offset=offset,
        limit=limit,
        total=total,
        minimum_payout_sats=referrals_svc.MINIMUM_PAYOUT_SATS,
    )


@router.get("/payouts", response_model=ReferralPayoutPageResponse)
def list_payouts(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> ReferralPayoutPageResponse:
    payouts, total = referrals_svc.list_referral_payouts(session, offset=offset, limit=limit)
    return ReferralPayoutPageResponse(
        items=[_payout_response(payout) for payout in payouts],
        offset=offset,
        limit=limit,
        total=total,
    )


@router.get("/settlement-review", response_model=SettlementReviewPaymentPageResponse)
def list_settlement_review(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> SettlementReviewPaymentPageResponse:
    payments, total = referrals_svc.list_settlement_review_payments(
        session, offset=offset, limit=limit
    )
    return SettlementReviewPaymentPageResponse(
        items=[
            SettlementReviewPaymentResponse(
                payment_id=payment.payment_id,
                status=payment.status,
                amount_sats=payment.amount_sats,
                markup_sats=payment.markup_sats,
                referral_address=payment.referral_address,
                settlement_verified_at=_as_utc(payment.settlement_verified_at),
                created_at=_as_utc(payment.created_at),
            )
            for payment in payments
        ],
        offset=offset,
        limit=limit,
        total=total,
    )


@router.put("/payouts/{payout_id}", response_model=ReferralPayoutResponse)
def reserve_address_payout(
    payout_id: UUID,
    body: PayoutReservationRequest,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> ReferralPayoutResponse:
    try:
        payout = referrals_svc.reserve_payout(session, payout_id=payout_id, address=body.address)
        response = _payout_response(payout)
        session.commit()
        return response
    except referrals_svc.ReferralBalanceTooLowError as error:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except referrals_svc.ReferralPayoutConflictError as error:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        session.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error


@router.post("/payouts/{payout_id}/paid", response_model=ReferralPayoutResponse)
def record_paid_payout(
    payout_id: UUID,
    body: PayoutPaidRequest,
    _admin: AdminPrincipal = Depends(current_admin),
    session: Session = Depends(get_session),
) -> ReferralPayoutResponse:
    try:
        payout = referrals_svc.mark_payout_paid(
            session,
            payout_id=payout_id,
            external_reference=body.external_reference,
        )
        response = _payout_response(payout)
        session.commit()
        return response
    except referrals_svc.ReferralPayoutNotFoundError as error:
        session.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(error)) from error
    except referrals_svc.ReferralPayoutConflictError as error:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from error
    except ValueError as error:
        session.rollback()
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from error


def _payout_response(payout: ReferralPayout) -> ReferralPayoutResponse:
    return ReferralPayoutResponse(
        id=payout.id,
        address=payout.address,
        amount_sats=payout.amount_sats,
        status=payout.status,
        external_reference=payout.external_reference,
        created_at=_as_utc(payout.created_at),
        paid_at=_as_utc(payout.paid_at),
    )


def _as_utc(value: datetime | None) -> datetime | None:
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value
