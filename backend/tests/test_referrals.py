"""Referral credit, reservation, and manual payout API regressions."""

from __future__ import annotations

import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine, select

from blindport.api.referrals import router
from blindport.config import settings
from blindport.core.models import (
    Payment,
    PaymentMethod,
    PaymentStatus,
    ReferralCredit,
    ReferralPayout,
)
from blindport.db import get_session
from blindport.services import referrals


def _admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {settings.ADMIN_TOKEN}"}


@pytest.fixture
def referral_engine(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'referrals.db'}",
        connect_args={"check_same_thread": False, "timeout": 2},
    )
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture
def referral_client(referral_engine):
    app = FastAPI()
    app.include_router(router)

    def override_session():
        with Session(referral_engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        yield client


def _payment(
    session: Session,
    *,
    amount_sats: int = 20_000,
    markup_sats: int = 0,
    address: str | None = "alice@wallet.co",
    commission_bps: int = 5_000,
    invoice_provider: str | None = "lnurl",
    settlement_verified_at: datetime | None = None,
    settlement_review_required: bool = False,
) -> Payment:
    payment = Payment(
        subscription_id=1,
        method=PaymentMethod.LIGHTNING,
        status=PaymentStatus.PAID,
        amount_sats=amount_sats,
        markup_sats=markup_sats,
        referral_address=address,
        referral_commission_bps=commission_bps,
        invoice_provider=invoice_provider,
        settlement_verified_at=settlement_verified_at or datetime.now(UTC),
        settlement_review_required=settlement_review_required,
    )
    session.add(payment)
    session.commit()
    assert payment.id is not None
    return payment


def _credit(session: Session, address: str, amount_sats: int) -> ReferralCredit:
    payment = _payment(session, address=address)
    assert payment.id is not None
    credit = ReferralCredit(payment_id=payment.id, address=address, amount_sats=amount_sats)
    session.add(credit)
    session.commit()
    return credit


def test_credit_settled_payment_creates_one_credit_and_excludes_markup(referral_engine) -> None:
    with Session(referral_engine) as session:
        payment = _payment(
            session,
            amount_sats=25_000,
            markup_sats=5_000,
            commission_bps=2_500,
            address="Alice@Wallet.Co",
        )

        credit = referrals.credit_settled_payment(session, payment)
        assert credit is not None
        assert (credit.address, credit.amount_sats) == ("alice@wallet.co", 5_000)
        assert referrals.credit_settled_payment(session, payment) is credit
        session.commit()
        payment_id = payment.id

        zero_base = _payment(
            session,
            amount_sats=20_000,
            markup_sats=20_000,
            commission_bps=5_000,
        )
        assert referrals.credit_settled_payment(session, zero_base) is None
        session.commit()

    with Session(referral_engine) as session:
        credits = session.exec(select(ReferralCredit)).all()
        assert len(credits) == 1
        assert (credits[0].payment_id, credits[0].address, credits[0].amount_sats) == (
            payment_id,
            "alice@wallet.co",
            5_000,
        )


def test_credit_settled_payment_rejects_invalid_address_without_io(
    referral_engine, monkeypatch
) -> None:
    def fail_network(*args, **kwargs):
        raise AssertionError("address validation must not perform network I/O")

    monkeypatch.setattr(socket, "getaddrinfo", fail_network)
    with Session(referral_engine) as session:
        payment = _payment(session, address="alice@localhost")
        with pytest.raises(ValueError, match="domain is invalid"):
            referrals.credit_settled_payment(session, payment)

        legacy = _payment(session, invoice_provider=None)
        mock = _payment(session, invoice_provider="mock")
        unverified = _payment(session)
        unverified.settlement_verified_at = None
        session.add(unverified)
        session.commit()
        review_required = _payment(session, settlement_review_required=True)
        zero_rate = _payment(session, commission_bps=0)
        assert referrals.credit_settled_payment(session, legacy) is None
        assert referrals.credit_settled_payment(session, mock) is None
        assert referrals.credit_settled_payment(session, unverified) is None
        assert referrals.credit_settled_payment(session, review_required) is None
        assert referrals.credit_settled_payment(session, zero_rate) is None
        assert session.exec(select(ReferralCredit)).all() == []


def test_admin_balance_and_review_routes_require_bearer_and_paginate(
    referral_engine, referral_client
) -> None:
    with Session(referral_engine) as session:
        _credit(session, "alice@wallet.co", 11_000)

        reserved = ReferralPayout(address="alice@wallet.co", amount_sats=10_000)
        session.add(reserved)
        session.flush()
        reserved_credit = _credit(session, "alice@wallet.co", 7_000)
        reserved_credit.payout_id = reserved.id
        session.add(reserved_credit)

        paid = ReferralPayout(
            address="alice@wallet.co",
            amount_sats=10_000,
            status="paid",
            external_reference="ledger.1",
            paid_at=datetime.now(UTC),
        )
        session.add(paid)
        session.flush()
        paid_credit = _credit(session, "alice@wallet.co", 2_000)
        paid_credit.payout_id = paid.id
        session.add(paid_credit)
        _credit(session, "bob@wallet.co", 5_000)

        review = _payment(session, settlement_review_required=True)
        _payment(session, invoice_provider="mock", settlement_review_required=True)
        review_id = review.id
        session.commit()

    assert referral_client.get("/api/v1/admin/referrals/balances").status_code == 401
    referral_client.cookies.set("blindport_admin_session", "browser-only-admin")
    assert referral_client.get("/api/v1/admin/referrals/balances").status_code == 401

    balances = referral_client.get(
        "/api/v1/admin/referrals/balances?limit=1", headers=_admin_headers()
    )
    assert balances.status_code == 200, balances.text
    assert balances.json() == {
        "items": [
            {
                "address": "alice@wallet.co",
                "available_sats": 11_000,
                "reserved_sats": 7_000,
                "paid_sats": 2_000,
                "payout_eligible": True,
            }
        ],
        "offset": 0,
        "limit": 1,
        "total": 2,
        "minimum_payout_sats": 10_000,
    }

    payouts = referral_client.get("/api/v1/admin/referrals/payouts", headers=_admin_headers())
    assert payouts.status_code == 200, payouts.text
    assert payouts.json()["total"] == 2

    review_response = referral_client.get(
        "/api/v1/admin/referrals/settlement-review", headers=_admin_headers()
    )
    assert review_response.status_code == 200, review_response.text
    assert review_response.json()["total"] == 1
    assert review_response.json()["items"][0]["payment_id"] == review_id


def test_payout_reservation_enforces_threshold_and_is_idempotent(
    referral_engine, referral_client
) -> None:
    address = "alice@wallet.co"
    with Session(referral_engine) as session:
        _credit(session, address, 9_999)

    payout_id = uuid4()
    below_threshold = referral_client.put(
        f"/api/v1/admin/referrals/payouts/{payout_id}",
        json={"address": address},
        headers=_admin_headers(),
    )
    assert below_threshold.status_code == 409

    with Session(referral_engine) as session:
        _credit(session, address, 1)

    first = referral_client.put(
        f"/api/v1/admin/referrals/payouts/{payout_id}",
        json={"address": "Alice@Wallet.Co"},
        headers=_admin_headers(),
    )
    assert first.status_code == 200, first.text
    assert first.json()["amount_sats"] == 10_000
    assert first.json()["address"] == address

    replay = referral_client.put(
        f"/api/v1/admin/referrals/payouts/{payout_id}",
        json={"address": address},
        headers=_admin_headers(),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == first.json()

    extra_input = referral_client.put(
        f"/api/v1/admin/referrals/payouts/{uuid4()}",
        json={"address": address, "amount_sats": 10_000},
        headers=_admin_headers(),
    )
    assert extra_input.status_code == 422

    conflict = referral_client.put(
        f"/api/v1/admin/referrals/payouts/{payout_id}",
        json={"address": "bob@wallet.co"},
        headers=_admin_headers(),
    )
    assert conflict.status_code == 409

    with Session(referral_engine) as session:
        credits = session.exec(select(ReferralCredit).order_by(ReferralCredit.payment_id)).all()
        assert {credit.payout_id for credit in credits} == {payout_id}


def test_concurrent_reservations_use_separate_sessions_and_retry_safely(referral_engine) -> None:
    address = "alice@wallet.co"
    with Session(referral_engine) as session:
        _credit(session, address, 12_000)

    first_id, second_id = uuid4(), uuid4()
    start = threading.Barrier(2)

    def reserve_once(payout_id: UUID) -> tuple[str, UUID]:
        with Session(referral_engine) as session:
            start.wait(timeout=10)
            try:
                referrals.reserve_payout(session, payout_id=payout_id, address=address)
                session.commit()
                return "reserved", payout_id
            except (referrals.ReferralBalanceTooLowError, referrals.ReferralPayoutConflictError):
                session.rollback()
                return "conflict", payout_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reserve_once, (first_id, second_id)))

    assert sorted(result[0] for result in results) == ["conflict", "reserved"]
    winner = next(payout_id for result, payout_id in results if result == "reserved")
    loser = next(payout_id for result, payout_id in results if result == "conflict")
    with Session(referral_engine) as session:
        payout = referrals.reserve_payout(session, payout_id=winner, address=address)
        assert payout.id == winner
        session.commit()

    with Session(referral_engine) as session:
        with pytest.raises(referrals.ReferralBalanceTooLowError):
            referrals.reserve_payout(session, payout_id=loser, address=address)
        session.rollback()
        payouts = session.exec(select(ReferralPayout)).all()
        credits = session.exec(select(ReferralCredit)).all()
        assert [payout.id for payout in payouts] == [winner]
        assert len(credits) == 1 and credits[0].payout_id == winner


def test_credits_arriving_after_reservation_are_claimed_by_a_later_payout(referral_engine) -> None:
    address = "alice@wallet.co"
    first_id, second_id = uuid4(), uuid4()
    with Session(referral_engine) as session:
        _credit(session, address, 6_000)
        _credit(session, address, 4_000)
        first = referrals.reserve_payout(session, payout_id=first_id, address=address)
        session.commit()
        assert first.amount_sats == 10_000

    with Session(referral_engine) as session:
        _credit(session, address, 5_000)
        with pytest.raises(referrals.ReferralBalanceTooLowError):
            referrals.reserve_payout(session, payout_id=second_id, address=address)
        session.rollback()

    with Session(referral_engine) as session:
        _credit(session, address, 5_000)
        second = referrals.reserve_payout(session, payout_id=second_id, address=address)
        session.commit()
        assert second.amount_sats == 10_000

    with Session(referral_engine) as session:
        payouts = {payout.id: payout for payout in session.exec(select(ReferralPayout)).all()}
        credits = session.exec(select(ReferralCredit).order_by(ReferralCredit.payment_id)).all()
        assert payouts[first_id].amount_sats == 10_000
        assert payouts[second_id].amount_sats == 10_000
        assert [credit.payout_id for credit in credits[:2]] == [first_id, first_id]
        assert [credit.payout_id for credit in credits[2:]] == [second_id, second_id]


def test_paid_reference_replay_is_idempotent_and_global(referral_engine, referral_client) -> None:
    first_address, second_address = "alice@wallet.co", "bob@wallet.co"
    first_id, second_id = uuid4(), uuid4()
    with Session(referral_engine) as session:
        _credit(session, first_address, 10_000)
        _credit(session, second_address, 10_000)

    for payout_id, address in ((first_id, first_address), (second_id, second_address)):
        response = referral_client.put(
            f"/api/v1/admin/referrals/payouts/{payout_id}",
            json={"address": address},
            headers=_admin_headers(),
        )
        assert response.status_code == 200, response.text

    reference = "ledger.2026:batch-1"
    paid = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{first_id}/paid",
        json={"external_reference": reference},
        headers=_admin_headers(),
    )
    assert paid.status_code == 200, paid.text
    assert paid.json()["status"] == "paid"
    assert paid.json()["external_reference"] == reference

    replay = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{first_id}/paid",
        json={"external_reference": reference},
        headers=_admin_headers(),
    )
    assert replay.status_code == 200, replay.text
    assert replay.json() == paid.json()

    different_reference = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{first_id}/paid",
        json={"external_reference": "ledger.2026:batch-2"},
        headers=_admin_headers(),
    )
    assert different_reference.status_code == 409

    extra_amount = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{second_id}/paid",
        json={"external_reference": "ledger.2026:batch-3", "amount_sats": 10_000},
        headers=_admin_headers(),
    )
    assert extra_amount.status_code == 422

    invalid_reference = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{second_id}/paid",
        json={"external_reference": "contains space"},
        headers=_admin_headers(),
    )
    assert invalid_reference.status_code == 422

    duplicate_reference = referral_client.post(
        f"/api/v1/admin/referrals/payouts/{second_id}/paid",
        json={"external_reference": reference},
        headers=_admin_headers(),
    )
    assert duplicate_reference.status_code == 409
