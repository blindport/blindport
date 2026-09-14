"""Invoice creation, settlement, and referral credits through real API/database boundaries."""

from datetime import UTC, datetime, timedelta
from hashlib import sha256
from uuid import UUID

import httpx
import pytest
from bolt11 import Bolt11, MilliSatoshi, Tag, TagChar, Tags, encode
from sqlmodel import Session, select

from blindport.adapters.lnurl import CoinosLnurlAdapter
from blindport.core.models import Payment, ReferralCredit, Subscription


@pytest.fixture
def coinos(app_client, monkeypatch):
    client, factory = app_client
    from blindport.services import payments

    monkeypatch.setattr(payments.settings, "PAYMENT_LIGHTNING_ADAPTER", "lnurl")
    state = {
        "settled": False,
        "fail_create": False,
        "invalid_proof": False,
        "calls": [],
        "invoices": {},
    }
    metadata = '[["text/plain","Paying blindport@coinos.io"]]'

    def handler(request):
        assert request.url.host == "coinos.io"
        state["calls"].append(request.url.path)
        if request.url.path.startswith("/.well-known"):
            return httpx.Response(
                200,
                json={
                    "tag": "payRequest",
                    "minSendable": 1000,
                    "maxSendable": 100000000000,
                    "metadata": metadata,
                    "callback": "https://coinos.io/api/lnurl/create",
                },
            )
        if request.url.path.endswith("/create"):
            if state["fail_create"]:
                raise httpx.ReadTimeout("ambiguous")
            number = len(state["invoices"]) + 1
            preimage = number.to_bytes(32, "big")
            pr = encode(
                Bolt11(
                    currency="bc",
                    date=int(datetime.now(UTC).timestamp()),
                    amount_msat=MilliSatoshi(int(request.url.params["amount"])),
                    tags=Tags(
                        [
                            Tag(TagChar.payment_hash, sha256(preimage).hexdigest()),
                            Tag(TagChar.description_hash, sha256(metadata.encode()).hexdigest()),
                            Tag(TagChar.payment_secret, "12" * 32),
                            Tag(TagChar.expire_time, 30 * 86400),
                            Tag(TagChar.min_final_cltv_expiry, 18),
                        ]
                    ),
                ),
                private_key="03" * 32,
                strict=True,
            )
            state["invoices"][str(number)] = (pr, preimage.hex())
            return httpx.Response(
                200, json={"pr": pr, "verify": f"https://coinos.io/api/lnurl/verify/{number}"}
            )
        pr, preimage = state["invoices"][request.url.path.rsplit("/", 1)[1]]
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "settled": state["settled"],
                "pr": pr,
                "preimage": ("ff" * 32 if state["invalid_proof"] else preimage)
                if state["settled"]
                else None,
            },
        )

    adapter = CoinosLnurlAdapter(transport=httpx.MockTransport(handler))
    monkeypatch.setattr(payments, "get_lnurl_adapter", lambda: adapter)
    token = client.post("/api/v1/signup").json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post(
        "/api/v1/subscriptions",
        headers=headers,
        json={"product": "port", "referral_address": "Alice@EXAMPLE.COM"},
    )
    assert response.status_code == 200, response.text
    yield client, headers, response.json()["id"], state
    adapter.close()


def _create(coinos):
    client, headers, sub_id, _ = coinos
    return client.post(
        "/api/v1/payments", headers=headers, json={"subscription_id": sub_id, "method": "lightning"}
    )


def _allow_check(payment_id):
    from blindport.db import engine

    with Session(engine) as session:
        payment = session.get(Payment, payment_id)
        payment.lnurl_last_checked_at = None
        session.add(payment)
        session.commit()


def test_lnurl_settles_once_and_credits_snapshotted_commission(coinos, monkeypatch):
    from blindport.db import engine
    from blindport.services import payments

    client, headers, sub_id, state = coinos
    response = _create(coinos)
    assert response.status_code == 200, response.text
    payment = response.json()
    assert datetime.fromisoformat(payment["invoice_expires_at"]) > datetime.fromisoformat(
        payment["expires_at"]
    ) + timedelta(days=29)
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        assert stored.invoice_provider == "lnurl"
        assert stored.referral_commission_bps == 1000
        assert session.exec(select(ReferralCredit)).all() == []
    monkeypatch.setattr(payments.settings, "REFERRAL_COMMISSION_BPS", 9999)
    state["settled"] = True
    paid = client.get(f"/api/v1/payments/{payment['id']}", headers=headers)
    assert paid.json()["status"] == "paid", paid.text
    assert (
        client.get(f"/api/v1/payments/{payment['id']}", headers=headers).json()["status"] == "paid"
    )
    with Session(engine) as session:
        credits = session.exec(select(ReferralCredit)).all()
        assert len(credits) == 1
        assert credits[0].amount_sats == payment["base_amount_sats"] // 10
        assert credits[0].address == "alice@example.com"
        sub = session.exec(select(Subscription).where(Subscription.public_id == UUID(sub_id))).one()
        assert sub.status.value == "active"
    assert state["calls"].count("/api/lnurl/create") == 1


def test_ambiguous_creation_is_never_retried_by_reads_or_reconciler(coinos):
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    client, headers, _, state = coinos
    state["fail_create"] = True
    response = _create(coinos)
    assert response.status_code == 502, response.text
    with Session(engine) as session:
        payment = session.exec(select(Payment)).one()
        assert payment.lnurl_attempted_at is not None
        payment_id = payment.id
    state["fail_create"] = False
    assert client.get(f"/api/v1/payments/{payment_id}", headers=headers).status_code == 200
    reconcile_pending_payments_once()
    assert state["calls"].count("/api/lnurl/create") == 1


def test_invalid_preimage_cannot_activate_or_credit(coinos):
    from blindport.db import engine

    client, headers, _, state = coinos
    payment = _create(coinos).json()
    state.update(settled=True, invalid_proof=True)
    assert client.get(f"/api/v1/payments/{payment['id']}", headers=headers).status_code == 502
    with Session(engine) as session:
        assert session.get(Payment, payment["id"]).status.value == "pending"
        assert session.exec(select(ReferralCredit)).all() == []


def test_expired_invoice_is_monitored_and_late_receipt_requires_review(coinos):
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    client, headers, _, state = coinos
    payment = _create(coinos).json()
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        stored.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        session.add(stored)
        session.commit()
    assert (
        client.get(f"/api/v1/payments/{payment['id']}", headers=headers).json()["status"]
        == "expired"
    )
    newer = _create(coinos).json()
    _allow_check(payment["id"])
    state["settled"] = True
    reconcile_pending_payments_once()
    with Session(engine) as session:
        late = session.get(Payment, payment["id"])
        assert late.settlement_verified_at is not None
        assert late.settlement_review_required
        assert late.status.value == "expired"
        assert session.get(ReferralCredit, late.id) is None
        assert session.get(Payment, newer["id"]).status.value == "paid"
    review = client.get(
        "/api/v1/admin/referrals/settlement-review",
        headers={"Authorization": "Bearer TESTADMIN0000"},
    )
    assert review.status_code == 200, review.text
    assert review.json()["items"][0]["payment_id"] == payment["id"]
    dashboard = client.get("/dashboard")
    assert "Payments awaiting review" in dashboard.text
    assert f"Payment {payment['id']}:" in dashboard.text
    client.post("/api/v1/signup")
    assert "Payments awaiting review" not in client.get("/dashboard").text


def test_provider_switch_does_not_recreate_legacy_pending_invoice(coinos):
    from blindport.db import engine

    client, headers, _, state = coinos
    payment = _create(coinos).json()
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        stored.invoice_provider = None
        stored.invoice = None
        session.add(stored)
        session.commit()
    before = list(state["calls"])
    assert client.get(f"/api/v1/payments/{payment['id']}", headers=headers).status_code == 502
    assert state["calls"] == before


def test_failed_wallet_invoice_still_monitored_when_method_disabled(coinos, monkeypatch):
    from blindport.core.models import PaymentMethod, PaymentStatus
    from blindport.db import engine
    from blindport.services import payment_reconciliation

    _, _, _, state = coinos
    payment = _create(coinos).json()
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        stored.status = PaymentStatus.FAILED
        stored.method = PaymentMethod.NWC
        session.add(stored)
        session.commit()
    monkeypatch.setattr(payment_reconciliation.settings, "PAYMENT_ENABLED_METHODS", "lightning")
    state["settled"] = True
    payment_reconciliation.reconcile_pending_payments_once()
    with Session(engine) as session:
        stored = session.get(Payment, payment["id"])
        assert stored.settlement_review_required
        assert session.get(ReferralCredit, stored.id) is None


def test_undrained_legacy_payment_does_not_starve_lnurl_reconciliation(coinos):
    from blindport.core.models import PaymentMethod, PaymentStatus
    from blindport.db import engine
    from blindport.services.payment_reconciliation import reconcile_pending_payments_once

    client, headers, sub_id, state = coinos
    legacy_sub = client.post(
        "/api/v1/subscriptions", headers=headers, json={"product": "port"}
    ).json()
    with Session(engine) as session:
        sub = session.exec(
            select(Subscription).where(Subscription.public_id == UUID(legacy_sub["id"]))
        ).one()
        session.add(
            Payment(
                subscription_id=sub.id,
                method=PaymentMethod.LIGHTNING,
                amount_sats=1000,
                status=PaymentStatus.PENDING,
                created_at=datetime.now(UTC) - timedelta(days=1),
            )
        )
        session.commit()
    payment = _create(coinos).json()
    state["settled"] = True
    summary = reconcile_pending_payments_once(batch_size=1)
    assert summary.scanned == 1
    assert summary.paid == 1
    assert (
        client.get(f"/api/v1/payments/{payment['id']}", headers=headers).json()["status"] == "paid"
    )
