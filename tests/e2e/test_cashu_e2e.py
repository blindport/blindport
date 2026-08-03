"""End-to-end test for the real Cashu payment flow.

Exercises the production-ish path:

  1. Sign up via the backend API.
  2. Subscribe to Blindport IP.
  3. Create a payment with ``method=cashu`` -> backend marks it pending.
  4. The tester acts as a Cashu wallet: asks the bundled nutshell mint for
     a mint quote, waits for FakeWallet to mark it paid, mints ecash,
     serializes a ``cashuA`` token.
  5. Submits the token via ``POST /api/v1/payments/cashu-submit`` -> backend
     swaps the proofs against the mint and marks the payment paid.
  6. Confirms the subscription is active and an IP got allocated.

Requires the mint, backend, and tester services from
``docker/docker-compose.yaml`` to be running.
"""

from __future__ import annotations

import os
import sys
import time

import httpx
import pytest  # noqa: F401  (kept for fixture-style usage in future tests)

# Add the backend source onto sys.path so the tester can reuse the BDHKE
# primitives shipped with the service.
sys.path.insert(0, "/repo/backend/src")
sys.path.insert(0, "/repo/tests/e2e")

from cashu_wallet import MinimalCashuWallet  # noqa: E402

BACKEND = os.environ["BLINDPORT_BACKEND_URL"]
MINT_URL = os.environ.get("BLINDPORT_MINT_URL", "http://mint:3338")


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _signup() -> str:
    r = httpx.post(f"{BACKEND}/api/v1/signup", timeout=5)
    r.raise_for_status()
    return r.json()["token"]


def _subscribe(token: str, product: str, domain: str | None = None) -> dict:
    body: dict = {"product": product}
    if domain:
        body["domain"] = domain
    r = httpx.post(
        f"{BACKEND}/api/v1/subscriptions",
        headers=_auth(token),
        json=body,
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


def _create_cashu_payment(token: str, sub_id: int) -> dict:
    r = httpx.post(
        f"{BACKEND}/api/v1/payments",
        headers=_auth(token),
        json={"subscription_id": sub_id, "method": "cashu"},
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


def _submit_token(token: str, payment_id: int, cashu_token: str) -> dict:
    r = httpx.post(
        f"{BACKEND}/api/v1/payments/cashu-submit",
        headers=_auth(token),
        json={"payment_id": payment_id, "cashu_token": cashu_token},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()


def _wait_for_mint(deadline_secs: float = 30) -> None:
    deadline = time.time() + deadline_secs
    while time.time() < deadline:
        try:
            r = httpx.get(f"{MINT_URL}/v1/info", timeout=2)
            if r.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError("nutshell mint never came up")


@pytest.fixture(scope="module", autouse=True)
def _mint_up():
    _wait_for_mint()


def test_cashu_payment_settles_subscription():
    token = _signup()
    sub = _subscribe(token, "ip")
    pay = _create_cashu_payment(token, sub["id"])
    assert (pay["billing_term"], pay["period_days"]) == ("monthly", 30)
    assert pay["status"] == "pending"
    assert pay["cashu_token_required"] is True
    amount = int(pay["amount_sats"])

    wallet = MinimalCashuWallet(MINT_URL)
    cashu_token = wallet.mint_token(amount)

    settled = _submit_token(token, pay["id"], cashu_token)
    assert settled["status"] == "paid", settled

    # Subscription should now be active and have an IP assigned.
    cfg = httpx.get(
        f"{BACKEND}/api/v1/client/config", headers=_auth(token), timeout=5
    ).json()
    assert any(row["product"] == "ip" and row["assigned_ip"] for row in cfg), cfg


def test_cashu_payment_rejects_underpriced_token():
    token = _signup()
    sub = _subscribe(token, "relay", domain="mail.relay.test")
    pay = _create_cashu_payment(token, sub["id"])
    amount = int(pay["amount_sats"])

    wallet = MinimalCashuWallet(MINT_URL)
    # Mint only half the required amount.
    short = wallet.mint_token(max(1, amount // 2))

    # Backend accepts the submit (HTTP 200) but marks payment as failed.
    resp = _submit_token(token, pay["id"], short)
    assert resp["status"] == "failed", resp


def test_cashu_quote_endpoint_returns_invoice():
    """Backend's /payments/cashu-quote proxies to the trusted mint and returns bolt11."""
    token = _signup()
    sub = _subscribe(token, "ip")
    pay = _create_cashu_payment(token, sub["id"])

    r = httpx.post(
        f"{BACKEND}/api/v1/payments/cashu-quote",
        headers=_auth(token),
        json={"payment_id": pay["id"]},
        timeout=10,
    )
    assert r.status_code == 200, r.text
    quote = r.json()
    assert quote["payment_id"] == pay["id"]
    assert quote["amount_sats"] == pay["amount_sats"]
    assert quote["quote_id"]
    assert quote["bolt11"].lower().startswith(("lnbc", "lntb", "lnbcrt", "lnsb"))
    assert quote["mint_url"].rstrip("/") == MINT_URL.rstrip("/")
