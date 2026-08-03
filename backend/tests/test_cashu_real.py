"""Tests for :mod:`blindport.adapters.cashu_real`.

We stand up a small in-memory NUT-compatible mint backed by ``httpx``'s
``MockTransport`` so we can exercise the swap path end-to-end without
networking. The fake mint implements just enough of NUT-00/01/03/04 for
the adapter to redeem ecash.
"""

from __future__ import annotations

import base64
import json
import secrets

import httpx
import pytest
from coincurve import PrivateKey, PublicKey

from blindport.adapters.cashu_bdhke import hash_to_curve
from blindport.adapters.cashu_real import RealCashuAdapter

_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_KEYSET_ID = "00aabbccddeeff01"


def _scalar(k: int) -> bytes:
    return k.to_bytes(32, "big")


class _FakeMint:
    """In-memory NUT-compatible mint.

    Issues power-of-two denominations 1..2^10 sat using one secret key per
    denomination, so the unblinded signature on amount=N can be verified as
    ``C == k_N * hash_to_curve(secret)``.
    """

    def __init__(self) -> None:
        # k_N: int for each denomination.
        self.keys: dict[int, int] = {1 << i: secrets.randbelow(_N - 1) + 1 for i in range(11)}
        self.pubkeys_hex: dict[int, str] = {
            amt: PrivateKey(_scalar(k)).public_key.format(compressed=True).hex()
            for amt, k in self.keys.items()
        }
        # Spent input set keyed by (secret, C) tuple.
        self.spent: set[tuple[str, str]] = set()
        # Mint quote registry.
        self.quotes: dict[str, dict] = {}
        self.swap_requests = 0

    # -- transport ---------------------------------------------------------

    def handler(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        if req.method == "POST" and path == "/v1/mint/quote/bolt11":
            body = json.loads(req.content)
            qid = secrets.token_hex(8)
            self.quotes[qid] = {"amount": int(body["amount"]), "paid": False}
            return httpx.Response(
                200,
                json={
                    "quote": qid,
                    "request": f"lnbcfake{body['amount']}",
                    "expiry": 0,
                    "paid": False,
                },
            )
        if req.method == "GET" and path.startswith("/v1/mint/quote/bolt11/"):
            qid = path.rsplit("/", 1)[-1]
            q = self.quotes.get(qid)
            if not q:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"quote": qid, "paid": q["paid"]})
        if req.method == "GET" and path.startswith("/v1/keys/"):
            return httpx.Response(
                200,
                json={
                    "keysets": [
                        {
                            "id": _KEYSET_ID,
                            "unit": "sat",
                            "keys": {str(amt): k for amt, k in self.pubkeys_hex.items()},
                        }
                    ]
                },
            )
        if req.method == "GET" and path == "/v1/keysets":
            return httpx.Response(
                200,
                json={
                    "keysets": [
                        {
                            "id": _KEYSET_ID,
                            "unit": "sat",
                            "active": True,
                            "input_fee_ppk": 0,
                        }
                    ]
                },
            )
        if req.method == "POST" and path == "/v1/mint/bolt11":
            body = json.loads(req.content)
            qid = str(body.get("quote", ""))
            q = self.quotes.get(qid)
            if not q or not q.get("paid"):
                return httpx.Response(400, json={"error": "quote not paid"})
            outputs = body.get("outputs") or []
            sigs = []
            for o in outputs:
                amt = int(o["amount"])
                k_int = self.keys[amt]
                B_ = PublicKey(bytes.fromhex(o["B_"]))
                C_ = B_.multiply(_scalar(k_int)).format(compressed=True).hex()
                sigs.append({"amount": amt, "id": o["id"], "C_": C_})
            return httpx.Response(200, json={"signatures": sigs})
        if req.method == "POST" and path == "/v1/swap":
            self.swap_requests += 1
            return self._swap(json.loads(req.content))
        return httpx.Response(404, json={"error": "no route"})

    def _swap(self, body: dict) -> httpx.Response:
        inputs = body.get("inputs") or []
        outputs = body.get("outputs") or []
        amount_in = 0
        for p in inputs:
            secret = str(p["secret"])
            C_hex = str(p["C"])
            amt = int(p["amount"])
            key = (secret, C_hex)
            if key in self.spent:
                return httpx.Response(400, json={"error": "already spent"})
            # Verify C == k_amt * hash_to_curve(secret).
            k_int = self.keys.get(amt)
            if k_int is None:
                return httpx.Response(400, json={"error": f"unknown denomination {amt}"})
            Y = hash_to_curve(secret.encode("utf-8"))
            expected = Y.multiply(_scalar(k_int)).format(compressed=True).hex()
            if expected != C_hex:
                return httpx.Response(400, json={"error": "invalid proof"})
            amount_in += amt
        amount_out = sum(int(o["amount"]) for o in outputs)
        if amount_in != amount_out:
            return httpx.Response(400, json={"error": "amount mismatch"})
        # Mark inputs spent and sign outputs.
        for p in inputs:
            self.spent.add((str(p["secret"]), str(p["C"])))
        sigs = []
        for o in outputs:
            amt = int(o["amount"])
            k_int = self.keys[amt]
            B_ = PublicKey(bytes.fromhex(o["B_"]))
            C_ = B_.multiply(_scalar(k_int)).format(compressed=True).hex()
            sigs.append({"amount": amt, "id": o["id"], "C_": C_})
        return httpx.Response(200, json={"signatures": sigs})

    # -- helpers for tests -------------------------------------------------

    def make_valid_token(self, mint_url: str, amount: int) -> str:
        """Build a valid Cashu V3 token redeemable against this fake mint."""
        proofs = []
        # Split into denominations the mint supports.
        remaining = amount
        bit = 0
        while remaining > 0:
            if remaining & 1:
                denom = 1 << bit
                secret = secrets.token_bytes(32).hex()
                Y = hash_to_curve(secret.encode("utf-8"))
                k_int = self.keys[denom]
                C = Y.multiply(_scalar(k_int)).format(compressed=True).hex()
                proofs.append({"amount": denom, "id": _KEYSET_ID, "secret": secret, "C": C})
            remaining >>= 1
            bit += 1
        payload = {"token": [{"mint": mint_url, "proofs": proofs}]}
        raw = json.dumps(payload).encode()
        return "cashuA" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@pytest.fixture()
def mint() -> _FakeMint:
    return _FakeMint()


@pytest.fixture()
def adapter(mint: _FakeMint) -> RealCashuAdapter:
    transport = httpx.MockTransport(mint.handler)
    client = httpx.Client(transport=transport, base_url="")
    return RealCashuAdapter(mint_urls=["http://fakemint"], client=client)


def test_redeem_accepts_valid_token(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    tok = mint.make_valid_token("http://fakemint", 21)
    assert adapter.validate_and_redeem(tok, expected_amount_sats=21) is True
    swapped = adapter.last_swapped_proofs
    assert sum(p["amount"] for p in swapped) == 21


def test_redeem_rejects_underpriced_token(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    tok = mint.make_valid_token("http://fakemint", 10)
    assert adapter.validate_and_redeem(tok, expected_amount_sats=21) is False
    assert mint.swap_requests == 0


def test_redeem_rejects_overpayment_before_swap(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    tok = mint.make_valid_token("http://fakemint", 22)
    assert adapter.validate_and_redeem(tok, expected_amount_sats=21) is False
    assert mint.swap_requests == 0


def test_redeem_rejects_double_spend(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    tok = mint.make_valid_token("http://fakemint", 5)
    assert adapter.validate_and_redeem(tok, expected_amount_sats=5) is True
    # Second attempt: same proofs already spent.
    assert adapter.validate_and_redeem(tok, expected_amount_sats=5) is False


def test_redeem_rejects_untrusted_mint(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    tok = mint.make_valid_token("http://evil-mint", 21)
    assert adapter.validate_and_redeem(tok, expected_amount_sats=21) is False


def test_mint_quote_roundtrip(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    quote = adapter.request_mint_quote(100)
    assert quote.amount_sats == 100
    assert quote.bolt11.startswith("lnbcfake")
    assert adapter.check_mint_quote(quote.quote_id) is False
    mint.quotes[quote.quote_id]["paid"] = True
    assert adapter.check_mint_quote(quote.quote_id) is True


def test_register_test_token_is_not_supported(adapter: RealCashuAdapter) -> None:
    with pytest.raises(NotImplementedError):
        adapter.register_test_token("cashuA...", 100)


def test_mint_against_quote(mint: _FakeMint, adapter: RealCashuAdapter) -> None:
    quote = adapter.request_mint_quote(15)
    mint.quotes[quote.quote_id]["paid"] = True
    proofs = adapter.mint_against_quote(quote.quote_id, 15)
    assert sum(int(p["amount"]) for p in proofs) == 15
    # Newly minted proofs should pass a follow-up swap against the same mint.
    body = {
        "token": [{"mint": "http://fakemint", "proofs": proofs}],
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    tok = "cashuA" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    assert adapter.validate_and_redeem(tok, expected_amount_sats=15) is True
