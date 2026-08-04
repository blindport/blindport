"""Minimal Cashu V3 wallet for end-to-end tests.

Implements just enough of NUT-00/01/04 to mint ecash against a trusted
nutshell mint backed by FakeWallet LN, and serialize the resulting proofs
into a ``cashuA`` token string. Reuses the BDHKE primitives shipped with
the backend (:mod:`blindport.adapters.cashu_bdhke`) so we don't duplicate
the curve math.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx

# These imports work because the tester container mounts the repo at /repo
# and runs from that directory; backend/src is on sys.path via the test
# harness adding it (see test_cashu_e2e.py).
from blindport.adapters.cashu_bdhke import (
    make_blinded_output,
    split_amount,
    unblind_signature,
)


@dataclass
class MintQuote:
    quote_id: str
    bolt11: str
    paid: bool


class MinimalCashuWallet:
    """Light Cashu wallet: mint quote -> pay -> mint -> serialize token."""

    def __init__(self, mint_url: str, timeout: float = 8.0) -> None:
        self.mint_url = mint_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    # -- mint quote / pay --------------------------------------------------

    def request_mint_quote(self, amount_sats: int) -> MintQuote:
        r = self._client.post(
            f"{self.mint_url}/v1/mint/quote/bolt11",
            json={"amount": amount_sats, "unit": "sat"},
        )
        r.raise_for_status()
        d = r.json()
        return MintQuote(
            quote_id=str(d["quote"]),
            bolt11=str(d["request"]),
            paid=bool(d.get("paid", False)),
        )

    def wait_for_paid(self, quote_id: str, deadline_secs: float = 20.0) -> None:
        """With FakeWallet, the quote flips paid after a configurable delay.

        Defaults to 20s to comfortably exceed the nutshell ``fakewallet_delay
        _incoming_payment`` setting (3s) plus listener dispatch latency.
        """
        deadline = time.time() + deadline_secs
        while time.time() < deadline:
            r = self._client.get(f"{self.mint_url}/v1/mint/quote/bolt11/{quote_id}")
            if r.status_code == 200:
                body = r.json()
                if body.get("paid") or body.get("state") == "PAID":
                    return
            time.sleep(1.0)
        raise RuntimeError(f"mint quote {quote_id} never marked paid")

    # -- keyset ------------------------------------------------------------

    def active_keyset(self) -> tuple[str, dict[int, str]]:
        r = self._client.get(f"{self.mint_url}/v1/keys")
        r.raise_for_status()
        data = r.json()
        # NUT-01: {"keysets":[{"id":"...","unit":"sat","keys":{"1":"hex",...}}]}
        for ks in data.get("keysets", []):
            if ks.get("unit", "sat") == "sat":
                keys = {int(k): str(v) for k, v in ks["keys"].items()}
                return str(ks["id"]), keys
        raise RuntimeError("mint exposes no 'sat' keyset")

    # -- mint --------------------------------------------------------------

    def mint(self, quote_id: str, amount_sats: int) -> list[dict[str, Any]]:
        """Run NUT-04 mint: send blinded outputs, get signatures, unblind to proofs."""
        keyset_id, pubkeys = self.active_keyset()
        outputs = [make_blinded_output(a, keyset_id) for a in split_amount(amount_sats)]
        body = {
            "quote": quote_id,
            "outputs": [{"amount": o.amount, "id": o.id, "B_": o.B_} for o in outputs],
        }
        r = self._client.post(f"{self.mint_url}/v1/mint/bolt11", json=body)
        r.raise_for_status()
        sigs = r.json()["signatures"]
        proofs: list[dict[str, Any]] = []
        for out, sig in zip(outputs, sigs, strict=True):
            k_pub = pubkeys[out.amount]
            C = unblind_signature(str(sig["C_"]), out._r, k_pub)
            proofs.append(
                {"amount": out.amount, "id": out.id, "secret": out._secret, "C": C}
            )
        return proofs

    # -- token serialization ----------------------------------------------

    def serialize_token(self, proofs: list[dict[str, Any]]) -> str:
        payload = {"token": [{"mint": self.mint_url, "proofs": proofs}]}
        raw = json.dumps(payload).encode()
        return "cashuA" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    # -- one-shot helper --------------------------------------------------

    def mint_token(self, amount_sats: int) -> str:
        q = self.request_mint_quote(amount_sats)
        self.wait_for_paid(q.quote_id)
        proofs = self.mint(q.quote_id, amount_sats)
        return self.serialize_token(proofs)


__all__ = ["MinimalCashuWallet", "MintQuote"]
