"""Real Cashu mint adapter.

Talks to one or more trusted Cashu mints over their NUT HTTP API and swaps
inbound ecash proofs for new ones the service operator owns. Built on top
of :mod:`blindport.adapters.cashu_bdhke`.

Only the parts of the protocol we actually need are implemented:

  * NUT-04: ``POST /v1/mint/quote/bolt11`` and ``GET /v1/mint/quote/bolt11/{quote_id}``
    so the user's wallet can mint ecash from a Lightning payment.
  * NUT-03: ``POST /v1/swap`` to atomically prove proofs are unspent.
  * NUT-01: ``GET /v1/keys/{keyset_id}`` to fetch per-denomination pubkeys
    used for unblinding.

The adapter persists nothing locally; the swapped proofs are returned to
the caller (services layer) which may persist them for later sweeping.
"""

from __future__ import annotations

from typing import Any

import httpx
from loguru import logger

from .base import CashuAdapter, CashuMintQuote
from .cashu_bdhke import (
    make_blinded_output,
    parse_v3_token,
    split_amount,
    unblind_signature,
)


class RealCashuAdapter(CashuAdapter):
    """Cashu mint adapter against a trusted pool of NUT-compatible mints."""

    def __init__(
        self,
        mint_urls: list[str],
        timeout: float = 8.0,
        client: httpx.Client | None = None,
    ) -> None:
        if not mint_urls:
            raise ValueError("RealCashuAdapter requires at least one trusted mint URL")
        self._mints = {u.rstrip("/") for u in mint_urls}
        self._timeout = timeout
        self._client = client or httpx.Client(timeout=timeout)
        # Cache of {(mint, keyset_id): {amount: pubkey_hex}}.
        self._keysets: dict[tuple[str, str], dict[int, str]] = {}
        self._fees: dict[tuple[str, str], int] = {}
        # Per-mint cached active keyset id (for NUT-04 minting).
        self._active_keysets: dict[str, str] = {}
        # Track swapped proofs by request for the caller; populated by
        # ``validate_and_redeem`` and exposed via ``last_swapped_proofs``.
        self._last_swapped_proofs: list[dict[str, Any]] = []

    # ----- mint quote (LN top-up) ---------------------------------------

    def request_mint_quote(self, amount_sats: int, mint_url: str | None = None) -> CashuMintQuote:
        """Ask the mint to issue an LN invoice for ``amount_sats``.

        The user's Cashu wallet then pays the invoice and mints ecash against
        the quote; the service never touches the LN payment directly.
        """
        url = self._resolve_mint(mint_url)
        r = self._client.post(
            f"{url}/v1/mint/quote/bolt11",
            json={"amount": amount_sats, "unit": "sat"},
        )
        r.raise_for_status()
        data = r.json()
        return CashuMintQuote(
            quote_id=str(data["quote"]),
            bolt11=str(data["request"]),
            amount_sats=amount_sats,
            expires_at=int(data.get("expiry", 0) or 0),
            mint_url=url,
        )

    def check_mint_quote(self, quote_id: str, mint_url: str | None = None) -> bool:
        url = self._resolve_mint(mint_url)
        r = self._client.get(f"{url}/v1/mint/quote/bolt11/{quote_id}")
        if r.status_code != 200:
            return False
        data = r.json()
        # NUT-04: newer mints return ``state == "PAID"``; older mints used a
        # boolean ``paid`` field. Accept either so we stay compatible.
        state = str(data.get("state", "")).upper()
        if state == "PAID":
            return True
        return bool(data.get("paid"))

    def mint_against_quote(
        self,
        quote_id: str,
        amount_sats: int,
        mint_url: str | None = None,
    ) -> list[dict[str, Any]]:
        """NUT-04: redeem a paid mint quote into fresh ecash proofs we own.

        Sends blinded outputs summing to ``amount_sats`` to
        ``POST /v1/mint/bolt11`` and unblinds the mint's signatures.
        """
        mint = self._resolve_mint(mint_url)
        keyset_id = self._pick_active_keyset(mint)
        outputs = [make_blinded_output(amt, keyset_id) for amt in split_amount(amount_sats)]
        body = {
            "quote": quote_id,
            "outputs": [{"amount": o.amount, "id": o.id, "B_": o.B_} for o in outputs],
        }
        r = self._client.post(f"{mint}/v1/mint/bolt11", json=body)
        r.raise_for_status()
        sigs = r.json().get("signatures") or []
        if len(sigs) != len(outputs):
            raise RuntimeError("mint returned wrong number of signatures on mint/bolt11")
        keyset = self._fetch_keyset(mint, keyset_id)
        proofs: list[dict[str, Any]] = []
        for out, sig in zip(outputs, sigs, strict=True):
            k_pub = keyset.get(out.amount)
            if not k_pub:
                raise RuntimeError(f"missing mint pubkey for amount {out.amount}")
            C = unblind_signature(str(sig["C_"]), out._r, k_pub)
            proofs.append(
                {
                    "amount": out.amount,
                    "id": out.id,
                    "secret": out._secret,
                    "C": C,
                }
            )
        self._last_swapped_proofs = list(proofs)
        return proofs

    # ----- ecash redemption ---------------------------------------------

    def validate_and_redeem(self, token: str, expected_amount_sats: int) -> bool:
        """Swap a Cashu V3 token with its mint and verify the value.

        On success, ``last_swapped_proofs`` is populated with the proofs the
        service operator now owns.
        """
        self._last_swapped_proofs = []
        try:
            payload = parse_v3_token(token)
        except ValueError as e:
            logger.warning("cashu token parse failed: {}", e)
            return False
        entries: list[tuple[str, list[dict[str, Any]]]] = []
        nominal_total = 0
        try:
            for entry in payload["token"]:
                mint = str(entry.get("mint", "")).rstrip("/")
                proofs = entry.get("proofs") or []
                if mint not in self._mints:
                    logger.warning("token references untrusted mint {}", mint)
                    return False
                if not isinstance(proofs, list):
                    raise ValueError("proofs must be an array")
                for proof in proofs:
                    amount = proof.get("amount")
                    if not isinstance(amount, int) or isinstance(amount, bool) or amount <= 0:
                        raise ValueError("proof amount must be a positive integer")
                    nominal_total += amount
                entries.append((mint, proofs))
        except (AttributeError, TypeError, ValueError) as e:
            logger.warning("cashu token validation failed: {}", e)
            return False
        if nominal_total != expected_amount_sats:
            logger.info(
                "cashu token amount mismatch: got {} sats, expected {}",
                nominal_total,
                expected_amount_sats,
            )
            return False

        all_swapped: list[dict[str, Any]] = []
        for mint, proofs in entries:
            try:
                swapped, _ = self._swap(mint, proofs)
            except Exception as e:
                logger.warning("mint swap failed on {}: {}", mint, e)
                return False
            all_swapped.extend(swapped)
        self._last_swapped_proofs = all_swapped
        return True

    def register_test_token(self, token: str, amount_sats: int) -> None:
        raise NotImplementedError("register_test_token is mock-only")

    @property
    def last_swapped_proofs(self) -> list[dict[str, Any]]:
        return list(self._last_swapped_proofs)

    # ----- internals ----------------------------------------------------

    def _resolve_mint(self, mint_url: str | None) -> str:
        if mint_url is None:
            return sorted(self._mints)[0]
        url = mint_url.rstrip("/")
        if url not in self._mints:
            raise ValueError(f"mint {url} is not in the trusted pool")
        return url

    def _swap(self, mint: str, proofs: list[dict]) -> tuple[list[dict[str, Any]], int]:
        """Perform a NUT-03 swap. Returns (new proofs we own, total amount).

        Honors the keyset's ``input_fee_ppk`` (NUT-02): each input costs
        ``ceil(n_inputs * fee_ppk / 1000)`` sat that must be skipped from
        outputs, otherwise the mint rejects the swap as unbalanced.
        """
        if not proofs:
            return [], 0
        # All inputs must share a keyset id (mints currently issue one id per unit).
        keyset_id = str(proofs[0]["id"])
        amount_in = sum(int(p["amount"]) for p in proofs)
        fee = self._swap_fee(mint, keyset_id, len(proofs))
        amount_out = amount_in - fee
        if amount_out <= 0:
            raise RuntimeError(f"swap fee {fee} >= inputs {amount_in}; cannot redeem")
        outputs = [make_blinded_output(amt, keyset_id) for amt in split_amount(amount_out)]
        body = {
            "inputs": [
                {
                    "amount": int(p["amount"]),
                    "id": str(p["id"]),
                    "secret": str(p["secret"]),
                    "C": str(p["C"]),
                }
                for p in proofs
            ],
            "outputs": [{"amount": o.amount, "id": o.id, "B_": o.B_} for o in outputs],
        }
        r = self._client.post(f"{mint}/v1/swap", json=body)
        r.raise_for_status()
        sigs = r.json().get("signatures") or []
        if len(sigs) != len(outputs):
            raise RuntimeError("mint returned wrong number of signatures")
        keyset = self._fetch_keyset(mint, keyset_id)
        new_proofs: list[dict[str, Any]] = []
        for out, sig in zip(outputs, sigs, strict=True):
            k_pub = keyset.get(out.amount)
            if not k_pub:
                raise RuntimeError(f"missing mint pubkey for amount {out.amount}")
            C = unblind_signature(str(sig["C_"]), out._r, k_pub)
            new_proofs.append(
                {
                    "amount": out.amount,
                    "id": out.id,
                    "secret": out._secret,
                    "C": C,
                }
            )
        return new_proofs, amount_in

    def _swap_fee(self, mint: str, keyset_id: str, n_inputs: int) -> int:
        """Return the swap fee (sat) charged by ``mint`` for ``n_inputs`` inputs.

        Per NUT-02: ``fee = ceil(n_inputs * input_fee_ppk / 1000)``. The fee
        table is fetched once per (mint, keyset_id) from ``/v1/keysets`` and
        cached in :attr:`_fees`.
        """
        cached = self._fees.get((mint, keyset_id))
        if cached is None:
            try:
                r = self._client.get(f"{mint}/v1/keysets")
                r.raise_for_status()
                cached = 0
                for ks in r.json().get("keysets", []):
                    if str(ks.get("id")) == keyset_id:
                        cached = int(ks.get("input_fee_ppk", 0) or 0)
                        break
            except Exception:
                cached = 0
            self._fees[(mint, keyset_id)] = cached
        if cached <= 0:
            return 0
        # Ceiling division.
        return (n_inputs * cached + 999) // 1000

    def _pick_active_keyset(self, mint: str) -> str:
        """Pick a usable ``sat`` keyset id for ``mint``.

        Prefers active keysets; falls back to whatever the mint exposes.
        Result is cached on first call per mint via :attr:`_active_keysets`.
        """
        cached = self._active_keysets.get(mint)
        if cached:
            return cached
        r = self._client.get(f"{mint}/v1/keysets")
        r.raise_for_status()
        sat_keysets = [
            ks for ks in r.json().get("keysets", []) if str(ks.get("unit", "sat")) == "sat"
        ]
        active = [ks for ks in sat_keysets if ks.get("active", True)]
        chosen = (active or sat_keysets)[0]
        ksid = str(chosen["id"])
        self._active_keysets[mint] = ksid
        return ksid

    def _fetch_keyset(self, mint: str, keyset_id: str) -> dict[int, str]:
        cached = self._keysets.get((mint, keyset_id))
        if cached is not None:
            return cached
        r = self._client.get(f"{mint}/v1/keys/{keyset_id}")
        r.raise_for_status()
        data = r.json()
        # NUT-01 shape: {"keysets": [{"id": ..., "unit": "sat", "keys": {amount_str: pubkey_hex}}]}
        for ks in data.get("keysets", []):
            if str(ks.get("id")) == keyset_id:
                keys = {int(k): str(v) for k, v in ks.get("keys", {}).items()}
                self._keysets[(mint, keyset_id)] = keys
                return keys
        raise RuntimeError(f"mint {mint} returned no keys for keyset {keyset_id}")


__all__ = ["RealCashuAdapter"]
