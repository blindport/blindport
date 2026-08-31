"""In-memory mock implementations of the payment adapters.

These are deterministic, threadsafe, and suitable for unit tests, e2e tests,
and developer environments.
"""

from __future__ import annotations

import os
import threading
import time
from hashlib import sha256

from .base import (
    ClinkAdapter,
    ClinkPaymentState,
    ClinkPayResult,
    ClinkValidationResult,
    LightningAdapter,
    LightningInvoice,
    LightningInvoiceState,
    NwcAdapter,
    NwcBudgetResult,
    NwcBudgetState,
    NwcLookupResult,
    NwcLookupState,
    NwcPaymentState,
    NwcPayResult,
    NwcValidationResult,
)


def _hex(n: int) -> str:
    return os.urandom(n).hex()


class MockLightningAdapter(LightningAdapter):
    """In-memory Lightning backend: invoices are tracked in a dict, never settled
    automatically, settled either by `mark_paid` or by `auto_settle=True`.
    """

    def __init__(self, auto_settle: bool = False) -> None:
        self._lock = threading.Lock()
        self._invoices: dict[str, dict] = {}
        self.auto_settle = auto_settle

    def health(self) -> bool:
        return True

    def create_invoice(
        self,
        amount_sats: int,
        memo: str,
        expiry_seconds: int | None = None,
    ) -> LightningInvoice:
        if expiry_seconds is not None and (
            not isinstance(expiry_seconds, int)
            or isinstance(expiry_seconds, bool)
            or expiry_seconds <= 0
        ):
            raise ValueError("invoice expiry must be a positive integer")
        effective_expiry = expiry_seconds if expiry_seconds is not None else 600
        ph = _hex(32)
        bolt11 = f"lnbcrt{amount_sats}u1mock{ph[:20]}"
        with self._lock:
            self._invoices[ph] = {
                "amount_sats": amount_sats,
                "memo": memo,
                "paid": self.auto_settle,
                "bolt11": bolt11,
            }
        return LightningInvoice(
            payment_request=bolt11,
            payment_hash=ph,
            amount_sats=amount_sats,
            expires_in_seconds=effective_expiry,
        )

    def create_or_lookup_invoice(
        self,
        amount_sats: int,
        memo: str,
        payment_preimage: bytes,
        expiry_seconds: int | None = None,
    ) -> LightningInvoice:
        if len(payment_preimage) != 32:
            raise ValueError("payment preimage must be 32 bytes")
        if expiry_seconds is not None and (
            not isinstance(expiry_seconds, int)
            or isinstance(expiry_seconds, bool)
            or expiry_seconds <= 0
        ):
            raise ValueError("invoice expiry must be a positive integer")
        effective_expiry = expiry_seconds if expiry_seconds is not None else 600
        payment_hash = sha256(payment_preimage).hexdigest()
        now = time.time()
        with self._lock:
            existing = self._invoices.get(payment_hash)
            if existing is None:
                existing = {
                    "amount_sats": amount_sats,
                    "memo": memo,
                    "paid": self.auto_settle,
                    "bolt11": f"lnbcrt{amount_sats}u1mock{payment_hash[:20]}",
                    "created_at": now,
                    "expiry": effective_expiry,
                }
                self._invoices[payment_hash] = existing
            elif existing["amount_sats"] != amount_sats or existing["memo"] != memo:
                raise RuntimeError("mock invoice identity conflicts with existing invoice")
            remaining = max(0, int(existing["created_at"] + existing["expiry"] - now))
            return LightningInvoice(
                payment_request=existing["bolt11"],
                payment_hash=payment_hash,
                amount_sats=amount_sats,
                expires_in_seconds=remaining,
            )

    def is_invoice_paid(self, payment_hash: str) -> bool:
        with self._lock:
            inv = self._invoices.get(payment_hash)
            return bool(inv and inv["paid"])

    def invoice_state(self, payment_hash: str) -> LightningInvoiceState:
        with self._lock:
            invoice = self._invoices.get(payment_hash)
            if invoice is None:
                raise RuntimeError("mock invoice disappeared")
            return LightningInvoiceState.SETTLED if invoice["paid"] else LightningInvoiceState.OPEN

    def lookup_invoice(
        self, payment_hash: str, amount_sats: int, memo: str
    ) -> LightningInvoice | None:
        try:
            raw_hash = bytes.fromhex(payment_hash)
        except ValueError as e:
            raise ValueError("payment_hash must be lowercase 32-byte hex") from e
        if len(raw_hash) != 32 or raw_hash.hex() != payment_hash:
            raise ValueError("payment_hash must be lowercase 32-byte hex")
        now = time.time()
        with self._lock:
            existing = self._invoices.get(payment_hash)
            if existing is None:
                return None
            if existing["amount_sats"] != amount_sats or existing["memo"] != memo:
                raise RuntimeError("mock invoice identity conflicts with existing invoice")
            return LightningInvoice(
                payment_request=existing["bolt11"],
                payment_hash=payment_hash,
                amount_sats=amount_sats,
                expires_in_seconds=max(0, int(existing["created_at"] + existing["expiry"] - now)),
            )

    def mark_paid(self, payment_hash: str) -> None:
        with self._lock:
            if payment_hash in self._invoices:
                self._invoices[payment_hash]["paid"] = True


class MockNwcAdapter(NwcAdapter):
    """NWC mock with the same explicit pay and lookup states as production."""

    def __init__(self, auto_settle: bool = False, settle_callback=None) -> None:
        self._lock = threading.Lock()
        self._payments: dict[str, NwcLookupState] = {}
        self.auto_settle = auto_settle
        self._settle_callback = settle_callback

    def validate_connection(self, nwc_uri: str) -> NwcValidationResult:
        if not nwc_uri:
            raise ValueError("NWC URI is required")
        return NwcValidationResult(
            capabilities=("pay_invoice", "lookup_invoice"),
            encryptions=("nip44_v2",),
        )

    def get_budget(self, nwc_uri: str) -> NwcBudgetResult:
        if not nwc_uri:
            raise ValueError("NWC URI is required")
        return NwcBudgetResult(NwcBudgetState.UNSUPPORTED)

    def pay_invoice(self, nwc_uri: str, bolt11: str) -> NwcPayResult:
        # Mock BOLT11 values contain the first 20 hash characters. The service
        # supplies the complete hash to lookup, so stage the next payment here.
        with self._lock:
            self._payments[bolt11] = (
                NwcLookupState.SETTLED if self.auto_settle else NwcLookupState.PENDING
            )
        return NwcPayResult(
            state=NwcPaymentState.SETTLED if self.auto_settle else NwcPaymentState.PENDING
        )

    def bind_payment_hash(self, bolt11: str, payment_hash: str) -> None:
        with self._lock:
            state = self._payments.pop(bolt11, NwcLookupState.NOT_FOUND)
            self._payments[payment_hash] = state
        if state == NwcLookupState.SETTLED and self._settle_callback is not None:
            self._settle_callback(payment_hash)

    def lookup_invoice(self, nwc_uri: str, payment_hash: str) -> NwcLookupResult:
        with self._lock:
            state = self._payments.get(payment_hash, NwcLookupState.NOT_FOUND)
        return NwcLookupResult(state=state, payment_hash=payment_hash)

    def mark_settled(self, payment_hash: str) -> None:
        with self._lock:
            if payment_hash in self._payments:
                self._payments[payment_hash] = NwcLookupState.SETTLED
        if self._settle_callback is not None:
            self._settle_callback(payment_hash)


class MockClinkAdapter(ClinkAdapter):
    """CLINK mock with deterministic results and optional Lightning settlement."""

    _APP_PUBKEY = sha256(b"blindport:mock-clink-app-pubkey:v1").hexdigest()

    def __init__(self, auto_settle: bool = False, settle_callback=None) -> None:
        self._lock = threading.Lock()
        self._payments: dict[str, tuple[ClinkPaymentState, str | None]] = {}
        self.auto_settle = auto_settle
        self._settle_callback = settle_callback

    @staticmethod
    def _require_ndebit(ndebit: str) -> None:
        if not isinstance(ndebit, str) or not ndebit:
            raise ValueError("CLINK pointer is required")

    def validate_connection(self, ndebit: str) -> ClinkValidationResult:
        self._require_ndebit(ndebit)
        return ClinkValidationResult(self._APP_PUBKEY)

    def pay_invoice(
        self,
        ndebit: str,
        invoice: str,
        amount_sats: int,
        description: str,
    ) -> ClinkPayResult:
        self._require_ndebit(ndebit)
        if not isinstance(invoice, str) or not invoice:
            raise ValueError("invoice is required")
        if not isinstance(amount_sats, int) or isinstance(amount_sats, bool) or amount_sats <= 0:
            raise ValueError("amount_sats must be a positive integer")
        if not isinstance(description, str) or not description:
            raise ValueError("description is required")
        preimage = sha256(f"blindport:mock-clink-preimage:{invoice}".encode()).hexdigest()
        state = ClinkPaymentState.SETTLED if self.auto_settle else ClinkPaymentState.PENDING
        result_preimage = preimage if state == ClinkPaymentState.SETTLED else None
        with self._lock:
            self._payments[invoice] = (state, result_preimage)
        return ClinkPayResult(state, result_preimage)

    def bind_payment_hash(self, invoice: str, payment_hash: str) -> None:
        with self._lock:
            state, preimage = self._payments.pop(invoice, (ClinkPaymentState.PENDING, None))
            self._payments[payment_hash] = (state, preimage)
        if state == ClinkPaymentState.SETTLED and self._settle_callback is not None:
            self._settle_callback(payment_hash)

    def mark_settled(self, payment_hash: str) -> None:
        with self._lock:
            state, preimage = self._payments.get(payment_hash, (ClinkPaymentState.PENDING, None))
            if state == ClinkPaymentState.PENDING:
                preimage = sha256(
                    f"blindport:mock-clink-preimage:{payment_hash}".encode()
                ).hexdigest()
            self._payments[payment_hash] = (ClinkPaymentState.SETTLED, preimage)
        if self._settle_callback is not None:
            self._settle_callback(payment_hash)
