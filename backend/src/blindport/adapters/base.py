"""Adapter interfaces for Lightning, Cashu, and NWC payment backends.

Each adapter is intentionally tiny so the rest of the application is agnostic
to the chosen backend. The default implementations are in-memory mocks, ideal
for unit + e2e tests. Production builds can swap them out via configuration.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal


@dataclass
class LightningInvoice:
    payment_request: str
    payment_hash: str
    amount_sats: int
    expires_in_seconds: int


class LightningAdapter(ABC):
    """Talks to an LN node (real LND, mock, or otherwise)."""

    @abstractmethod
    def health(self) -> bool:
        """Return whether the configured Lightning backend is reachable and usable."""

    @abstractmethod
    def create_invoice(
        self,
        amount_sats: int,
        memo: str,
        expiry_seconds: int | None = None,
    ) -> LightningInvoice: ...

    @abstractmethod
    def create_or_lookup_invoice(
        self,
        amount_sats: int,
        memo: str,
        payment_preimage: bytes,
        expiry_seconds: int | None = None,
    ) -> LightningInvoice:
        """Create or recover the invoice identified by ``payment_preimage``."""

    @abstractmethod
    def lookup_invoice(
        self, payment_hash: str, amount_sats: int, memo: str
    ) -> LightningInvoice | None:
        """Recover an existing invoice without creating one."""

    @abstractmethod
    def is_invoice_paid(self, payment_hash: str) -> bool: ...

    @abstractmethod
    def invoice_state(self, payment_hash: str) -> LightningInvoiceState:
        """Return the authoritative LND invoice state."""

    @abstractmethod
    def mark_paid(self, payment_hash: str) -> None:
        """Test/admin-only hook to mark an invoice paid (only meaningful in mocks)."""


class CashuAdapter(ABC):
    """Validates Cashu tokens against a trusted mint pool."""

    @abstractmethod
    def validate_and_redeem(self, token: str, expected_amount_sats: int) -> bool:
        """Return True if `token` is valid and at least `expected_amount_sats`.

        Real implementation would call the mint's `/v1/swap` (or melt) endpoint
        to claim the proofs. The mock simply checks an in-memory registry.
        """

    @abstractmethod
    def register_test_token(self, token: str, amount_sats: int) -> None:
        """Test helper: pre-register a token-value pair (mock impls only)."""

    def request_mint_quote(self, amount_sats: int) -> CashuMintQuote:
        """Optional: ask the trusted mint for a bolt11 LN invoice.

        Real implementations should override to call ``POST /v1/mint/quote/bolt11``;
        the mock raises so callers know it's unsupported.
        """
        raise NotImplementedError("cashu adapter does not support mint quotes")


@dataclass
class CashuMintQuote:
    """Generic envelope so the API layer doesn't import RealCashuAdapter."""

    quote_id: str
    bolt11: str
    amount_sats: int
    expires_at: int = 0
    mint_url: str = ""


class LightningInvoiceState(StrEnum):
    OPEN = "open"
    ACCEPTED = "accepted"
    SETTLED = "settled"
    CANCELED = "canceled"


class NwcPaymentState(StrEnum):
    SETTLED = "settled"
    PENDING = "pending"
    FAILED = "failed"
    UNKNOWN = "unknown"


class NwcLookupState(StrEnum):
    SETTLED = "settled"
    PENDING = "pending"
    FAILED = "failed"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class NwcBudgetState(StrEnum):
    AVAILABLE = "available"
    UNLIMITED = "unlimited"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class NwcValidationResult:
    capabilities: tuple[str, ...]
    encryptions: tuple[str, ...]


@dataclass(frozen=True)
class NwcBudgetResult:
    state: NwcBudgetState
    used_budget_msats: int | None = None
    total_budget_msats: int | None = None
    renews_at: int | None = None
    renewal_period: Literal["daily", "weekly", "monthly", "yearly", "never"] | None = None


@dataclass(frozen=True)
class NwcPayResult:
    state: NwcPaymentState
    preimage: str | None = None
    fees_paid_msats: int | None = None


@dataclass(frozen=True)
class NwcLookupResult:
    state: NwcLookupState
    payment_hash: str | None = None
    preimage: str | None = None
    fees_paid_msats: int | None = None


class NwcAdapterError(RuntimeError):
    """Sanitized NWC failure with retry semantics safe for persistence."""

    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class NwcAdapter(ABC):
    """Validates and executes NIP-44-only NWC wallet operations."""

    @abstractmethod
    def validate_connection(self, nwc_uri: str) -> NwcValidationResult: ...

    def get_budget(self, nwc_uri: str) -> NwcBudgetResult:
        return NwcBudgetResult(NwcBudgetState.UNSUPPORTED)

    @abstractmethod
    def pay_invoice(self, nwc_uri: str, bolt11: str) -> NwcPayResult: ...

    @abstractmethod
    def lookup_invoice(self, nwc_uri: str, payment_hash: str) -> NwcLookupResult: ...

    @abstractmethod
    def mark_settled(self, payment_hash: str) -> None:
        """Test/admin-only hook (mock impls only)."""
