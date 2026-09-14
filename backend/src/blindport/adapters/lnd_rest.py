"""Lightning adapter for LND's REST API."""

from __future__ import annotations

import base64
import math
import ssl
from hashlib import sha256
from pathlib import Path
from time import monotonic, time
from typing import Any

import httpx

from .base import LightningAdapter, LightningInvoice, LightningInvoiceState


class LndRestLightningAdapter(LightningAdapter):
    """Create and look up invoices through LND's official REST contract."""

    def __init__(
        self,
        rest_url: str,
        cert_path: str,
        macaroon_path: str,
        invoice_expiry_seconds: int = 600,
        request_timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        url = httpx.URL(rest_url)
        if url.scheme != "https" or not url.host:
            raise ValueError("LND_REST_URL must be an absolute https URL")
        if url.query or url.fragment:
            raise ValueError("LND_REST_URL must not include a query string or fragment")
        if not isinstance(invoice_expiry_seconds, int) or invoice_expiry_seconds <= 0:
            raise ValueError("LND_INVOICE_EXPIRY_SECONDS must be a positive integer")
        if not math.isfinite(request_timeout_seconds) or request_timeout_seconds <= 0:
            raise ValueError("LND_REQUEST_TIMEOUT_SECONDS must be a positive number")

        cert = Path(cert_path).expanduser()
        if not cert.is_file():
            raise ValueError(f"LND_CERT_PATH is not a readable file: {cert}")
        try:
            if not cert.read_bytes():
                raise ValueError("LND_CERT_PATH must not be empty")
        except OSError as e:
            raise ValueError(f"LND_CERT_PATH is not readable: {cert}") from e
        macaroon = Path(macaroon_path).expanduser()
        if not macaroon.is_file():
            raise ValueError(f"LND_MACAROON_PATH is not a readable file: {macaroon}")
        try:
            macaroon_bytes = macaroon.read_bytes()
        except OSError as e:
            raise ValueError(f"LND_MACAROON_PATH is not readable: {macaroon}") from e
        if not macaroon_bytes:
            raise ValueError("LND_MACAROON_PATH must not be empty")

        self._rest_url = str(url).rstrip("/")
        self._invoice_expiry_seconds = invoice_expiry_seconds
        self._request_timeout_seconds = request_timeout_seconds
        self._headers = {"Grpc-Metadata-macaroon": macaroon_bytes.hex()}
        if client is not None:
            self._client = client
        else:
            try:
                tls_context = ssl.create_default_context(cafile=str(cert))
            except (OSError, ssl.SSLError) as e:
                raise ValueError(f"LND_CERT_PATH is not a valid TLS certificate: {cert}") from e
            self._client = httpx.Client(verify=tls_context)

    def health(self) -> bool:
        response = self._client.get(
            f"{self._rest_url}/v1/getinfo",
            headers=self._headers,
            timeout=self._request_timeout_seconds,
        )
        response.raise_for_status()
        payload = self._json_object(response)
        if not isinstance(payload.get("identity_pubkey"), str) or not payload["identity_pubkey"]:
            raise RuntimeError("LND getinfo response has no identity_pubkey")
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
        effective_expiry = (
            min(self._invoice_expiry_seconds, expiry_seconds)
            if expiry_seconds is not None
            else self._invoice_expiry_seconds
        )
        response = self._client.post(
            f"{self._rest_url}/v1/invoices",
            headers=self._headers,
            json={
                "value": str(amount_sats),
                "memo": memo,
                "expiry": str(effective_expiry),
            },
            timeout=self._request_timeout_seconds,
        )
        response.raise_for_status()
        payload = self._json_object(response)
        payment_request = payload.get("payment_request")
        if not isinstance(payment_request, str) or not payment_request:
            raise RuntimeError("LND invoice response has no payment_request")
        payment_hash = self._decode_payment_hash(payload.get("r_hash"))
        return LightningInvoice(
            payment_request=payment_request,
            payment_hash=payment_hash,
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
        """Create an invoice idempotently using LND's caller-supplied preimage."""
        if len(payment_preimage) != 32:
            raise ValueError("payment preimage must be 32 bytes")
        effective_expiry = self._effective_expiry(expiry_seconds)
        expiry_deadline = monotonic() + effective_expiry
        payment_hash = sha256(payment_preimage).hexdigest()

        existing = self._lookup_invoice(payment_hash, allow_missing=True)
        if existing is not None:
            return self._invoice_from_lookup(existing, payment_hash, amount_sats, memo)

        remaining_expiry = expiry_deadline - monotonic()
        if remaining_expiry <= 0:
            raise TimeoutError("invoice expiry elapsed during LND lookup")
        create_expiry = math.floor(remaining_expiry)
        if create_expiry <= 0:
            raise TimeoutError("invoice expiry elapsed during LND lookup")

        try:
            response = self._client.post(
                f"{self._rest_url}/v1/invoices",
                headers=self._headers,
                json={
                    "value": str(amount_sats),
                    "memo": memo,
                    "expiry": str(create_expiry),
                    "r_preimage": base64.b64encode(payment_preimage).decode("ascii"),
                },
                timeout=self._request_timeout_seconds,
            )
            response.raise_for_status()
            payload = self._json_object(response)
            invoice = self._invoice_from_create(payload, amount_sats, create_expiry)
            if invoice.payment_hash != payment_hash:
                raise RuntimeError("LND invoice response does not match requested preimage")
            return invoice
        except Exception as create_error:
            # A timeout or proxy error can occur after LND commits the invoice.
            # Recover by its deterministic hash before exposing the failure.
            try:
                recovered = self._lookup_invoice(payment_hash, allow_missing=True)
            except Exception as lookup_error:
                raise create_error from lookup_error
            if recovered is None:
                raise create_error
            return self._invoice_from_lookup(recovered, payment_hash, amount_sats, memo)

    def is_invoice_paid(self, payment_hash: str) -> bool:
        return self.invoice_state(payment_hash) == LightningInvoiceState.SETTLED

    def invoice_state(self, payment_hash: str) -> LightningInvoiceState:
        payload = self._lookup_invoice(payment_hash)
        if payload is None:  # pragma: no cover - only possible with allow_missing
            raise RuntimeError("LND invoice disappeared")
        state = payload.get("state")
        states = {
            "OPEN": LightningInvoiceState.OPEN,
            "ACCEPTED": LightningInvoiceState.ACCEPTED,
            "SETTLED": LightningInvoiceState.SETTLED,
            "CANCELED": LightningInvoiceState.CANCELED,
        }
        if state in states:
            return states[state]
        raise RuntimeError("LND invoice lookup response has an invalid state")

    def lookup_invoice(
        self, payment_hash: str, amount_sats: int, memo: str
    ) -> LightningInvoice | None:
        payload = self._lookup_invoice(payment_hash, allow_missing=True)
        if payload is None:
            return None
        return self._invoice_from_lookup(payload, payment_hash, amount_sats, memo)

    def mark_paid(self, payment_hash: str) -> None:
        raise NotImplementedError("mark_paid is only supported by mock Lightning adapters")

    @staticmethod
    def _json_object(response: httpx.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as e:
            raise RuntimeError("LND returned malformed JSON") from e
        if not isinstance(payload, dict):
            raise RuntimeError("LND returned a non-object JSON response")
        return payload

    @staticmethod
    def _decode_payment_hash(value: Any) -> str:
        if not isinstance(value, str):
            raise RuntimeError("LND invoice response has no r_hash")
        try:
            raw_hash = base64.b64decode(value, validate=True)
        except (ValueError, base64.binascii.Error) as e:
            raise RuntimeError("LND invoice response has an invalid r_hash") from e
        if len(raw_hash) != 32:
            raise RuntimeError("LND invoice response r_hash must be 32 bytes")
        return raw_hash.hex()

    def _effective_expiry(self, expiry_seconds: int | None) -> int:
        if expiry_seconds is not None and (
            not isinstance(expiry_seconds, int)
            or isinstance(expiry_seconds, bool)
            or expiry_seconds <= 0
        ):
            raise ValueError("invoice expiry must be a positive integer")
        return (
            min(self._invoice_expiry_seconds, expiry_seconds)
            if expiry_seconds is not None
            else self._invoice_expiry_seconds
        )

    def _lookup_invoice(
        self, payment_hash: str, *, allow_missing: bool = False
    ) -> dict[str, Any] | None:
        try:
            raw_hash = bytes.fromhex(payment_hash)
        except ValueError as e:
            raise ValueError("payment_hash must be lowercase 32-byte hex") from e
        if len(raw_hash) != 32 or raw_hash.hex() != payment_hash:
            raise ValueError("payment_hash must be lowercase 32-byte hex")
        response = self._client.get(
            f"{self._rest_url}/v2/invoices/lookup",
            headers=self._headers,
            params={"payment_hash": base64.b64encode(raw_hash).decode("ascii")},
            timeout=self._request_timeout_seconds,
        )
        if allow_missing and response.status_code == 404:
            return None
        response.raise_for_status()
        return self._json_object(response)

    def _invoice_from_create(
        self, payload: dict[str, Any], amount_sats: int, expires_in_seconds: int
    ) -> LightningInvoice:
        payment_request = payload.get("payment_request")
        if not isinstance(payment_request, str) or not payment_request:
            raise RuntimeError("LND invoice response has no payment_request")
        return LightningInvoice(
            payment_request=payment_request,
            payment_hash=self._decode_payment_hash(payload.get("r_hash")),
            amount_sats=amount_sats,
            expires_in_seconds=expires_in_seconds,
        )

    def _invoice_from_lookup(
        self,
        payload: dict[str, Any],
        payment_hash: str,
        amount_sats: int,
        memo: str,
    ) -> LightningInvoice:
        recovered_hash = self._decode_payment_hash(payload.get("r_hash"))
        if recovered_hash != payment_hash:
            raise RuntimeError("LND lookup returned a different payment hash")
        if payload.get("memo") != memo:
            raise RuntimeError("LND lookup invoice memo does not match payment outbox")
        try:
            recovered_amount = int(payload["value"])
            creation_date = int(payload["creation_date"])
            expiry = int(payload["expiry"])
        except (KeyError, TypeError, ValueError) as e:
            raise RuntimeError("LND lookup invoice has invalid amount or expiry metadata") from e
        if recovered_amount != amount_sats:
            raise RuntimeError("LND lookup invoice amount does not match payment outbox")
        if creation_date <= 0 or expiry <= 0:
            raise RuntimeError("LND lookup invoice has invalid amount or expiry metadata")
        payment_request = payload.get("payment_request")
        if not isinstance(payment_request, str) or not payment_request:
            raise RuntimeError("LND lookup invoice has no payment_request")
        return LightningInvoice(
            payment_request=payment_request,
            payment_hash=recovered_hash,
            amount_sats=amount_sats,
            expires_in_seconds=max(0, math.floor(creation_date + expiry - time())),
        )
