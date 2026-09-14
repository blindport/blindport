"""Receive-only, Coinos-pinned LNURL-pay adapter."""

from __future__ import annotations

import hmac
import json
import math
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from urllib.parse import urlsplit

import httpx
from bolt11 import decode

from blindport.core.lightning_address import validate_lightning_address

from .base import LightningInvoiceState

_COINOS_DOMAIN = "coinos.io"
_MAX_JSON_BYTES = 64 * 1024
_MAX_MSATS = 2_100_000_000_000_000
_CONTROL_CHARACTERS = frozenset(chr(code) for code in range(32)) | {chr(127)}


@dataclass(frozen=True)
class LnurlInvoice:
    payment_request: str
    payment_hash: str
    amount_sats: int
    expires_at: datetime
    verify_url: str
    metadata: str


@dataclass(frozen=True)
class _PayRequest:
    callback_url: httpx.URL
    min_sendable_msats: int
    max_sendable_msats: int
    metadata: str


class CoinosLnurlError(RuntimeError):
    """Sanitized Coinos LNURL failure safe to record or expose."""

    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class CoinosLnurlAdapter:
    """Create and verify receive-only LNURL-pay invoices for one Coinos address."""

    def __init__(
        self,
        address: str = "blindport@coinos.io",
        request_timeout_seconds: float = 10.0,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        canonical_address = validate_lightning_address(address)
        username, domain = canonical_address.split("@")
        if domain != _COINOS_DOMAIN:
            raise ValueError("Coinos LNURL address must use coinos.io")
        if (
            isinstance(request_timeout_seconds, bool)
            or not isinstance(request_timeout_seconds, int | float)
            or not math.isfinite(request_timeout_seconds)
            or request_timeout_seconds <= 0
        ):
            raise ValueError("Coinos LNURL timeout must be a positive finite number")

        self._username = username
        self._request_timeout_seconds = float(request_timeout_seconds)
        self._client = httpx.Client(
            transport=transport,
            timeout=self._request_timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            headers={"Accept": "application/json"},
        )

    def close(self) -> None:
        self._client.close()

    def health(self) -> bool:
        """Check only Lightning Address discovery, never invoice or verify endpoints."""
        try:
            self._discover()
        except CoinosLnurlError:
            return False
        return True

    def create_invoice(self, amount_sats: int) -> LnurlInvoice:
        if isinstance(amount_sats, bool) or not isinstance(amount_sats, int):
            raise ValueError("LNURL invoice amount must be an integer number of sats")
        if not 1 <= amount_sats <= _MAX_MSATS // 1000:
            raise ValueError("LNURL invoice amount is outside the allowed range")
        amount_msats = amount_sats * 1000
        pay_request = self._discover()
        if not pay_request.min_sendable_msats <= amount_msats <= pay_request.max_sendable_msats:
            raise CoinosLnurlError(
                "amount_out_of_range",
                "Coinos LNURL amount is outside the advertised range",
                retryable=False,
            )

        callback_response = self._get_json(
            pay_request.callback_url.copy_add_param("amount", str(amount_msats))
        )
        if "status" in callback_response and callback_response["status"] != "OK":
            raise CoinosLnurlError(
                "provider_rejected",
                "Coinos LNURL rejected the invoice request",
                retryable=False,
            )
        payment_request = callback_response.get("pr")
        if not isinstance(payment_request, str) or not payment_request:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid invoice response",
                retryable=False,
            )
        verify_url = self._coinos_url(callback_response.get("verify"), "verify")
        payment_hash, expires_at = self._validate_invoice(
            payment_request,
            amount_msats,
            pay_request.metadata,
        )
        return LnurlInvoice(
            payment_request=payment_request,
            payment_hash=payment_hash,
            amount_sats=amount_sats,
            expires_at=expires_at,
            verify_url=str(verify_url),
            metadata=pay_request.metadata,
        )

    def invoice_state(
        self,
        *,
        payment_request: str,
        payment_hash: str,
        verify_url: str,
    ) -> LightningInvoiceState:
        if not isinstance(payment_request, str) or not payment_request:
            raise ValueError("stored LNURL payment request is invalid")
        expected_hash = _canonical_payment_hash(payment_hash)
        response = self._get_json(self._coinos_url(verify_url, "verify"))
        if response.get("status") != "OK" or response.get("pr") != payment_request:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid verification response",
                retryable=False,
            )
        settled = response.get("settled")
        if type(settled) is not bool:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid verification response",
                retryable=False,
            )
        if not settled:
            if "preimage" not in response or response["preimage"] is not None:
                raise CoinosLnurlError(
                    "invalid_response",
                    "Coinos LNURL returned an invalid verification response",
                    retryable=False,
                )
            return LightningInvoiceState.OPEN

        preimage = response.get("preimage")
        if not isinstance(preimage, str) or len(preimage) != 64 or preimage.lower() != preimage:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid verification response",
                retryable=False,
            )
        try:
            preimage_bytes = bytes.fromhex(preimage)
        except ValueError:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid verification response",
                retryable=False,
            ) from None
        if len(preimage_bytes) != 32 or not hmac.compare_digest(
            sha256(preimage_bytes).hexdigest(), expected_hash
        ):
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid verification response",
                retryable=False,
            )
        return LightningInvoiceState.SETTLED

    def _discover(self) -> _PayRequest:
        response = self._get_json(
            httpx.URL(f"https://{_COINOS_DOMAIN}/.well-known/lnurlp/{self._username}")
        )
        if response.get("tag") != "payRequest":
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid discovery response",
                retryable=False,
            )
        min_sendable = _strict_msats(response.get("minSendable"))
        max_sendable = _strict_msats(response.get("maxSendable"))
        if min_sendable > max_sendable:
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid discovery response",
                retryable=False,
            )
        metadata = response.get("metadata")
        if not isinstance(metadata, str) or not _has_text_plain_metadata(metadata):
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned an invalid discovery response",
                retryable=False,
            )
        return _PayRequest(
            callback_url=self._coinos_url(response.get("callback"), "callback"),
            min_sendable_msats=min_sendable,
            max_sendable_msats=max_sendable,
            metadata=metadata,
        )

    def _get_json(self, url: httpx.URL) -> dict[str, Any]:
        try:
            with self._client.stream("GET", url) as response:
                if response.is_redirect:
                    raise CoinosLnurlError(
                        "redirect",
                        "Coinos LNURL redirected the request",
                        retryable=False,
                    )
                if not 200 <= response.status_code < 300:
                    raise CoinosLnurlError(
                        "http_error",
                        "Coinos LNURL request failed",
                        retryable=response.status_code in {408, 429} or response.status_code >= 500,
                    )
                content_length = response.headers.get("content-length")
                if content_length is not None and (
                    not content_length.isdecimal() or int(content_length) > _MAX_JSON_BYTES
                ):
                    raise CoinosLnurlError(
                        "response_too_large",
                        "Coinos LNURL response is too large",
                        retryable=False,
                    )
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_JSON_BYTES:
                        raise CoinosLnurlError(
                            "response_too_large",
                            "Coinos LNURL response is too large",
                            retryable=False,
                        )
        except CoinosLnurlError:
            raise
        except httpx.TimeoutException:
            raise CoinosLnurlError(
                "timeout", "Coinos LNURL request timed out", retryable=True
            ) from None
        except httpx.HTTPError:
            raise CoinosLnurlError(
                "transport", "Coinos LNURL transport is unavailable", retryable=True
            ) from None

        try:
            text = body.decode("utf-8")
            payload = json.loads(
                text,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_json_constant,
            )
        except (UnicodeDecodeError, ValueError, TypeError):
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned invalid JSON",
                retryable=False,
            ) from None
        if not isinstance(payload, dict):
            raise CoinosLnurlError(
                "invalid_response",
                "Coinos LNURL returned invalid JSON",
                retryable=False,
            )
        return payload

    @staticmethod
    def _coinos_url(value: object, field: str) -> httpx.URL:
        if (
            not isinstance(value, str)
            or not value
            or "\\" in value
            or "#" in value
            or any(character in _CONTROL_CHARACTERS for character in value)
        ):
            raise CoinosLnurlError(
                "invalid_response",
                f"Coinos LNURL returned an invalid {field} URL",
                retryable=False,
            )
        try:
            if "@" in urlsplit(value).netloc:
                raise ValueError("credentials are not allowed")
        except ValueError:
            raise CoinosLnurlError(
                "invalid_response",
                f"Coinos LNURL returned an invalid {field} URL",
                retryable=False,
            ) from None
        try:
            url = httpx.URL(value)
        except (TypeError, ValueError):
            raise CoinosLnurlError(
                "invalid_response",
                f"Coinos LNURL returned an invalid {field} URL",
                retryable=False,
            ) from None
        if (
            url.scheme != "https"
            or url.host != _COINOS_DOMAIN
            or url.port not in (None, 443)
            or url.username not in (None, "")
            or url.password not in (None, "")
            or url.fragment not in (None, "")
        ):
            raise CoinosLnurlError(
                "invalid_response",
                f"Coinos LNURL returned an invalid {field} URL",
                retryable=False,
            )
        return url

    @staticmethod
    def _validate_invoice(
        payment_request: str,
        amount_msats: int,
        metadata: str,
    ) -> tuple[str, datetime]:
        try:
            invoice = decode(payment_request, strict=True)
            if invoice.signature is None or invoice.payee is None:
                raise ValueError("missing signature")
            invoice.signature.verify(invoice.payee)
            if invoice.currency != "bc" or invoice.amount_msat is None:
                raise ValueError("invalid network or amount")
            if int(invoice.amount_msat) != amount_msats:
                raise ValueError("incorrect amount")
            payment_hash = _canonical_payment_hash(invoice.payment_hash)
            expected_description_hash = sha256(metadata.encode("utf-8")).digest()
            description_hash = bytes.fromhex(invoice.description_hash or "")
            if len(description_hash) != 32 or not hmac.compare_digest(
                description_hash, expected_description_hash
            ):
                raise ValueError("incorrect description hash")
            expires_at = datetime.fromtimestamp(invoice.expiry_time, tz=UTC)
            if expires_at <= datetime.now(UTC):
                raise ValueError("expired")
        except Exception:
            raise CoinosLnurlError(
                "invalid_invoice",
                "Coinos LNURL returned an invalid invoice",
                retryable=False,
            ) from None
        return payment_hash, expires_at


def _strict_msats(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_MSATS:
        raise CoinosLnurlError(
            "invalid_response",
            "Coinos LNURL returned an invalid discovery response",
            retryable=False,
        )
    return value


def _has_text_plain_metadata(metadata: str) -> bool:
    try:
        entries = json.loads(
            metadata,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (TypeError, ValueError):
        return False
    if not isinstance(entries, list) or not entries:
        return False
    has_text_plain = False
    for entry in entries:
        if (
            not isinstance(entry, list)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
        ):
            return False
        has_text_plain |= entry[0] == "text/plain"
    return has_text_plain


def _canonical_payment_hash(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or value.lower() != value:
        raise ValueError("payment hash must be lowercase 32-byte hex")
    try:
        raw_hash = bytes.fromhex(value)
    except ValueError:
        raise ValueError("payment hash must be lowercase 32-byte hex") from None
    if len(raw_hash) != 32:
        raise ValueError("payment hash must be lowercase 32-byte hex")
    return raw_hash.hex()


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
