"""Synchronous, bounded client for LNemail's paid outgoing-email API."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_MAX_REQUEST_BYTES = 16_384
_MAX_RESPONSE_BYTES = 16_384
_PAYMENT_HASH_PATTERN = r"^[0-9a-f]{64}$"
_BOLT11_AMOUNT = re.compile(r"^([1-9][0-9]*)([munp]?)$")
_BOLT11_NETWORKS = ("lnbcrt", "lntbs", "lnbc", "lntb", "lnsb")


class LnemailError(RuntimeError):
    """Sanitized provider failure safe to persist or log."""

    def __init__(self, code: str, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class LnemailConfigurationError(ValueError):
    """The configured LNemail endpoint or credential is unsafe."""


class LnemailTransportError(LnemailError):
    """The provider response was not known to have completed."""


class LnemailProtocolError(LnemailError):
    """The provider returned a response outside its documented contract."""


class LnemailHTTPError(LnemailError):
    """The provider returned a non-success HTTP status without response details."""

    def __init__(self, status_code: int) -> None:
        super().__init__(
            "http_error",
            f"LNemail request failed with HTTP {status_code}",
            retryable=status_code in {408, 425, 429} or status_code >= 500,
        )
        self.status_code = status_code


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _SendRequest(_StrictModel):
    recipient: str = Field(min_length=3, max_length=254)
    subject: str = Field(min_length=1, max_length=998)
    body: str = Field(min_length=1, max_length=12_000)

    @field_validator("recipient", "subject")
    @classmethod
    def reject_header_injection(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("header value contains a newline")
        return value


class _SendInvoiceResponse(_StrictModel):
    payment_request: str = Field(min_length=1, max_length=4096)
    payment_hash: str = Field(pattern=_PAYMENT_HASH_PATTERN)
    price_sats: int = Field(ge=1, le=2_147_483_647)
    sender_email: str = Field(min_length=3, max_length=254)
    recipient: str = Field(min_length=3, max_length=254)
    subject: str = Field(min_length=1, max_length=998)
    provider: str | None = Field(default=None, min_length=1, max_length=64)


class _SendStatusResponse(_StrictModel):
    payment_status: Literal["pending", "paid", "expired", "failed"]
    delivery_status: Literal["pending", "sent", "failed", "expired"]
    delivery_error: str | None = Field(default=None, max_length=500)
    sender_email: str | None = Field(default=None, max_length=254)
    recipient: str | None = Field(default=None, max_length=254)
    subject: str | None = Field(default=None, max_length=998)
    sent_at: datetime | None = None
    retry_count: int = Field(default=0, ge=0, le=1_000_000)


@dataclass(frozen=True)
class LnemailInvoice:
    payment_request: str
    payment_hash: str
    price_sats: int
    provider: str | None


@dataclass(frozen=True)
class LnemailStatus:
    payment_status: Literal["pending", "paid", "expired", "failed"]
    delivery_status: Literal["pending", "sent", "failed", "expired"]
    sent_at: datetime | None
    retry_count: int


class LnemailAdapter:
    """Call one configured HTTPS origin without following redirects."""

    def __init__(
        self,
        base_url: str,
        access_token: str,
        *,
        timeout_seconds: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        try:
            origin = httpx.URL(base_url)
            port = origin.port
        except (TypeError, ValueError):
            raise LnemailConfigurationError(
                "LNemail base URL must be an exact HTTPS origin"
            ) from None
        if (
            origin.scheme != "https"
            or not origin.host
            or origin.userinfo
            or origin.path not in {"", "/"}
            or origin.query
            or origin.fragment
            or port not in {None, 443}
        ):
            raise LnemailConfigurationError("LNemail base URL must be an exact HTTPS origin")
        if (
            not access_token
            or len(access_token) > 4096
            or access_token.strip() != access_token
            or any(ord(character) < 32 or ord(character) == 127 for character in access_token)
        ):
            raise LnemailConfigurationError("LNemail access token is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 60
        ):
            raise LnemailConfigurationError("LNemail timeout must be within 0-60 seconds")

        self._origin = origin.copy_with(path="/", query=None, fragment=None)
        self._headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
            "Accept-Encoding": "identity",
        }
        self._timeout = timeout_seconds
        self._client = client or httpx.Client(
            follow_redirects=False,
            timeout=timeout_seconds,
            trust_env=False,
        )

    def create_send_invoice(self, recipient: str, subject: str, body: str) -> LnemailInvoice:
        try:
            request = _SendRequest(recipient=recipient, subject=subject, body=body)
        except ValidationError:
            raise LnemailProtocolError(
                "invalid_request", "LNemail request is invalid", retryable=False
            ) from None
        encoded = request.model_dump_json().encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise LnemailProtocolError(
                "request_too_large", "LNemail request is too large", retryable=False
            )
        payload = self._request("POST", "/api/v1/email/send", content=encoded)
        try:
            response = _SendInvoiceResponse.model_validate_json(payload)
        except ValidationError:
            raise LnemailProtocolError(
                "invalid_response", "LNemail returned an invalid response", retryable=False
            ) from None
        if response.recipient != recipient or response.subject != subject:
            raise LnemailProtocolError(
                "response_mismatch", "LNemail returned a mismatched response", retryable=False
            )
        if _bolt11_amount_msats(response.payment_request) != response.price_sats * 1000:
            raise LnemailProtocolError(
                "invoice_amount_mismatch",
                "LNemail returned a mismatched invoice amount",
                retryable=False,
            )
        return LnemailInvoice(
            response.payment_request,
            response.payment_hash,
            response.price_sats,
            response.provider,
        )

    def send_status(self, payment_hash: str) -> LnemailStatus:
        if len(payment_hash) != 64 or any(
            character not in "0123456789abcdef" for character in payment_hash
        ):
            raise LnemailProtocolError(
                "invalid_payment_hash", "LNemail payment hash is invalid", retryable=False
            )
        payload = self._request("GET", f"/api/v1/email/send/status/{payment_hash}", content=None)
        try:
            response = _SendStatusResponse.model_validate_json(payload)
        except ValidationError:
            raise LnemailProtocolError(
                "invalid_response", "LNemail returned an invalid response", retryable=False
            ) from None
        return LnemailStatus(
            response.payment_status,
            response.delivery_status,
            response.sent_at,
            response.retry_count,
        )

    def _request(self, method: str, path: str, *, content: bytes | None) -> bytes:
        headers = self._headers | ({"Content-Type": "application/json"} if content else {})
        try:
            with self._client.stream(
                method,
                self._origin.copy_with(path=path),
                headers=headers,
                content=content,
                timeout=self._timeout,
                follow_redirects=False,
            ) as response:
                if not 200 <= response.status_code < 300:
                    raise LnemailHTTPError(response.status_code)
                content_length = response.headers.get("Content-Length")
                if content_length is not None:
                    try:
                        if int(content_length) > _MAX_RESPONSE_BYTES:
                            raise LnemailProtocolError(
                                "response_too_large",
                                "LNemail response is too large",
                                retryable=False,
                            )
                    except ValueError:
                        raise LnemailProtocolError(
                            "invalid_response",
                            "LNemail returned an invalid response",
                            retryable=False,
                        ) from None
                payload = bytearray()
                for chunk in response.iter_bytes():
                    payload.extend(chunk)
                    if len(payload) > _MAX_RESPONSE_BYTES:
                        raise LnemailProtocolError(
                            "response_too_large",
                            "LNemail response is too large",
                            retryable=False,
                        )
                return bytes(payload)
        except LnemailError:
            raise
        except httpx.TimeoutException:
            raise LnemailTransportError(
                "timeout", "LNemail request timed out", retryable=True
            ) from None
        except httpx.HTTPError:
            raise LnemailTransportError(
                "transport", "LNemail transport failed", retryable=True
            ) from None


def _bolt11_amount_msats(payment_request: str) -> int:
    """Extract the authenticated BOLT11 HRP amount for policy enforcement."""
    normalized = payment_request.lower()
    if (
        not payment_request.isascii()
        or payment_request
        not in {
            normalized,
            payment_request.upper(),
        }
        or "1" not in normalized
    ):
        raise LnemailProtocolError(
            "invalid_invoice", "LNemail returned an invalid invoice", retryable=False
        )
    human_readable = normalized.rsplit("1", 1)[0]
    network = next(
        (prefix for prefix in _BOLT11_NETWORKS if human_readable.startswith(prefix)), None
    )
    match = _BOLT11_AMOUNT.fullmatch(human_readable[len(network) :] if network else "")
    if match is None:
        raise LnemailProtocolError(
            "invalid_invoice", "LNemail returned an invalid invoice", retryable=False
        )
    value = int(match.group(1))
    unit = match.group(2)
    if unit == "m":
        return value * 100_000_000
    if unit == "u":
        return value * 100_000
    if unit == "n":
        return value * 100
    if unit == "p":
        if value % 10:
            raise LnemailProtocolError(
                "invalid_invoice", "LNemail returned an invalid invoice", retryable=False
            )
        return value // 10
    return value * 100_000_000_000
