"""Bounded subprocess adapter for the single-shot Bun NWC helper."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from typing import Literal
from urllib.parse import parse_qsl, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .base import (
    NwcAdapter,
    NwcAdapterError,
    NwcLookupResult,
    NwcLookupState,
    NwcPaymentState,
    NwcPayResult,
    NwcValidationResult,
)

_MAX_REQUEST_BYTES = 16_384
_MAX_RESPONSE_BYTES = 16_384


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _SafeError(_StrictModel):
    code: Literal[
        "expired",
        "insufficient_balance",
        "internal",
        "invalid_request",
        "invalid_uri",
        "invalid_wallet_response",
        "payment_failed",
        "quota_exceeded",
        "rate_limited",
        "relay_not_allowed",
        "response_too_large",
        "restricted",
        "timeout",
        "transport",
        "unauthorized",
        "unsupported_capability",
        "unsupported_encryption",
    ]
    message: str = Field(min_length=1, max_length=200)
    retryable: bool


class _Envelope(_StrictModel):
    version: Literal[1]
    ok: bool
    result: dict | None = None
    error: _SafeError | None = None

    @model_validator(mode="after")
    def validate_union(self):
        if self.ok != (self.result is not None) or self.ok == (self.error is not None):
            raise ValueError("helper response union is invalid")
        return self


class _Validation(_StrictModel):
    state: Literal["valid"]
    capabilities: list[Literal["pay_invoice", "lookup_invoice"]]
    encryptions: list[Literal["nip44_v2"]]


class _Pay(_StrictModel):
    state: Literal["settled", "pending", "failed", "unknown"]
    preimage: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fees_paid_msats: int | None = Field(default=None, ge=0, le=2_147_483_647)

    @model_validator(mode="after")
    def validate_settlement_proof(self):
        if self.state == "settled" and self.preimage is None:
            raise ValueError("settled payment has no preimage")
        return self


class _Lookup(_StrictModel):
    state: Literal["settled", "pending", "failed", "not_found", "unknown", "unsupported"]
    payment_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    preimage: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    fees_paid_msats: int | None = Field(default=None, ge=0, le=2_147_483_647)

    @model_validator(mode="after")
    def validate_settlement_proof(self):
        if self.state == "settled" and (self.payment_hash is None or self.preimage is None):
            raise ValueError("settled lookup has no payment proof")
        return self


_SAFE_ERROR_MESSAGES = {
    "expired": "wallet connection expired",
    "insufficient_balance": "wallet balance is insufficient",
    "internal": "wallet operation failed",
    "invalid_request": "wallet helper rejected the request",
    "invalid_uri": "wallet connection URI is invalid",
    "invalid_wallet_response": "wallet returned an invalid response",
    "payment_failed": "wallet reported payment failure",
    "quota_exceeded": "wallet spending quota was exceeded",
    "rate_limited": "wallet rate limit was reached",
    "relay_not_allowed": "wallet relay host is not allowed",
    "response_too_large": "wallet helper response was too large",
    "restricted": "wallet policy rejected the payment",
    "timeout": "wallet operation timed out",
    "transport": "wallet transport is unavailable",
    "unauthorized": "wallet connection is unauthorized",
    "unsupported_capability": "wallet connection lacks required permissions",
    "unsupported_encryption": "wallet connection must support NIP-44 v2",
}


class SubprocessNwcAdapter(NwcAdapter):
    def __init__(
        self,
        executable: str,
        timeout_seconds: float,
        allowed_relay_hosts: tuple[str, ...] = (),
    ) -> None:
        if not os.path.isabs(executable):
            raise ValueError("NWC helper path must be absolute")
        if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            raise ValueError("NWC helper must be an executable regular file")
        if not 0 < timeout_seconds <= 120:
            raise ValueError("NWC helper timeout must be within 0-120 seconds")
        if not allowed_relay_hosts:
            raise ValueError("NWC relay allowlist must not be empty")
        self._executable = executable
        self._timeout = timeout_seconds
        self._allowed_relay_hosts = frozenset(host.lower() for host in allowed_relay_hosts)

    def _validate_relay_hosts(self, nwc_uri: str) -> None:
        try:
            query = urlsplit(nwc_uri).query
            relays = [value for key, value in parse_qsl(query) if key == "relay"]
            parsed_relays = [urlsplit(relay) for relay in relays]
            invalid = not parsed_relays or any(
                relay.scheme.lower() != "wss"
                or relay.hostname is None
                or relay.hostname.lower() not in self._allowed_relay_hosts
                or relay.port not in (None, 443)
                or relay.username is not None
                or relay.password is not None
                for relay in parsed_relays
            )
        except (TypeError, ValueError) as error:
            raise NwcAdapterError(
                "invalid_uri", "wallet connection URI is invalid", retryable=False
            ) from error
        if invalid:
            raise NwcAdapterError(
                "relay_not_allowed", "wallet relay host is not allowed", retryable=False
            )

    def _invoke(self, request: dict) -> dict:
        encoded = json.dumps(request, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise NwcAdapterError("invalid_request", "wallet request is too large", retryable=False)
        try:
            process = subprocess.Popen(
                [self._executable],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
                close_fds=True,
            )
        except OSError as error:
            raise NwcAdapterError(
                "helper_failed", "wallet helper failed", retryable=True
            ) from error
        output = bytearray()
        input_offset = 0
        deadline = time.monotonic() + self._timeout
        try:
            assert process.stdin is not None and process.stdout is not None
            os.set_blocking(process.stdin.fileno(), False)
            os.set_blocking(process.stdout.fileno(), False)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
                selector.register(process.stdout, selectors.EVENT_READ, "stdout")
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError
                    events = selector.select(min(remaining, 0.1))
                    for key, _ in events:
                        if key.data == "stdin":
                            try:
                                written = os.write(key.fileobj.fileno(), encoded[input_offset:])
                            except BrokenPipeError:
                                written = len(encoded) - input_offset
                            input_offset += written
                            if input_offset == len(encoded):
                                selector.unregister(key.fileobj)
                                key.fileobj.close()
                        else:
                            chunk = os.read(key.fileobj.fileno(), 4096)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            output.extend(chunk)
                            if len(output) > _MAX_RESPONSE_BYTES:
                                raise ValueError("oversized helper response")
                    if not selector.get_map():
                        break
                    if process.poll() is not None and not events:
                        continue
            process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except TimeoutError as error:
            process.kill()
            process.wait()
            raise NwcAdapterError(
                "timeout", "wallet operation timed out", retryable=True
            ) from error
        except Exception as error:
            process.kill()
            process.wait()
            raise NwcAdapterError(
                "protocol", "wallet helper protocol failed", retryable=False
            ) from error
        finally:
            if process.stdin is not None:
                process.stdin.close()
            if process.stdout is not None:
                process.stdout.close()
        if process.returncode != 0:
            raise NwcAdapterError("helper_failed", "wallet helper failed", retryable=True)
        try:
            text = output.decode("utf-8")
            decoder = json.JSONDecoder()
            payload, end = decoder.raw_decode(text)
            if text[end:].strip():
                raise ValueError("multiple helper responses")
            envelope = _Envelope.model_validate(payload)
        except (UnicodeDecodeError, ValueError, ValidationError):
            raise NwcAdapterError(
                "protocol", "wallet helper returned an invalid response", retryable=False
            ) from None
        if not envelope.ok:
            assert envelope.error is not None
            raise NwcAdapterError(
                envelope.error.code,
                _SAFE_ERROR_MESSAGES[envelope.error.code],
                retryable=envelope.error.retryable,
            )
        assert envelope.result is not None
        return envelope.result

    def validate_connection(self, nwc_uri: str) -> NwcValidationResult:
        self._validate_relay_hosts(nwc_uri)
        try:
            result = _Validation.model_validate(
                self._invoke(
                    {
                        "version": 1,
                        "operation": "validate",
                        "nwc_uri": nwc_uri,
                        "allowed_relay_hosts": sorted(self._allowed_relay_hosts),
                    }
                )
            )
        except ValidationError:
            raise NwcAdapterError(
                "protocol", "wallet helper returned an invalid response", retryable=False
            ) from None
        if set(result.capabilities) != {"pay_invoice", "lookup_invoice"}:
            raise NwcAdapterError(
                "protocol", "wallet helper returned invalid capabilities", retryable=False
            )
        return NwcValidationResult(tuple(result.capabilities), tuple(result.encryptions))

    def pay_invoice(self, nwc_uri: str, bolt11: str) -> NwcPayResult:
        self._validate_relay_hosts(nwc_uri)
        try:
            result = _Pay.model_validate(
                self._invoke(
                    {
                        "version": 1,
                        "operation": "pay_invoice",
                        "nwc_uri": nwc_uri,
                        "allowed_relay_hosts": sorted(self._allowed_relay_hosts),
                        "invoice": bolt11,
                    }
                )
            )
        except ValidationError:
            raise NwcAdapterError(
                "protocol", "wallet helper returned an invalid response", retryable=False
            ) from None
        return NwcPayResult(NwcPaymentState(result.state), result.preimage, result.fees_paid_msats)

    def lookup_invoice(self, nwc_uri: str, payment_hash: str) -> NwcLookupResult:
        self._validate_relay_hosts(nwc_uri)
        try:
            result = _Lookup.model_validate(
                self._invoke(
                    {
                        "version": 1,
                        "operation": "lookup_invoice",
                        "nwc_uri": nwc_uri,
                        "allowed_relay_hosts": sorted(self._allowed_relay_hosts),
                        "payment_hash": payment_hash,
                    }
                )
            )
        except ValidationError:
            raise NwcAdapterError(
                "protocol", "wallet helper returned an invalid response", retryable=False
            ) from None
        return NwcLookupResult(
            NwcLookupState(result.state),
            result.payment_hash,
            result.preimage,
            result.fees_paid_msats,
        )

    def mark_settled(self, payment_hash: str) -> None:
        raise NotImplementedError("mark_settled is only supported by mock NWC adapters")
