"""Bounded subprocess adapter for the single-shot CLINK helper."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import time
from contextlib import suppress
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .base import (
    ClinkAdapter,
    ClinkAdapterError,
    ClinkPaymentState,
    ClinkPayResult,
    ClinkValidationResult,
)

_MAX_REQUEST_BYTES = 16_384
_MAX_RESPONSE_BYTES = 16_384
_MAX_NDEBIT_LENGTH = 4096
_MAX_INVOICE_LENGTH = 8192
_MAX_DESCRIPTION_LENGTH = 100


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class _SafeError(_StrictModel):
    code: Literal[
        "denied",
        "expired",
        "internal",
        "invalid_amount",
        "invalid_pointer",
        "invalid_request",
        "invalid_wallet_response",
        "rate_limited",
        "relay_not_allowed",
        "temporary_failure",
        "timeout",
        "transport",
    ]
    message: str = Field(min_length=1, max_length=200)
    retryable: bool
    wallet_rejection: bool

    @model_validator(mode="after")
    def validate_wallet_rejection(self) -> _SafeError:
        if self.wallet_rejection and (
            self.retryable
            or self.code
            not in {
                "denied",
                "expired",
                "invalid_amount",
                "invalid_request",
                "rate_limited",
                "temporary_failure",
            }
        ):
            raise ValueError("helper wallet rejection is invalid")
        return self


class _Envelope(_StrictModel):
    version: Literal[1]
    ok: bool
    result: dict[str, object] | None = None
    error: _SafeError | None = None

    @model_validator(mode="after")
    def validate_union(self) -> _Envelope:
        if self.ok != (self.result is not None) or self.ok == (self.error is not None):
            raise ValueError("helper response union is invalid")
        return self


class _Validation(_StrictModel):
    state: Literal["valid"]
    app_pubkey: str = Field(pattern=r"^[0-9a-f]{64}$")


class _Pay(_StrictModel):
    state: Literal["settled", "pending"]
    preimage: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_settlement_proof(self) -> _Pay:
        if (self.state == "settled") != (self.preimage is not None):
            raise ValueError("payment state and preimage are inconsistent")
        return self


_SAFE_ERROR_MESSAGES = {
    "denied": "payment request was denied",
    "expired": "payment request expired",
    "internal": "CLINK payment request failed",
    "invalid_amount": "payment amount was rejected",
    "invalid_pointer": "CLINK payment pointer is invalid",
    "invalid_request": "CLINK request is invalid",
    "invalid_wallet_response": "CLINK wallet returned an invalid response",
    "rate_limited": "payment request was rate limited",
    "relay_not_allowed": "CLINK relay host is not allowed",
    "temporary_failure": "payment request failed temporarily",
    "timeout": "CLINK payment request timed out",
    "transport": "CLINK payment transport is unavailable",
}


class SubprocessClinkAdapter(ClinkAdapter):
    """Run one policy-constrained CLINK operation per helper process."""

    def __init__(
        self,
        executable: str,
        helper_timeout_seconds: float,
        request_timeout_seconds: int,
        private_key: str,
        allowed_relay_hosts: tuple[str, ...] = (),
        *,
        allow_public_relays: bool = False,
    ) -> None:
        if not os.path.isabs(executable):
            raise ValueError("CLINK helper path must be absolute")
        if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
            raise ValueError("CLINK helper must be an executable regular file")
        if not isinstance(request_timeout_seconds, int) or isinstance(
            request_timeout_seconds, bool
        ):
            raise ValueError("CLINK request timeout must be an integer")
        if not 1 <= request_timeout_seconds <= 120:
            raise ValueError("CLINK request timeout must be within 1-120 seconds")
        if not 0 < helper_timeout_seconds <= 120:
            raise ValueError("CLINK helper timeout must be within 0-120 seconds")
        if helper_timeout_seconds < request_timeout_seconds + 1:
            raise ValueError(
                "CLINK helper timeout must exceed request timeout by at least 1 second"
            )
        if (
            not isinstance(private_key, str)
            or len(private_key) != 64
            or private_key.lower() != private_key
        ):
            raise ValueError("CLINK private key must be 64 lowercase hexadecimal characters")
        try:
            if len(bytes.fromhex(private_key)) != 32:
                raise ValueError
        except ValueError as error:
            raise ValueError(
                "CLINK private key must be 64 lowercase hexadecimal characters"
            ) from error
        if bool(allowed_relay_hosts) == allow_public_relays:
            raise ValueError("CLINK requires exactly one relay egress policy")
        self._executable = executable
        self._helper_timeout = helper_timeout_seconds
        self._request_timeout = request_timeout_seconds
        self._private_key = private_key
        self._allowed_relay_hosts = frozenset(host.lower() for host in allowed_relay_hosts)
        self._allow_public_relays = allow_public_relays

    @staticmethod
    def _invalid_request(message: str = "CLINK request is invalid") -> ClinkAdapterError:
        return ClinkAdapterError("invalid_request", message, retryable=False)

    def _validate_ndebit(self, ndebit: str) -> None:
        if (
            not isinstance(ndebit, str)
            or not ndebit.startswith("ndebit1")
            or len(ndebit) > _MAX_NDEBIT_LENGTH
        ):
            raise ClinkAdapterError(
                "invalid_pointer", _SAFE_ERROR_MESSAGES["invalid_pointer"], retryable=False
            )

    def _validate_payment_request(
        self,
        ndebit: str,
        invoice: str,
        amount_sats: int,
        description: str,
    ) -> None:
        self._validate_ndebit(ndebit)
        if not isinstance(invoice, str) or not invoice or len(invoice) > _MAX_INVOICE_LENGTH:
            raise self._invalid_request()
        if (
            not isinstance(description, str)
            or not description
            or len(description) > _MAX_DESCRIPTION_LENGTH
        ):
            raise self._invalid_request()
        if (
            not isinstance(amount_sats, int)
            or isinstance(amount_sats, bool)
            or not 0 < amount_sats <= 9_007_199_254_740_991
        ):
            raise self._invalid_request()

    def _invoke(self, request: dict[str, object]) -> dict[str, object]:
        encoded = json.dumps(request, separators=(",", ":")).encode("utf-8")
        if len(encoded) > _MAX_REQUEST_BYTES:
            raise self._invalid_request("CLINK request is too large")
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
            raise ClinkAdapterError(
                "internal", _SAFE_ERROR_MESSAGES["internal"], retryable=True
            ) from error

        output = bytearray()
        input_offset = 0
        deadline = time.monotonic() + self._helper_timeout
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
            if process.poll() is None:
                process.kill()
            process.wait()
            raise ClinkAdapterError(
                "timeout", _SAFE_ERROR_MESSAGES["timeout"], retryable=True
            ) from error
        except Exception as error:
            if process.poll() is None:
                process.kill()
            process.wait()
            raise ClinkAdapterError(
                "invalid_wallet_response",
                _SAFE_ERROR_MESSAGES["invalid_wallet_response"],
                retryable=False,
            ) from error
        finally:
            if process.stdin is not None:
                with suppress(OSError):
                    process.stdin.close()
            if process.stdout is not None:
                with suppress(OSError):
                    process.stdout.close()

        if process.returncode != 0:
            raise ClinkAdapterError("internal", _SAFE_ERROR_MESSAGES["internal"], retryable=True)
        try:
            text = output.decode("utf-8")
            decoder = json.JSONDecoder()
            payload, end = decoder.raw_decode(text)
            if text[end:].strip():
                raise ValueError("multiple helper responses")
            envelope = _Envelope.model_validate(payload)
        except (UnicodeDecodeError, ValueError, ValidationError):
            raise ClinkAdapterError(
                "invalid_wallet_response",
                _SAFE_ERROR_MESSAGES["invalid_wallet_response"],
                retryable=False,
            ) from None
        if not envelope.ok:
            assert envelope.error is not None
            code = envelope.error.code
            raise ClinkAdapterError(
                code,
                _SAFE_ERROR_MESSAGES[code],
                retryable=envelope.error.retryable,
                wallet_rejection=envelope.error.wallet_rejection,
            )
        assert envelope.result is not None
        return envelope.result

    def _common_request(self, ndebit: str, operation: str) -> dict[str, object]:
        return {
            "version": 1,
            "operation": operation,
            "ndebit": ndebit,
            "private_key": self._private_key,
            "allowed_relay_hosts": sorted(self._allowed_relay_hosts),
            "allow_public_relays": self._allow_public_relays,
        }

    def validate_connection(self, ndebit: str) -> ClinkValidationResult:
        self._validate_ndebit(ndebit)
        try:
            result = _Validation.model_validate(
                self._invoke(self._common_request(ndebit, "validate"))
            )
        except ValidationError:
            raise ClinkAdapterError(
                "invalid_wallet_response",
                _SAFE_ERROR_MESSAGES["invalid_wallet_response"],
                retryable=False,
            ) from None
        return ClinkValidationResult(result.app_pubkey)

    def pay_invoice(
        self,
        ndebit: str,
        invoice: str,
        amount_sats: int,
        description: str,
    ) -> ClinkPayResult:
        self._validate_payment_request(ndebit, invoice, amount_sats, description)
        request = self._common_request(ndebit, "pay_invoice")
        request.update(
            {
                "invoice": invoice,
                "amount_sats": amount_sats,
                "description": description,
                "timeout_seconds": self._request_timeout,
            }
        )
        try:
            result = _Pay.model_validate(self._invoke(request))
        except ValidationError:
            raise ClinkAdapterError(
                "invalid_wallet_response",
                _SAFE_ERROR_MESSAGES["invalid_wallet_response"],
                retryable=False,
            ) from None
        return ClinkPayResult(ClinkPaymentState(result.state), result.preimage)
