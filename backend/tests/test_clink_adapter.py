"""Strict bounded protocol tests for the production CLINK subprocess adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from blindport.adapters.base import ClinkAdapterError, ClinkPaymentState
from blindport.adapters.clink import SubprocessClinkAdapter
from blindport.adapters.mock import MockClinkAdapter

_PRIVATE_KEY = "22" * 32
_NDEBIT = "ndebit1testpointer"


def _helper(tmp_path: Path, body: str) -> str:
    path = tmp_path / "fake-clink-helper"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="ascii")
    path.chmod(0o700)
    return str(path)


def _adapter(
    executable: str,
    *,
    helper_timeout: float = 2,
    request_timeout: int = 1,
    allow_public_relays: bool = False,
) -> SubprocessClinkAdapter:
    return SubprocessClinkAdapter(
        executable,
        helper_timeout,
        request_timeout,
        _PRIVATE_KEY,
        () if allow_public_relays else ("relay.example",),
        allow_public_relays=allow_public_relays,
    )


def test_subprocess_sends_private_key_only_in_bounded_stdin_and_parses_validation(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        """import json, os, sys
request = json.load(sys.stdin)
assert request["private_key"] not in " ".join(sys.argv)
assert request["private_key"] not in json.dumps(dict(os.environ))
assert request == {
    "version": 1, "operation": "validate", "ndebit": "ndebit1testpointer",
    "private_key": "22" * 32, "allowed_relay_hosts": ["relay.example"],
    "allow_public_relays": False,
}
print(json.dumps({"version": 1, "ok": True, "result": {
    "state": "valid", "app_pubkey": "11" * 32}}))
""",
    )

    result = _adapter(executable).validate_connection(_NDEBIT)

    assert result.app_pubkey == "11" * 32


def test_subprocess_forwards_public_relay_policy_and_request_timeout(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        """import json, sys
request = json.load(sys.stdin)
assert request["allowed_relay_hosts"] == []
assert request["allow_public_relays"] is True
assert request["timeout_seconds"] == 1
assert request["amount_sats"] == 123
assert request["description"] == "service"
print(json.dumps({"version": 1, "ok": True, "result": {
    "state": "settled", "preimage": "33" * 32}}))
""",
    )

    result = _adapter(executable, allow_public_relays=True).pay_invoice(
        _NDEBIT, "lnbc1invoice", 123, "service"
    )

    assert result.state == ClinkPaymentState.SETTLED
    assert result.preimage == "33" * 32


def test_subprocess_rejects_invalid_pointer_and_relay_policy_before_helper(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")
    adapter = _adapter(executable)

    with pytest.raises(ClinkAdapterError) as exc_info:
        adapter.validate_connection("invalid-pointer")

    assert exc_info.value.code == "invalid_pointer"
    with pytest.raises(ValueError, match="exactly one relay egress policy"):
        SubprocessClinkAdapter(executable, 2, 1, _PRIVATE_KEY)
    with pytest.raises(ValueError, match="exactly one relay egress policy"):
        SubprocessClinkAdapter(
            executable,
            2,
            1,
            _PRIVATE_KEY,
            ("relay.example",),
            allow_public_relays=True,
        )


@pytest.mark.parametrize(
    "result",
    [
        {"state": "settled", "preimage": None},
        {"state": "pending", "preimage": "33" * 32},
        {"state": "settled", "preimage": "33" * 31},
        {"state": "failed", "preimage": None},
    ],
)
def test_subprocess_rejects_invalid_payment_state_and_preimage(tmp_path, result) -> None:
    executable = _helper(
        tmp_path,
        f"import json\nprint(json.dumps({{'version': 1, 'ok': True, 'result': {result!r}}}))\n",
    )

    with pytest.raises(ClinkAdapterError) as exc_info:
        _adapter(executable).pay_invoice(_NDEBIT, "lnbc1invoice", 1, "service")

    assert exc_info.value.code == "invalid_wallet_response"


def test_subprocess_sanitizes_helper_errors_and_enforces_retry_semantics(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        f"""import json
print(json.dumps({{"version": 1, "ok": False, "error": {{
    "code": "denied", "message": "{_PRIVATE_KEY}", "retryable": False,
    "wallet_rejection": True}}}}))
""",
    )

    with pytest.raises(ClinkAdapterError) as exc_info:
        _adapter(executable).pay_invoice(_NDEBIT, "private-invoice", 1, "service")

    assert exc_info.value.code == "denied"
    assert exc_info.value.retryable is False
    assert exc_info.value.wallet_rejection is True
    assert str(exc_info.value) == "payment request was denied"
    assert _PRIVATE_KEY not in str(exc_info.value)


@pytest.mark.parametrize(
    "body",
    [
        "import sys\nsys.stdout.write('x' * 17000)\n",
        "print('{}{}')\n",
        "print('{not-json}')\n",
        'print(\'{"version":1,"ok":true,"result":{}}\')\n',
    ],
)
def test_subprocess_rejects_malformed_or_oversized_output(tmp_path, body: str) -> None:
    executable = _helper(tmp_path, body)

    with pytest.raises(ClinkAdapterError) as exc_info:
        _adapter(executable).validate_connection(_NDEBIT)

    assert exc_info.value.code == "invalid_wallet_response"


def test_subprocess_timeout_is_retryable(tmp_path) -> None:
    executable = _helper(tmp_path, "import time\ntime.sleep(3)\n")

    with pytest.raises(ClinkAdapterError) as exc_info:
        _adapter(executable).validate_connection(_NDEBIT)

    assert exc_info.value.code == "timeout"
    assert exc_info.value.retryable is True


def test_subprocess_validates_constructor_and_request_bounds(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")

    with pytest.raises(ValueError, match="private key"):
        SubprocessClinkAdapter(executable, 2, 1, "A" * 64, ("relay.example",))
    with pytest.raises(ValueError, match="helper timeout"):
        SubprocessClinkAdapter(executable, 1, 1, _PRIVATE_KEY, ("relay.example",))
    with pytest.raises(ClinkAdapterError) as exc_info:
        _adapter(executable).pay_invoice(_NDEBIT, "x" * 8193, 1, "service")
    assert exc_info.value.code == "invalid_request"


def test_mock_clink_adapter_supports_deterministic_validation_and_settlement() -> None:
    settled: list[str] = []
    adapter = MockClinkAdapter(auto_settle=True, settle_callback=settled.append)

    first = adapter.validate_connection("test-pointer")
    second = adapter.validate_connection("another-test-pointer")
    payment = adapter.pay_invoice("test-pointer", "lnbc1invoice", 1, "service")
    adapter.bind_payment_hash("lnbc1invoice", "44" * 32)

    assert first == second
    assert len(first.app_pubkey) == 64
    assert payment.state == ClinkPaymentState.SETTLED
    assert payment.preimage is not None
    assert settled == ["44" * 32]
