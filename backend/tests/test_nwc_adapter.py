"""Strict bounded protocol tests for the production NWC subprocess adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from blindport.adapters.base import NwcAdapterError, NwcLookupState
from blindport.adapters.nwc import SubprocessNwcAdapter

_PUBKEY = "11" * 32
_SECRET = "22" * 32
_URI = f"nostr+walletconnect://{_PUBKEY}?relay=wss%3A%2F%2Frelay.example&secret={_SECRET}"


def _helper(tmp_path: Path, body: str) -> str:
    path = tmp_path / "fake-nwc-helper"
    path.write_text("#!/usr/bin/env python3\n" + body, encoding="ascii")
    path.chmod(0o700)
    return str(path)


def _adapter(executable: str, timeout: float = 2) -> SubprocessNwcAdapter:
    return SubprocessNwcAdapter(executable, timeout, ("relay.example",))


def test_subprocess_sends_secret_only_in_bounded_stdin_and_parses_strict_json(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        """import json, os, sys
request = json.load(sys.stdin)
assert request["nwc_uri"] not in " ".join(sys.argv)
assert request["nwc_uri"] not in json.dumps(dict(os.environ))
print(json.dumps({"version": 1, "ok": True, "result": {
    "state": "valid", "capabilities": ["pay_invoice", "lookup_invoice"],
    "encryptions": ["nip44_v2"]}}))
""",
    )
    adapter = _adapter(executable)

    result = adapter.validate_connection(_URI)

    assert set(result.capabilities) == {"pay_invoice", "lookup_invoice"}
    assert result.encryptions == ("nip44_v2",)


def test_subprocess_maps_safe_errors_without_private_detail(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        """import json
print(json.dumps({"version": 1, "ok": False, "error": {
    "code": "insufficient_balance", "message": "wallet balance is insufficient",
    "retryable": False}}))
""",
    )
    adapter = _adapter(executable)

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.pay_invoice(_URI, "private-invoice")

    assert exc_info.value.code == "insufficient_balance"
    assert exc_info.value.retryable is False
    assert "private" not in str(exc_info.value)


def test_subprocess_rejects_oversized_multiple_and_malformed_output(tmp_path) -> None:
    bodies = (
        "import sys\nsys.stdout.write('x' * 17000)\n",
        "print('{}{}')\n",
        "print('{not-json}')\n",
    )
    for index, body in enumerate(bodies):
        directory = tmp_path / str(index)
        directory.mkdir()
        executable = _helper(directory, body)
        adapter = _adapter(executable)
        with pytest.raises(NwcAdapterError) as exc_info:
            adapter.lookup_invoice(_URI, "11" * 32)
        assert exc_info.value.code == "protocol"


def test_subprocess_timeout_is_retryable(tmp_path) -> None:
    executable = _helper(tmp_path, "import time\ntime.sleep(2)\n")
    adapter = _adapter(executable, 0.05)

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.lookup_invoice(_URI, "11" * 32)

    assert exc_info.value.code == "timeout"
    assert exc_info.value.retryable is True


def test_subprocess_lookup_result_schema(tmp_path) -> None:
    payment_hash = "11" * 32
    executable = _helper(
        tmp_path,
        f"""import json
print(json.dumps({{"version": 1, "ok": True, "result": {{
    "state": "pending", "payment_hash": "{payment_hash}",
    "preimage": None, "fees_paid_msats": 3}}}}))
""",
    )

    result = _adapter(executable).lookup_invoice(_URI, payment_hash)

    assert result.state == NwcLookupState.PENDING
    assert result.payment_hash == payment_hash


def test_subprocess_rejects_non_allowlisted_relay_before_helper_execution(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")
    uri = f"nostr+walletconnect://{'11' * 32}?relay=wss%3A%2F%2Fevil.example&secret={'22' * 32}"
    adapter = SubprocessNwcAdapter(executable, 2, ("relay.getalby.com",))

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.validate_connection(uri)

    assert exc_info.value.code == "relay_not_allowed"
    assert exc_info.value.retryable is False


def test_subprocess_rejects_allowlisted_host_on_nonstandard_port(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")
    uri = _URI.replace("relay.example", "relay.example%3A8443")

    with pytest.raises(NwcAdapterError) as exc_info:
        _adapter(executable).validate_connection(uri)

    assert exc_info.value.code == "relay_not_allowed"


def test_subprocess_does_not_trust_helper_error_text_or_codes(tmp_path) -> None:
    leaking = _helper(
        tmp_path,
        f"""import json
print(json.dumps({{"version": 1, "ok": False, "error": {{
    "code": "internal", "message": "{_SECRET}", "retryable": True}}}}))
""",
    )

    with pytest.raises(NwcAdapterError) as exc_info:
        _adapter(leaking).pay_invoice(_URI, "private-invoice")

    assert str(exc_info.value) == "wallet operation failed"
    assert _SECRET not in str(exc_info.value)

    invalid_directory = tmp_path / "invalid-code"
    invalid_directory.mkdir()
    invalid_code = _helper(
        invalid_directory,
        """import json
print(json.dumps({"version": 1, "ok": False, "error": {
    "code": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "message": "safe", "retryable": True}}))
""",
    )
    with pytest.raises(NwcAdapterError) as invalid_info:
        _adapter(invalid_code).pay_invoice(_URI, "private-invoice")
    assert invalid_info.value.code == "protocol"
