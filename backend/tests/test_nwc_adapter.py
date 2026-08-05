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
assert request["allow_public_relays"] is False
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


def test_subprocess_public_relay_policy_is_rechecked_and_sent_to_helper(tmp_path) -> None:
    executable = _helper(
        tmp_path,
        """import json, sys
request = json.load(sys.stdin)
assert request["allowed_relay_hosts"] == []
assert request["allow_public_relays"] is True
print(json.dumps({"version": 1, "ok": True, "result": {
    "state": "valid", "capabilities": ["pay_invoice", "lookup_invoice"],
    "encryptions": ["nip44_v2"]}}))
""",
    )
    adapter = SubprocessNwcAdapter(
        executable,
        2,
        allow_public_relays=True,
        relay_resolver=lambda host: ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"),
    )

    result = adapter.validate_connection(_URI)

    assert result.encryptions == ("nip44_v2",)


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("169.254.169.254",),
        ("192.0.2.1",),
        ("224.0.0.1",),
        ("::1",),
        ("fc00::1",),
        ("ff0e::1",),
        ("64:ff9b::7f00:1",),
        ("93.184.216.34", "10.0.0.1"),
    ],
)
def test_subprocess_public_relay_policy_rejects_any_non_public_dns_answer(
    tmp_path, addresses
) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")
    adapter = SubprocessNwcAdapter(
        executable,
        2,
        allow_public_relays=True,
        relay_resolver=lambda host: addresses,
    )

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.validate_connection(_URI)

    assert exc_info.value.code == "relay_not_allowed"
    assert exc_info.value.retryable is False


def test_subprocess_public_relay_dns_failure_is_retryable(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")

    def unavailable(host: str) -> tuple[str, ...]:
        raise OSError("private DNS detail")

    adapter = SubprocessNwcAdapter(
        executable,
        2,
        allow_public_relays=True,
        relay_resolver=unavailable,
    )

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.validate_connection(_URI)

    assert exc_info.value.code == "transport"
    assert exc_info.value.retryable is True
    assert "private" not in str(exc_info.value)


def test_subprocess_public_relay_rejects_malformed_dns_name_without_detail(tmp_path) -> None:
    executable = _helper(tmp_path, "raise AssertionError('helper must not run')\n")

    def malformed(host: str) -> tuple[str, ...]:
        raise UnicodeError("private DNS detail")

    adapter = SubprocessNwcAdapter(
        executable,
        2,
        allow_public_relays=True,
        relay_resolver=malformed,
    )

    with pytest.raises(NwcAdapterError) as exc_info:
        adapter.validate_connection(_URI)

    assert exc_info.value.code == "relay_not_allowed"
    assert exc_info.value.retryable is False
    assert "private" not in str(exc_info.value)


def test_subprocess_requires_one_explicit_relay_policy(tmp_path) -> None:
    executable = _helper(tmp_path, "pass\n")

    with pytest.raises(ValueError, match="exactly one relay egress policy"):
        SubprocessNwcAdapter(executable, 2)
    with pytest.raises(ValueError, match="exactly one relay egress policy"):
        SubprocessNwcAdapter(
            executable,
            2,
            ("relay.example",),
            allow_public_relays=True,
        )


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
