"""Unit tests for the production LND REST Lightning adapter."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from blindport.adapters import lnd_rest
from blindport.adapters.lnd_rest import LndRestLightningAdapter
from blindport.adapters.mock import MockLightningAdapter


@pytest.fixture
def lnd_files(tmp_path: Path) -> tuple[Path, Path]:
    cert = tmp_path / "tls.cert"
    cert.write_text("test certificate", encoding="ascii")
    macaroon = tmp_path / "admin.macaroon"
    macaroon.write_bytes(b"\x00\xff\x10")
    return cert, macaroon


def _adapter(
    lnd_files: tuple[Path, Path],
    handler: Any,
    *,
    expiry: int = 900,
    timeout: float = 4.5,
) -> LndRestLightningAdapter:
    cert, macaroon = lnd_files
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return LndRestLightningAdapter(
        rest_url="https://lnd.example:8080",
        cert_path=str(cert),
        macaroon_path=str(macaroon),
        invoice_expiry_seconds=expiry,
        request_timeout_seconds=timeout,
        client=client,
    )


def test_create_invoice_uses_official_request_and_decodes_hash(
    lnd_files: tuple[Path, Path],
) -> None:
    raw_hash = bytes(range(32))

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url == "https://lnd.example:8080/v1/invoices"
        assert request.headers["Grpc-Metadata-macaroon"] == "00ff10"
        assert request.extensions["timeout"] == {
            "connect": 4.5,
            "read": 4.5,
            "write": 4.5,
            "pool": 4.5,
        }
        assert request.read()
        assert json.loads(request.content) == {
            "value": "5000",
            "memo": "Blindport subscription",
            "expiry": "900",
        }
        return httpx.Response(
            200,
            json={
                "payment_request": "lnbc5000n1production",
                "r_hash": base64.b64encode(raw_hash).decode("ascii"),
            },
        )

    invoice = _adapter(lnd_files, handler).create_invoice(5000, "Blindport subscription")

    assert invoice.payment_request == "lnbc5000n1production"
    assert invoice.payment_hash == raw_hash.hex()
    assert invoice.amount_sats == 5000
    assert invoice.expires_in_seconds == 900


def test_health_uses_authenticated_official_getinfo_request(
    lnd_files: tuple[Path, Path],
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url == "https://lnd.example:8080/v1/getinfo"
        assert request.headers["Grpc-Metadata-macaroon"] == "00ff10"
        assert request.extensions["timeout"] == {
            "connect": 4.5,
            "read": 4.5,
            "write": 4.5,
            "pool": 4.5,
        }
        return httpx.Response(200, json={"identity_pubkey": "02abc"})

    assert _adapter(lnd_files, handler).health() is True


def test_health_propagates_lnd_http_error(lnd_files: tuple[Path, Path]) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(503, json={"error": "offline"}))

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        adapter.health()

    assert exc_info.value.response.status_code == 503


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json=[]),
    ],
)
def test_health_rejects_malformed_response(
    lnd_files: tuple[Path, Path], response: httpx.Response
) -> None:
    adapter = _adapter(lnd_files, lambda request: response)

    with pytest.raises(RuntimeError, match="malformed JSON|non-object"):
        adapter.health()


def test_health_requires_lnd_identity(lnd_files: tuple[Path, Path]) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(200, json={}))

    with pytest.raises(RuntimeError, match="identity_pubkey"):
        adapter.health()


def test_create_invoice_bounds_configured_expiry_per_invoice(
    lnd_files: tuple[Path, Path],
) -> None:
    raw_hash = bytes(range(32))

    def handler(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["expiry"] == "120"
        return httpx.Response(
            200,
            json={
                "payment_request": "lnbc5000n1bounded",
                "r_hash": base64.b64encode(raw_hash).decode("ascii"),
            },
        )

    invoice = _adapter(lnd_files, handler, expiry=900).create_invoice(
        5000,
        "bounded",
        expiry_seconds=120,
    )

    assert invoice.expires_in_seconds == 120


def test_recoverable_invoice_uses_preimage_and_lookup_before_add(
    lnd_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    preimage = bytes(range(32))
    raw_hash = hashlib.sha256(preimage).digest()
    calls: list[str] = []
    clock = iter((100.0, 100.0))
    monkeypatch.setattr(lnd_rest, "monotonic", lambda: next(clock))

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.method)
        if request.method == "GET":
            assert request.url.params["payment_hash"] == base64.b64encode(raw_hash).decode()
            return httpx.Response(404, json={"code": 5, "message": "unable to locate invoice"})
        assert json.loads(request.content) == {
            "value": "5000",
            "memo": "durable payment",
            "expiry": "120",
            "r_preimage": base64.b64encode(preimage).decode(),
        }
        return httpx.Response(
            200,
            json={
                "payment_request": "lnbc5000n1durable",
                "r_hash": base64.b64encode(raw_hash).decode(),
            },
        )

    invoice = _adapter(lnd_files, handler).create_or_lookup_invoice(
        5000, "durable payment", preimage, expiry_seconds=120
    )

    assert calls == ["GET", "POST"]
    assert invoice.payment_hash == raw_hash.hex()
    assert invoice.payment_request == "lnbc5000n1durable"


def test_recoverable_invoice_expiry_includes_preflight_lookup_time(
    lnd_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    preimage = b"e" * 32
    raw_hash = hashlib.sha256(preimage).digest()
    clock = iter((100.0, 110.25))
    monkeypatch.setattr(lnd_rest, "monotonic", lambda: next(clock))

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(404, json={"code": 5})
        assert json.loads(request.content)["expiry"] == "109"
        return httpx.Response(
            200,
            json={
                "payment_request": "lnbc42n1lookupbounded",
                "r_hash": base64.b64encode(raw_hash).decode(),
            },
        )

    invoice = _adapter(lnd_files, handler).create_or_lookup_invoice(
        42, "lookup bounded", preimage, expiry_seconds=120
    )

    assert invoice.expires_in_seconds == 109


def test_recoverable_invoice_is_not_added_after_expiry_during_lookup(
    lnd_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    methods: list[str] = []
    clock = iter((100.0, 220.0))
    monkeypatch.setattr(lnd_rest, "monotonic", lambda: next(clock))

    def handler(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(404, json={"code": 5})

    with pytest.raises(TimeoutError, match="expiry elapsed"):
        _adapter(lnd_files, handler).create_or_lookup_invoice(
            42, "elapsed", b"e" * 32, expiry_seconds=120
        )

    assert methods == ["GET"]


def test_recoverable_invoice_recovers_after_ambiguous_create_failure(
    lnd_files: tuple[Path, Path],
) -> None:
    preimage = b"p" * 32
    raw_hash = hashlib.sha256(preimage).digest()
    lookup_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal lookup_calls
        if request.method == "POST":
            return httpx.Response(503, json={"error": "proxy lost upstream response"})
        lookup_calls += 1
        if lookup_calls == 1:
            return httpx.Response(404, json={"code": 5})
        return httpx.Response(
            200,
            json={
                "payment_request": "lnbc42n1recovered",
                "r_hash": base64.b64encode(raw_hash).decode(),
                "memo": "ambiguous",
                "value": "42",
                "creation_date": str(int(time.time())),
                "expiry": "300",
                "state": "OPEN",
            },
        )

    invoice = _adapter(lnd_files, handler).create_or_lookup_invoice(
        42, "ambiguous", preimage, expiry_seconds=300
    )

    assert lookup_calls == 2
    assert invoice.payment_request == "lnbc42n1recovered"
    assert invoice.payment_hash == raw_hash.hex()
    assert 298 <= invoice.expires_in_seconds <= 299


@pytest.mark.parametrize(
    "override,error",
    [
        ({"memo": "wrong"}, "memo"),
        ({"value": "43"}, "amount"),
        ({"r_hash": base64.b64encode(b"x" * 32).decode()}, "payment hash"),
    ],
)
def test_recoverable_lookup_rejects_conflicting_invoice(
    lnd_files: tuple[Path, Path], override: dict[str, str], error: str
) -> None:
    preimage = b"q" * 32
    raw_hash = hashlib.sha256(preimage).digest()
    payload = {
        "payment_request": "lnbc42n1existing",
        "r_hash": base64.b64encode(raw_hash).decode(),
        "memo": "expected",
        "value": "42",
        "creation_date": str(int(time.time())),
        "expiry": "300",
        "state": "OPEN",
    }
    payload.update(override)
    adapter = _adapter(lnd_files, lambda request: httpx.Response(200, json=payload))

    with pytest.raises(RuntimeError, match=error):
        adapter.create_or_lookup_invoice(42, "expected", preimage, expiry_seconds=300)


@pytest.mark.parametrize("expiry", [0, -1, True])
def test_create_invoice_rejects_invalid_per_invoice_expiry(
    lnd_files: tuple[Path, Path], expiry: Any
) -> None:
    adapter = _adapter(lnd_files, lambda request: pytest.fail("LND should not be called"))

    with pytest.raises(ValueError, match="positive integer"):
        adapter.create_invoice(21, "memo", expiry_seconds=expiry)


def test_mock_invoice_honors_and_validates_per_invoice_expiry() -> None:
    adapter = MockLightningAdapter()

    assert adapter.create_invoice(21, "memo", expiry_seconds=120).expires_in_seconds == 120
    assert adapter.create_invoice(21, "memo").expires_in_seconds == 600
    with pytest.raises(ValueError, match="positive integer"):
        adapter.create_invoice(21, "memo", expiry_seconds=True)


def test_lookup_encodes_canonical_hash_and_recognizes_settled(
    lnd_files: tuple[Path, Path],
) -> None:
    raw_hash = bytes(reversed(range(32)))

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v2/invoices/lookup"
        assert request.url.params["payment_hash"] == base64.b64encode(raw_hash).decode("ascii")
        assert request.headers["Grpc-Metadata-macaroon"] == "00ff10"
        return httpx.Response(200, json={"state": "SETTLED"})

    assert _adapter(lnd_files, handler).is_invoice_paid(raw_hash.hex()) is True


@pytest.mark.parametrize("state", ["OPEN", "ACCEPTED", "CANCELED"])
def test_lookup_recognizes_unsettled_states(lnd_files: tuple[Path, Path], state: str) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(200, json={"state": state}))

    assert adapter.is_invoice_paid("ab" * 32) is False


@pytest.mark.parametrize(
    "payload,error",
    [
        ({"r_hash": base64.b64encode(b"a" * 32).decode("ascii")}, "payment_request"),
        ({"payment_request": "lnbc1test"}, "r_hash"),
        ({"payment_request": "lnbc1test", "r_hash": "not base64"}, "invalid r_hash"),
        (
            {"payment_request": "lnbc1test", "r_hash": base64.b64encode(b"short").decode()},
            "32 bytes",
        ),
    ],
)
def test_create_invoice_rejects_malformed_response(
    lnd_files: tuple[Path, Path], payload: dict[str, Any], error: str
) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(200, json=payload))

    with pytest.raises(RuntimeError, match=error):
        adapter.create_invoice(21, "memo")


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"not-json"),
        httpx.Response(200, json=[]),
    ],
)
def test_create_invoice_rejects_invalid_json_shape(
    lnd_files: tuple[Path, Path], response: httpx.Response
) -> None:
    adapter = _adapter(lnd_files, lambda request: response)

    with pytest.raises(RuntimeError, match="malformed JSON|non-object"):
        adapter.create_invoice(21, "memo")


@pytest.mark.parametrize("payload", [{}, {"state": "UNKNOWN"}, {"state": 1}])
def test_lookup_rejects_malformed_state(
    lnd_files: tuple[Path, Path], payload: dict[str, Any]
) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(200, json=payload))

    with pytest.raises(RuntimeError, match="invalid state"):
        adapter.is_invoice_paid("ab" * 32)


@pytest.mark.parametrize("operation", ["create", "lookup"])
def test_lnd_http_errors_are_propagated(lnd_files: tuple[Path, Path], operation: str) -> None:
    adapter = _adapter(lnd_files, lambda request: httpx.Response(503, json={"error": "offline"}))

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        if operation == "create":
            adapter.create_invoice(21, "memo")
        else:
            adapter.is_invoice_paid("ab" * 32)
    assert exc_info.value.response.status_code == 503


@pytest.mark.parametrize("payment_hash", ["bad", "AB" * 32, ("ab" * 31) + " "])
def test_lookup_rejects_noncanonical_payment_hash(
    lnd_files: tuple[Path, Path], payment_hash: str
) -> None:
    adapter = _adapter(lnd_files, lambda request: pytest.fail("LND should not be called"))

    with pytest.raises(ValueError, match="lowercase 32-byte hex"):
        adapter.is_invoice_paid(payment_hash)


def test_mark_paid_is_unsupported(lnd_files: tuple[Path, Path]) -> None:
    adapter = _adapter(lnd_files, lambda request: pytest.fail("LND should not be called"))

    with pytest.raises(NotImplementedError, match="mock Lightning adapters"):
        adapter.mark_paid("ab" * 32)


@pytest.mark.parametrize(
    "overrides,error",
    [
        ({"rest_url": "http://lnd.example"}, "absolute https URL"),
        ({"rest_url": "https://lnd.example?bad=1"}, "query string or fragment"),
        ({"cert_path": "/missing/tls.cert"}, "LND_CERT_PATH"),
        ({"macaroon_path": "/missing/admin.macaroon"}, "LND_MACAROON_PATH"),
        ({"invoice_expiry_seconds": 0}, "LND_INVOICE_EXPIRY_SECONDS"),
        ({"request_timeout_seconds": 0}, "LND_REQUEST_TIMEOUT_SECONDS"),
    ],
)
def test_configuration_is_validated_when_adapter_is_created(
    lnd_files: tuple[Path, Path], overrides: dict[str, Any], error: str
) -> None:
    cert, macaroon = lnd_files
    kwargs: dict[str, Any] = {
        "rest_url": "https://lnd.example",
        "cert_path": str(cert),
        "macaroon_path": str(macaroon),
        "invoice_expiry_seconds": 600,
        "request_timeout_seconds": 10.0,
        "client": httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200))),
    }
    kwargs.update(overrides)

    with pytest.raises(ValueError, match=error):
        LndRestLightningAdapter(**kwargs)


def test_configured_cert_is_used_for_tls_verification(
    lnd_files: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    cert, macaroon = lnd_files
    captured: dict[str, Any] = {}
    tls_context = object()

    def fake_create_default_context(*, cafile: str) -> object:
        captured["cafile"] = cafile
        return tls_context

    def fake_client(**kwargs: Any) -> object:
        captured["verify"] = kwargs["verify"]
        return object()

    monkeypatch.setattr(
        "blindport.adapters.lnd_rest.ssl.create_default_context", fake_create_default_context
    )
    monkeypatch.setattr(httpx, "Client", fake_client)
    LndRestLightningAdapter(
        rest_url="https://lnd.example",
        cert_path=str(cert),
        macaroon_path=str(macaroon),
    )

    assert captured == {"cafile": str(cert), "verify": tls_context}


def test_factory_wires_lnd_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from blindport.adapters import factory

    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_adapter(**kwargs: Any) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(factory.settings, "PAYMENT_LIGHTNING_ADAPTER", "lnd")
    monkeypatch.setattr(factory.settings, "LND_REST_URL", "https://lnd.example:8080")
    monkeypatch.setattr(factory.settings, "LND_CERT_PATH", "/lnd/tls.cert")
    monkeypatch.setattr(factory.settings, "LND_MACAROON_PATH", "/lnd/admin.macaroon")
    monkeypatch.setattr(factory.settings, "LND_INVOICE_EXPIRY_SECONDS", 720)
    monkeypatch.setattr(factory.settings, "STABLECOIN_PAYMENTS_ENABLED", False)
    monkeypatch.setattr(factory.settings, "LND_REQUEST_TIMEOUT_SECONDS", 12.5)
    monkeypatch.setattr(factory, "LndRestLightningAdapter", fake_adapter)
    factory.reset_adapters_for_tests()

    assert factory.get_lightning_adapter() is sentinel
    assert captured == {
        "rest_url": "https://lnd.example:8080",
        "cert_path": "/lnd/tls.cert",
        "macaroon_path": "/lnd/admin.macaroon",
        "invoice_expiry_seconds": 720,
        "request_timeout_seconds": 12.5,
    }
    factory.reset_adapters_for_tests()


def test_factory_allows_longer_stablecoin_invoice_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from blindport.adapters import factory

    captured: dict[str, Any] = {}
    sentinel = object()

    def fake_adapter(**kwargs: Any) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(factory.settings, "PAYMENT_LIGHTNING_ADAPTER", "lnd")
    monkeypatch.setattr(factory.settings, "LND_REST_URL", "https://lnd.example:8080")
    monkeypatch.setattr(factory.settings, "LND_CERT_PATH", "/lnd/tls.cert")
    monkeypatch.setattr(factory.settings, "LND_MACAROON_PATH", "/lnd/admin.macaroon")
    monkeypatch.setattr(factory.settings, "LND_INVOICE_EXPIRY_SECONDS", 600)
    monkeypatch.setattr(factory.settings, "STABLECOIN_PAYMENTS_ENABLED", True)
    monkeypatch.setattr(factory.settings, "STABLECOIN_SWAP_INVOICE_EXPIRY_SECONDS", 1200)
    monkeypatch.setattr(factory, "LndRestLightningAdapter", fake_adapter)
    factory.reset_adapters_for_tests()

    assert factory.get_lightning_adapter() is sentinel
    assert captured["invoice_expiry_seconds"] == 1200
    factory.reset_adapters_for_tests()
