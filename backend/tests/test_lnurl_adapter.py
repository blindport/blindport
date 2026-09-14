"""Isolated Coinos LNURL-pay adapter tests with no live provider calls."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import UTC, datetime
from hashlib import sha256

import httpx
import pytest
from bolt11 import Bolt11, MilliSatoshi, Tag, TagChar, Tags, encode

from blindport.adapters.base import LightningInvoiceState
from blindport.adapters.lnurl import CoinosLnurlAdapter, CoinosLnurlError

_METADATA = json.dumps([["text/plain", "Blindport subscription"]], separators=(",", ":"))
_PAYMENT_HASH = "01" * 32
_PRIVATE_KEY = "03" * 32


@pytest.fixture
def signed_bolt11() -> Callable[..., str]:
    def create(
        *,
        metadata: str = _METADATA,
        amount_msats: int = 21_000,
        payment_hash: str = _PAYMENT_HASH,
        currency: str = "bc",
        expiry_seconds: int = 600,
        issued_at: int | None = None,
    ) -> str:
        invoice = Bolt11(
            currency=currency,
            date=int(time.time()) if issued_at is None else issued_at,
            amount_msat=MilliSatoshi(amount_msats),
            tags=Tags(
                [
                    Tag(TagChar.payment_hash, payment_hash),
                    Tag(TagChar.description_hash, sha256(metadata.encode("utf-8")).hexdigest()),
                    Tag(TagChar.payment_secret, "02" * 32),
                    Tag(TagChar.expire_time, expiry_seconds),
                    Tag(TagChar.min_final_cltv_expiry, 18),
                ]
            ),
        )
        return encode(invoice, private_key=_PRIVATE_KEY, strict=True)

    return create


def _discovery(
    callback: str = "https://coinos.io/api/lnurl/callback?token=first",
) -> dict[str, object]:
    return {
        "tag": "payRequest",
        "callback": callback,
        "minSendable": 1_000,
        "maxSendable": 100_000,
        "metadata": _METADATA,
    }


def _adapter(handler: Callable[[httpx.Request], httpx.Response]) -> CoinosLnurlAdapter:
    return CoinosLnurlAdapter(transport=httpx.MockTransport(handler))


def test_health_discovers_only_the_configured_coinos_address() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.method == "GET"
        assert request.url == "https://coinos.io/.well-known/lnurlp/blindport"
        return httpx.Response(200, json=_discovery())

    assert _adapter(handler).health() is True
    assert len(requests) == 1


def test_constructor_rejects_referrer_address_without_a_request() -> None:
    with pytest.raises(ValueError, match="coinos.io"):
        CoinosLnurlAdapter(address="merchant@elsewhere.org")


def test_create_invoice_appends_amount_and_binds_signed_bolt11(
    signed_bolt11: Callable[..., str],
) -> None:
    payment_request = signed_bolt11()
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(200, json=_discovery())
        assert request.url.path == "/api/lnurl/callback"
        assert list(request.url.params.multi_items()) == [("token", "first"), ("amount", "21000")]
        return httpx.Response(
            200,
            json={
                "pr": payment_request,
                "verify": "https://coinos.io/api/lnurl/verify?invoice=one",
            },
        )

    invoice = _adapter(handler).create_invoice(21)

    assert len(requests) == 2
    assert invoice.payment_request == payment_request
    assert invoice.payment_hash == _PAYMENT_HASH
    assert invoice.amount_sats == 21
    assert invoice.metadata == _METADATA
    assert invoice.verify_url == "https://coinos.io/api/lnurl/verify?invoice=one"
    assert invoice.expires_at.tzinfo is UTC
    assert invoice.expires_at > datetime.now(UTC)


@pytest.mark.parametrize(
    "invoice_kwargs",
    [
        {"amount_msats": 22_000},
        {"metadata": json.dumps([["text/plain", "other"]], separators=(",", ":"))},
        {"currency": "tb"},
        {"expiry_seconds": 1, "issued_at": int(time.time()) - 100},
    ],
)
def test_create_invoice_rejects_malformed_or_mismatched_bolt11(
    signed_bolt11: Callable[..., str], invoice_kwargs: dict[str, object]
) -> None:
    payment_request = signed_bolt11(**invoice_kwargs)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(200, json=_discovery())
        return httpx.Response(
            200,
            json={"pr": payment_request, "verify": "https://coinos.io/api/lnurl/verify"},
        )

    with pytest.raises(CoinosLnurlError) as exc_info:
        _adapter(handler).create_invoice(21)

    assert exc_info.value.code == "invalid_invoice"


def test_create_invoice_rejects_malformed_bolt11() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(200, json=_discovery())
        return httpx.Response(
            200,
            json={"pr": "not-a-bolt11", "verify": "https://coinos.io/api/lnurl/verify"},
        )

    with pytest.raises(CoinosLnurlError) as exc_info:
        _adapter(handler).create_invoice(21)

    assert exc_info.value.code == "invalid_invoice"


def test_create_invoice_accepts_long_provider_expiry(
    signed_bolt11: Callable[..., str],
) -> None:
    payment_request = signed_bolt11(expiry_seconds=31_536_000)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(200, json=_discovery())
        return httpx.Response(
            200,
            json={"pr": payment_request, "verify": "https://coinos.io/api/lnurl/verify"},
        )

    assert _adapter(handler).create_invoice(21).payment_request == payment_request


@pytest.mark.parametrize(
    "callback",
    [
        "https://evil.example/callback",
        "https://coinos.io.evil.example/callback",
        "https://user@coinos.io/callback",
        "https://coinos.io:8443/callback",
        "https://coinos.io/callback#fragment",
        "https://coinos.io/callback#",
        "https://@coinos.io/callback",
        "https://coinos.io\\@evil.example/callback",
    ],
)
def test_create_invoice_rejects_callback_ssrf_before_following(callback: str) -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=_discovery(callback))

    with pytest.raises(CoinosLnurlError, match="callback URL"):
        _adapter(handler).create_invoice(21)

    assert calls == 1


def test_create_invoice_rejects_untrusted_verify_url_before_returning() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if request.url.path.startswith("/.well-known/"):
            return httpx.Response(200, json=_discovery())
        return httpx.Response(
            200,
            json={"pr": "invalid-but-not-fetched", "verify": "https://evil.example/verify"},
        )

    with pytest.raises(CoinosLnurlError, match="verify URL"):
        _adapter(handler).create_invoice(21)

    assert calls == 2


def test_redirects_are_rejected_without_following() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://evil.example/"})

    assert _adapter(handler).health() is False
    assert len(calls) == 1


def test_response_body_is_stream_bounded() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"{" + (b" " * (64 * 1024)))

    with pytest.raises(CoinosLnurlError) as exc_info:
        _adapter(handler).create_invoice(21)

    assert exc_info.value.code == "response_too_large"


def test_invoice_state_requires_matching_invoice_and_settlement_proof() -> None:
    preimage = bytes(range(32))
    payment_hash = sha256(preimage).hexdigest()
    payment_request = "lnbc21n1stored"

    def settled_handler(request: httpx.Request) -> httpx.Response:
        assert request.url == "https://coinos.io/api/lnurl/verify?id=one"
        return httpx.Response(
            200,
            json={
                "status": "OK",
                "settled": True,
                "pr": payment_request,
                "preimage": preimage.hex(),
            },
        )

    assert (
        _adapter(settled_handler).invoice_state(
            payment_request=payment_request,
            payment_hash=payment_hash,
            verify_url="https://coinos.io/api/lnurl/verify?id=one",
        )
        == LightningInvoiceState.SETTLED
    )


def test_invoice_state_allows_only_null_preimage_when_unsettled() -> None:
    payment_request = "lnbc21n1stored"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"status": "OK", "settled": False, "pr": payment_request, "preimage": None},
        )

    assert (
        _adapter(handler).invoice_state(
            payment_request=payment_request,
            payment_hash="ab" * 32,
            verify_url="https://coinos.io/api/lnurl/verify",
        )
        == LightningInvoiceState.OPEN
    )


@pytest.mark.parametrize(
    "response",
    [
        {"status": "OK", "settled": 1, "pr": "lnbc21n1stored", "preimage": None},
        {"status": "OK", "settled": False, "pr": "other", "preimage": None},
        {"status": "OK", "settled": False, "pr": "lnbc21n1stored"},
        {"status": "OK", "settled": True, "pr": "lnbc21n1stored", "preimage": "00" * 32},
        {"status": "ERROR", "settled": False, "pr": "lnbc21n1stored", "preimage": None},
    ],
)
def test_invoice_state_rejects_invalid_provider_claims(response: dict[str, object]) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response)

    with pytest.raises(CoinosLnurlError) as exc_info:
        _adapter(handler).invoice_state(
            payment_request="lnbc21n1stored",
            payment_hash="ab" * 32,
            verify_url="https://coinos.io/api/lnurl/verify",
        )

    assert exc_info.value.code == "invalid_response"


def test_invoice_state_rejects_untrusted_verify_url_before_request() -> None:
    with pytest.raises(CoinosLnurlError, match="verify URL"):
        CoinosLnurlAdapter(transport=httpx.MockTransport(pytest.fail)).invoice_state(
            payment_request="lnbc21n1stored",
            payment_hash="ab" * 32,
            verify_url="https://169.254.169.254/verify",
        )
