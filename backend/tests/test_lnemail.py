"""Strict and bounded LNemail adapter behavior."""

from __future__ import annotations

import json

import httpx
import pytest

from blindport.adapters.lnemail import (
    LnemailAdapter,
    LnemailConfigurationError,
    LnemailHTTPError,
    LnemailProtocolError,
    LnemailTransportError,
)

_HASH = "ab" * 32


def _adapter(handler, *, token: str = "secret-token") -> LnemailAdapter:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return LnemailAdapter("https://mail.example", token, client=client)


def test_create_invoice_uses_exact_origin_and_returns_sanitized_result() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://mail.example/api/v1/email/send")
        assert request.headers["Authorization"] == "Bearer secret-token"
        assert json.loads(request.content) == {
            "recipient": "person@example.com",
            "subject": "Expiry notice",
            "body": "Renew soon",
        }
        return httpx.Response(
            202,
            json={
                "payment_request": "lnbc1u1invoice",
                "payment_hash": _HASH,
                "price_sats": 100,
                "sender_email": "blindport@lnemail.net",
                "recipient": "person@example.com",
                "subject": "Expiry notice",
                "provider": "nwc-1",
            },
        )

    invoice = _adapter(handler).create_send_invoice(
        "person@example.com", "Expiry notice", "Renew soon"
    )

    assert invoice.payment_request == "lnbc1u1invoice"
    assert invoice.payment_hash == _HASH
    assert not hasattr(invoice, "recipient")


def test_status_contract_is_strict_and_drops_provider_content() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL(f"https://mail.example/api/v1/email/send/status/{_HASH}")
        return httpx.Response(
            200,
            json={
                "payment_status": "paid",
                "delivery_status": "sent",
                "delivery_error": None,
                "sender_email": "blindport@lnemail.net",
                "recipient": "person@example.com",
                "subject": "Expiry notice",
                "sent_at": "2026-08-02T12:00:00Z",
                "retry_count": 1,
            },
        )

    status = _adapter(handler).send_status(_HASH)

    assert (status.payment_status, status.delivery_status, status.retry_count) == (
        "paid",
        "sent",
        1,
    )
    assert not hasattr(status, "recipient")


def test_create_invoice_rejects_price_that_does_not_match_bolt11_amount() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202,
            json={
                "payment_request": "lnbc2u1invoice",
                "payment_hash": _HASH,
                "price_sats": 100,
                "sender_email": "blindport@lnemail.net",
                "recipient": "person@example.com",
                "subject": "Expiry notice",
            },
        )

    with pytest.raises(LnemailProtocolError) as exc_info:
        _adapter(handler).create_send_invoice("person@example.com", "Expiry notice", "Renew soon")
    assert exc_info.value.code == "invoice_amount_mismatch"


@pytest.mark.parametrize(
    "url",
    [
        "http://mail.example",
        "https://mail.example:8443",
        "https://user@mail.example",
        "https://mail.example/api",
        "https://mail.example?next=https://internal.example",
        "https://mail.example#fragment",
    ],
)
def test_base_url_must_be_an_exact_https_origin(url: str) -> None:
    with pytest.raises(LnemailConfigurationError):
        LnemailAdapter(url, "token")


def test_redirect_is_not_followed_and_error_does_not_leak_secrets() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            307,
            headers={"Location": "https://internal.example/private"},
            content=b"person@example.com secret-token private response",
        )

    with pytest.raises(LnemailHTTPError) as exc_info:
        _adapter(handler).create_send_invoice("person@example.com", "Expiry notice", "Renew soon")

    assert calls == 1
    assert "person@example.com" not in str(exc_info.value)
    assert "secret-token" not in str(exc_info.value)
    assert "private response" not in str(exc_info.value)


def test_response_and_request_sizes_are_bounded() -> None:
    adapter = _adapter(lambda request: httpx.Response(200, content=b"x" * 16_385))
    with pytest.raises(LnemailProtocolError, match="too large"):
        adapter.send_status(_HASH)

    with pytest.raises(LnemailProtocolError, match="request is too large"):
        adapter.create_send_invoice("person@example.com", "Expiry", "x" * 6_000 + "\u2603" * 6_000)


def test_transport_error_has_no_request_cause_or_sensitive_values() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private response", request=request)

    with pytest.raises(LnemailTransportError) as exc_info:
        _adapter(handler).create_send_invoice("person@example.com", "Expiry notice", "Renew soon")

    assert exc_info.value.__cause__ is None
    assert "person@example.com" not in str(exc_info.value)
    assert "secret-token" not in str(exc_info.value)
