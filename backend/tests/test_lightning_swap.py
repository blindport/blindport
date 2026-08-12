"""Strict protocol tests for the Lightning Swap provider adapter."""

from __future__ import annotations

import hashlib
import hmac
from decimal import Decimal

import httpx
import pytest

from blindport.services.lightning_swap import (
    LightningSwapClient,
    LightningSwapError,
    LightningSwapRate,
    fetch_minimum_payout_sats,
    minimum_payout_sats,
    parse_rates_xml,
)

_ORIGIN = "https://swap.example"
_KEY = "public-api-key"
_SECRET = "private-api-secret"
_INVOICE = "lnbc1privateinvoice"


def _order_response(*, target_amount: str = "0.00001234", message: str = "") -> dict[str, object]:
    return {
        "code": 0,
        "msg": message,
        "data": {
            "token": "checkout-token-123",
            "id": "ORDER123",
            "status": "NEW",
            "time": {"expiration": 1_800_000_000},
            "from": {
                "code": "USDCSOL",
                "network": "SOL",
                "amount": "4.25",
                "address": "deposit-address",
                "tag": "",
                "reqConfirmations": 1,
            },
            "to": {"code": "BTCLN", "amount": target_amount, "address": _INVOICE},
        },
    }


def test_create_order_signs_exact_compact_body_and_returns_validated_order() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert str(request.url) == f"{_ORIGIN}/api/v2/create"
        expected = (
            b'{"fromCcy":"USDCSOL","toCcy":"BTCLN","type":"fixed","direction":"to",'
            b'"toAddress":"lnbc1privateinvoice","amount":"0.00001234"}'
        )
        assert request.content == expected
        assert request.headers["Content-Type"] == "application/json; charset=UTF-8"
        assert request.headers["X-API-KEY"] == _KEY
        assert request.headers["Idempotency-Key"] == "request-123"
        assert request.headers["X-API-SIGN"] == hmac.new(
            _SECRET.encode(), expected, hashlib.sha256
        ).hexdigest()
        return httpx.Response(200, json=_order_response(), request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        order = LightningSwapClient(_ORIGIN, _KEY, _SECRET, http_client).create_order(
            _INVOICE, 1234, "USDCSOL", "request-123"
        )

    assert order.order_id == "ORDER123"
    assert order.public_token == "checkout-token-123"
    assert order.deposit_amount == Decimal("4.25")
    assert order.deposit_tag is None
    assert order.expires_at.tzinfo is not None


@pytest.mark.parametrize(
    "raw",
    [
        b"<!DOCTYPE rates [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><rates></rates>",
        b"<rates><item><from>USDCSOL</from><from>USDT</from><to>BTCLN</to>"
        b"<in>1</in><out>0.1</out><amount>1</amount><tofee>0.1 BTCLN</tofee>"
        b"<minamount>1 USDCSOL</minamount><maxamount>2 USDCSOL</maxamount></item></rates>",
        b"<rates><item><from>USDCSOL</from><to>BTC</to><in>1</in>"
        b"<out>0.1</out><amount>1</amount><tofee>0.1 BTCLN</tofee>"
        b"<minamount>1 USDCSOL</minamount><maxamount>2 USDCSOL</maxamount></item></rates>",
        b"x" * (64 * 1024 + 1),
    ],
)
def test_parse_rates_xml_rejects_malformed_or_unsafe_input(raw: bytes) -> None:
    with pytest.raises(ValueError, match="Lightning Swap rates"):
        parse_rates_xml(raw)


def test_fetch_rates_requires_xml_and_calculates_current_like_usdcsol_floor() -> None:
    xml = b"""<rates><item><from>USDCSOL</from><to>BTCLN</to><in>1</in>
    <out>0.00001642</out><amount>1</amount><tofee>0.000001 BTCLN</tofee>
    <minamount>3.5 USDCSOL</minamount><maxamount>10000 USDCSOL</maxamount></item></rates>"""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept"] == "application/xml, text/xml"
        return httpx.Response(200, content=xml, headers={"Content-Type": "application/xml"}, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        payout = fetch_minimum_payout_sats(_ORIGIN, "USDCSOL", client)

    assert payout == 5647


@pytest.mark.parametrize(
    "status_code,content_type,body",
    [
        (200, "text/plain", b"<rates />"),
        (200, "application/xml", b"x" * (64 * 1024 + 1)),
        (302, "application/xml", b"<rates />"),
    ],
)
def test_fetch_rates_rejects_invalid_http_responses(
    status_code: int, content_type: str, body: bytes
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            content=body,
            headers={"Content-Type": content_type, "Location": "https://other.example/rates"},
            request=request,
        )

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as client,
        pytest.raises(LightningSwapError, match="Lightning Swap"),
    ):
        fetch_minimum_payout_sats(_ORIGIN, "USDCSOL", client)


def test_minimum_payout_uses_decimal_ceiling_and_zero_floor() -> None:
    rate = LightningSwapRate("USDCSOL", Decimal("3"), Decimal("0.00000001"), Decimal("0"), Decimal("1"), Decimal("2"))
    assert minimum_payout_sats(rate) == 1
    fee_exceeds_payout = LightningSwapRate("USDCSOL", Decimal("1"), Decimal("0.000001"), Decimal("0.000002"), Decimal("1"), Decimal("2"))
    assert minimum_payout_sats(fee_exceeds_payout) == 0


def test_create_order_rejects_response_mismatch_and_redacts_provider_values() -> None:
    leaked_message = f"provider said {_SECRET} {_INVOICE} checkout-token-123"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"code": 42, "msg": leaked_message, "data": {}}, request=request)

    with httpx.Client(transport=httpx.MockTransport(handler)) as http_client:
        adapter = LightningSwapClient(_ORIGIN, _KEY, _SECRET, http_client)
        with pytest.raises(LightningSwapError) as exc_info:
            adapter.create_order(_INVOICE, 1234, "USDCSOL", "request-123")

    text = str(exc_info.value)
    assert _SECRET not in text
    assert _INVOICE not in text
    assert "checkout-token-123" not in text
    assert "provider said" not in text


def test_create_order_rejects_target_mismatch_without_leaking_invoice_or_token() -> None:
    response = _order_response(target_amount="0.00001235")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response, request=request)

    with (
        httpx.Client(transport=httpx.MockTransport(handler)) as http_client,
        pytest.raises(LightningSwapError) as exc_info,
    ):
        LightningSwapClient(_ORIGIN, _KEY, _SECRET, http_client).create_order(
            _INVOICE, 1234, "USDCSOL", "request-123"
        )

    assert str(exc_info.value) == "Lightning Swap order response is invalid"
