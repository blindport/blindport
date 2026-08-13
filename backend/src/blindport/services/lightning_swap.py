"""Strict, bounded client for the Lightning Swap fixed-rate API."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal, InvalidOperation
from typing import Any

import httpx

_MAX_RESPONSE_BYTES = 64 * 1024
_SATOSHIS_PER_BTC = Decimal("100000000")
_MAX_ASSET_LENGTH = 32
_MAX_INVOICE_LENGTH = 4096
_MAX_IDEMPOTENCY_KEY_LENGTH = 255
_MAX_TOKEN_LENGTH = 512
_MAX_ID_LENGTH = 32
_MAX_TEXT_LENGTH = 512
_MAX_AMOUNT_LENGTH = 128
_XML_DECLARATION = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_ORDER_ID = re.compile(r"[A-Z0-9]{1,32}\Z")


@dataclass(frozen=True)
class LightningSwapRate:
    from_asset: str
    in_amount: Decimal
    out_amount: Decimal
    lightning_fee_btc: Decimal
    min_from_amount: Decimal
    max_from_amount: Decimal


@dataclass(frozen=True)
class LightningSwapOrder:
    public_token: str
    order_id: str
    status: str
    asset: str
    network: str
    deposit_amount: str
    deposit_address: str
    deposit_tag: str | None
    required_confirmations: int
    expires_at: datetime


class LightningSwapError(RuntimeError):
    """A provider failure that intentionally contains no provider-supplied detail."""


def _decimal(value: object, *, positive: bool = True) -> Decimal:
    if isinstance(value, bool) or not isinstance(value, int | float | str | Decimal):
        raise ValueError
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError
    decimal = Decimal(str(value))
    if not decimal.is_finite() or (positive and decimal <= 0):
        raise ValueError
    return decimal


def _xml_text(value: str | None) -> str:
    if value is None:
        raise ValueError
    text = value.strip()
    if not text or len(text) > _MAX_TEXT_LENGTH:
        raise ValueError
    return text


def _rate_field(record: ElementTree.Element, name: str) -> str:
    values: list[str] = []
    if name in record.attrib:
        values.append(record.attrib[name])
    for child in record:
        if child.tag == name:
            if child.attrib or list(child):
                raise ValueError
            values.append(child.text or "")
    if len(values) != 1:
        raise ValueError
    return _xml_text(values[0])


def parse_rates_xml(raw: bytes) -> dict[str, LightningSwapRate]:
    """Parse a fixed-rate feed without accepting XML entity expansion."""
    if not isinstance(raw, bytes) or not raw or len(raw) > _MAX_RESPONSE_BYTES:
        raise ValueError("Lightning Swap rates response is invalid")
    if _XML_DECLARATION.search(raw):
        raise ValueError("Lightning Swap rates response is invalid")

    try:
        root = ElementTree.fromstring(raw)
        if root.tag != "rates" or root.attrib:
            raise ValueError
        rates: dict[str, LightningSwapRate] = {}
        for record in root:
            if record.tag != "item" or record.attrib:
                raise ValueError
            fields = {
                "from",
                "to",
                "in",
                "out",
                "amount",
                "tofee",
                "minamount",
                "maxamount",
            }
            if any(child.tag not in fields for child in record):
                raise ValueError
            from_asset = _rate_field(record, "from")
            target_asset = _rate_field(record, "to")
            if (
                target_asset != "BTCLN"
                or not from_asset.isascii()
                or len(from_asset) > _MAX_ASSET_LENGTH
            ):
                raise ValueError
            if from_asset in rates:
                raise ValueError
            _decimal(_rate_field(record, "amount"))
            fee_parts = _rate_field(record, "tofee").split()
            minimum_parts = _rate_field(record, "minamount").split()
            maximum_parts = _rate_field(record, "maxamount").split()
            if (
                len(fee_parts) != 2
                or fee_parts[1] != "BTCLN"
                or len(minimum_parts) != 2
                or minimum_parts[1] != from_asset
                or len(maximum_parts) != 2
                or maximum_parts[1] != from_asset
            ):
                raise ValueError
            rates[from_asset] = LightningSwapRate(
                from_asset=from_asset,
                in_amount=_decimal(_rate_field(record, "in")),
                out_amount=_decimal(_rate_field(record, "out")),
                lightning_fee_btc=_decimal(fee_parts[0]),
                min_from_amount=_decimal(minimum_parts[0]),
                max_from_amount=_decimal(maximum_parts[0]),
            )
            if rates[from_asset].max_from_amount < rates[from_asset].min_from_amount:
                raise ValueError
        if not rates:
            raise ValueError
        return rates
    except (ElementTree.ParseError, InvalidOperation, TypeError, ValueError) as error:
        raise ValueError("Lightning Swap rates response is invalid") from error


def minimum_payout_sats(rate: LightningSwapRate) -> int:
    """Return the minimum invoice payout after the provider Lightning fee."""
    value = rate.min_from_amount * rate.out_amount / rate.in_amount - rate.lightning_fee_btc
    return int((max(Decimal(0), value) * _SATOSHIS_PER_BTC).to_integral_value(ROUND_CEILING))


def _canonical_origin(origin: str) -> str:
    try:
        url = httpx.URL(origin)
    except (TypeError, ValueError) as error:
        raise ValueError("Lightning Swap origin is invalid") from error
    if (
        url.scheme not in {"http", "https"}
        or url.host is None
        or url.username
        or url.password
        or url.path not in {"", "/"}
        or url.query
        or url.fragment
    ):
        raise ValueError("Lightning Swap origin is invalid")
    return str(url).rstrip("/")


def _response_bytes(response: httpx.Response) -> bytes:
    body = bytearray()
    for chunk in response.iter_bytes():
        body.extend(chunk)
        if len(body) > _MAX_RESPONSE_BYTES:
            raise LightningSwapError("Lightning Swap response is too large")
    return bytes(body)


def _content_type(response: httpx.Response) -> str:
    return response.headers.get("Content-Type", "").partition(";")[0].strip().lower()


def fetch_minimum_payout_sats(origin: str, asset: str, client: httpx.Client | None = None) -> int:
    """Fetch the fixed-rate feed and calculate the selected asset's payout floor."""
    base_url = _canonical_origin(origin)
    owns_client = client is None
    effective_client = client or httpx.Client(timeout=5.0, follow_redirects=False)
    try:
        request = effective_client.build_request(
            "GET", f"{base_url}/rates/fixed.xml", headers={"Accept": "application/xml, text/xml"}
        )
        response = effective_client.send(request, stream=True, follow_redirects=False)
        try:
            if response.is_redirect:
                raise LightningSwapError("Lightning Swap rates request was redirected")
            if response.status_code != 200:
                raise LightningSwapError("Lightning Swap rates request failed")
            if _content_type(response) not in {"application/xml", "text/xml"}:
                raise LightningSwapError(
                    "Lightning Swap rates response has an invalid content type"
                )
            body = _response_bytes(response)
        finally:
            response.close()
        try:
            rate = parse_rates_xml(body)[asset]
        except (KeyError, ValueError) as error:
            raise LightningSwapError("Lightning Swap rate is unavailable") from error
        return minimum_payout_sats(rate)
    except httpx.HTTPError as error:
        raise LightningSwapError("Lightning Swap rates request failed") from error
    finally:
        if owns_client:
            effective_client.close()


def _bounded_ascii(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or not value.isascii():
        raise ValueError
    return value


def _response_field(data: dict[str, Any], name: str) -> Any:
    if name not in data:
        raise ValueError
    return data[name]


def _decimal_text(value: object) -> tuple[str, Decimal]:
    if isinstance(value, str):
        text = _bounded_ascii(value, _MAX_AMOUNT_LENGTH)
    elif isinstance(value, int | Decimal) and not isinstance(value, bool):
        text = str(value)
        if len(text) > _MAX_AMOUNT_LENGTH:
            raise ValueError
    else:
        raise ValueError
    return text, _decimal(text)


class LightningSwapClient:
    """Authenticated fixed-order adapter for the Lightning Swap API."""

    def __init__(
        self,
        origin: str,
        api_key: str,
        api_secret: str,
        http_client: httpx.Client | None = None,
        request_timeout_seconds: float = 5.0,
    ) -> None:
        self._origin = _canonical_origin(origin)
        try:
            self._api_key = _bounded_ascii(api_key, _MAX_TEXT_LENGTH)
            self._api_secret = _bounded_ascii(api_secret, _MAX_TEXT_LENGTH)
        except ValueError as error:
            raise ValueError("Lightning Swap credentials are invalid") from error
        self._owns_client = http_client is None
        self._client = http_client or httpx.Client(
            timeout=request_timeout_seconds, follow_redirects=False
        )

    def __enter__(self) -> LightningSwapClient:
        return self

    def __exit__(self, exc_type: object, exc_value: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def create_order(
        self, invoice: str, amount_sats: int, asset: str, idempotency_key: str
    ) -> LightningSwapOrder:
        try:
            invoice = _bounded_ascii(invoice, _MAX_INVOICE_LENGTH)
            asset = _bounded_ascii(asset, _MAX_ASSET_LENGTH)
            idempotency_key = _bounded_ascii(idempotency_key, _MAX_IDEMPOTENCY_KEY_LENGTH)
            if (
                isinstance(amount_sats, bool)
                or not isinstance(amount_sats, int)
                or amount_sats <= 0
            ):
                raise ValueError
        except ValueError as error:
            raise LightningSwapError("Lightning Swap order request is invalid") from error

        amount_btc = (Decimal(amount_sats) / _SATOSHIS_PER_BTC).quantize(Decimal("0.00000000"))
        payload = {
            "fromCcy": asset,
            "toCcy": "BTCLN",
            "type": "fixed",
            "direction": "to",
            "toAddress": invoice,
            "amount": format(amount_btc, ".8f"),
        }
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        signature = hmac.new(self._api_secret.encode("ascii"), body, hashlib.sha256).hexdigest()
        request = self._client.build_request(
            "POST",
            f"{self._origin}/api/v2/create",
            content=body,
            headers={
                "X-API-KEY": self._api_key,
                "X-API-SIGN": signature,
                "Idempotency-Key": idempotency_key,
                "Content-Type": "application/json; charset=UTF-8",
            },
        )
        try:
            response = self._client.send(request, stream=True, follow_redirects=False)
            try:
                if response.is_redirect or response.status_code != 200:
                    raise LightningSwapError("Lightning Swap order request failed")
                if _content_type(response) != "application/json":
                    raise LightningSwapError(
                        "Lightning Swap order response has an invalid content type"
                    )
                raw = _response_bytes(response)
            finally:
                response.close()
            return self._parse_order_response(raw, invoice, amount_btc, asset)
        except LightningSwapError:
            raise
        except httpx.HTTPError as error:
            raise LightningSwapError("Lightning Swap order request failed") from error

    @staticmethod
    def _parse_order_response(
        raw: bytes, invoice: str, amount_btc: Decimal, asset: str
    ) -> LightningSwapOrder:
        try:
            payload = json.loads(raw, parse_float=Decimal)
            if not isinstance(payload, dict) or payload.get("code") != 0:
                raise ValueError
            data = _response_field(payload, "data")
            if not isinstance(data, dict):
                raise ValueError
            source = _response_field(data, "from")
            target = _response_field(data, "to")
            if not isinstance(source, dict) or not isinstance(target, dict):
                raise ValueError
            public_token = _bounded_ascii(_response_field(data, "token"), _MAX_TOKEN_LENGTH)
            order_id = _bounded_ascii(_response_field(data, "id"), _MAX_ID_LENGTH)
            if _ORDER_ID.fullmatch(order_id) is None:
                raise ValueError
            status = _bounded_ascii(_response_field(data, "status"), _MAX_ID_LENGTH)
            from_code = _bounded_ascii(_response_field(source, "code"), _MAX_ASSET_LENGTH)
            to_code = _bounded_ascii(_response_field(target, "code"), _MAX_ASSET_LENGTH)
            target_address = _bounded_ascii(_response_field(target, "address"), _MAX_INVOICE_LENGTH)
            target_amount = _decimal(_response_field(target, "amount"))
            deposit_amount, _ = _decimal_text(_response_field(source, "amount"))
            deposit_address = _bounded_ascii(_response_field(source, "address"), _MAX_TEXT_LENGTH)
            network = _bounded_ascii(_response_field(source, "network"), _MAX_ASSET_LENGTH)
            confirmations = _response_field(source, "reqConfirmations")
            timing = _response_field(data, "time")
            if not isinstance(timing, dict):
                raise ValueError
            expiry = _response_field(timing, "expiration")
            if (
                from_code != asset
                or to_code != "BTCLN"
                or target_address != invoice
                or target_amount != amount_btc
                or isinstance(confirmations, bool)
                or not isinstance(confirmations, int)
                or not 0 <= confirmations <= 1000
                or isinstance(expiry, bool)
                or not isinstance(expiry, int)
                or expiry <= 0
            ):
                raise ValueError
            tag = source.get("tag")
            if tag == "":
                tag = None
            elif tag is not None:
                tag = _bounded_ascii(tag, _MAX_TEXT_LENGTH)
            expires_at = datetime.fromtimestamp(expiry, UTC)
            return LightningSwapOrder(
                public_token=public_token,
                order_id=order_id,
                status=status,
                asset=from_code,
                network=network,
                deposit_amount=deposit_amount,
                deposit_address=deposit_address,
                deposit_tag=tag,
                required_confirmations=confirmations,
                expires_at=expires_at,
            )
        except (
            InvalidOperation,
            OSError,
            OverflowError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise LightningSwapError("Lightning Swap order response is invalid") from error
