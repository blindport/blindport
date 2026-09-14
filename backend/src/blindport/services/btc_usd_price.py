"""Process-local advisory Bitcoin/USD price cache."""

from __future__ import annotations

import asyncio
import json
import threading
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

import httpx
from loguru import logger

from ..config import settings

MEMPOOL_PRICES_URL = "https://mempool.space/api/v1/prices"
_MAX_RESPONSE_BYTES = 16_384
_SATS_PER_BITCOIN = Decimal(100_000_000)


@dataclass(frozen=True)
class BtcUsdPriceSnapshot:
    usd_per_btc: Decimal
    source_updated_at: datetime
    fetched_at: datetime


class BtcUsdPriceCache:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: BtcUsdPriceSnapshot | None = None

    def current(self, now: datetime | None = None) -> BtcUsdPriceSnapshot | None:
        if not settings.BTC_USD_PRICE_ENABLED:
            return None
        checked_at = now or datetime.now(UTC)
        with self._lock:
            snapshot = self._snapshot
        if snapshot is None:
            return None
        if checked_at - snapshot.fetched_at > timedelta(
            seconds=settings.BTC_USD_PRICE_MAX_STALE_SECONDS
        ):
            return None
        return snapshot

    def refresh(self, client: httpx.Client | None = None) -> BtcUsdPriceSnapshot:
        owns_client = client is None
        effective_client = client or httpx.Client(
            timeout=settings.BTC_USD_PRICE_TIMEOUT_SECONDS,
            follow_redirects=False,
        )
        try:
            with effective_client.stream(
                "GET",
                MEMPOOL_PRICES_URL,
                headers={"Accept": "application/json"},
            ) as response:
                response.raise_for_status()
                content_type = response.headers.get("Content-Type", "").partition(";")[0].lower()
                if content_type != "application/json":
                    raise ValueError("Bitcoin price response is not JSON")
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_RESPONSE_BYTES:
                        raise ValueError("Bitcoin price response is too large")
        finally:
            if owns_client:
                effective_client.close()

        try:
            payload = json.loads(body, parse_float=Decimal)
            raw_price = payload["USD"]
            raw_time = payload["time"]
            if isinstance(raw_price, bool) or not isinstance(raw_price, int | Decimal | str):
                raise ValueError("Bitcoin price is invalid")
            if isinstance(raw_time, bool) or not isinstance(raw_time, int) or raw_time <= 0:
                raise ValueError("Bitcoin price timestamp is invalid")
            price = Decimal(raw_price)
            if not price.is_finite() or price <= 0 or price > Decimal(100_000_000):
                raise ValueError("Bitcoin price is invalid")
            source_updated_at = datetime.fromtimestamp(raw_time, UTC)
        except (
            InvalidOperation,
            KeyError,
            OSError,
            OverflowError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise ValueError("Bitcoin price response is invalid") from error

        snapshot = BtcUsdPriceSnapshot(
            usd_per_btc=price,
            source_updated_at=source_updated_at,
            fetched_at=datetime.now(UTC),
        )
        with self._lock:
            self._snapshot = snapshot
        return snapshot


price_cache = BtcUsdPriceCache()


def approximate_usd(amount_sats: int) -> str:
    snapshot = price_cache.current()
    if snapshot is None or amount_sats <= 0:
        return ""
    value = Decimal(amount_sats) * snapshot.usd_per_btc / _SATS_PER_BITCOIN
    if value < Decimal("0.01"):
        return "<$0.01"
    rounded = value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return f"${rounded:,.2f}"


async def run_btc_usd_price_refresh(stop_event: asyncio.Event) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(price_cache.refresh)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            logger.opt(exception=error).warning("Bitcoin/USD price refresh failed")
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.BTC_USD_PRICE_REFRESH_SECONDS,
            )
