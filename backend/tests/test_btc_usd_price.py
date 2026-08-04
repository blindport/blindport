"""Advisory Bitcoin/USD price cache behavior."""

from __future__ import annotations

from datetime import timedelta

import httpx
import pytest

from blindport.services import btc_usd_price


def _client(payload: object, *, content_type: str = "application/json") -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == btc_usd_price.MEMPOOL_PRICES_URL
        assert request.headers["Accept"] == "application/json"
        if content_type == "application/json":
            return httpx.Response(200, json=payload, request=request)
        return httpx.Response(
            200,
            text=str(payload),
            headers={"Content-Type": content_type},
            request=request,
        )

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_price_cache_refreshes_and_expires_last_good_value(monkeypatch) -> None:
    monkeypatch.setattr(btc_usd_price.settings, "BTC_USD_PRICE_ENABLED", True)
    monkeypatch.setattr(btc_usd_price.settings, "BTC_USD_PRICE_MAX_STALE_SECONDS", 1800)
    cache = btc_usd_price.BtcUsdPriceCache()
    with _client({"time": 1_785_859_508, "USD": 64_000}) as client:
        snapshot = cache.refresh(client)

    assert snapshot.usd_per_btc == 64_000
    assert snapshot.source_updated_at.timestamp() == 1_785_859_508
    assert cache.current(snapshot.fetched_at + timedelta(seconds=1800)) == snapshot
    assert cache.current(snapshot.fetched_at + timedelta(seconds=1801)) is None


@pytest.mark.parametrize(
    "payload,content_type",
    [
        ({"time": 1_785_859_508}, "application/json"),
        ({"time": 1_785_859_508, "USD": 0}, "application/json"),
        ({"time": True, "USD": 64_000}, "application/json"),
        ({"time": 1_785_859_508, "USD": "NaN"}, "application/json"),
        ("not-json", "text/plain"),
    ],
)
def test_price_cache_rejects_malformed_provider_responses(
    monkeypatch, payload: object, content_type: str
) -> None:
    monkeypatch.setattr(btc_usd_price.settings, "BTC_USD_PRICE_ENABLED", True)
    cache = btc_usd_price.BtcUsdPriceCache()

    with (
        _client(payload, content_type=content_type) as client,
        pytest.raises(ValueError, match="Bitcoin price"),
    ):
        cache.refresh(client)

    assert cache.current() is None


def test_failed_refresh_retains_last_good_snapshot(monkeypatch) -> None:
    monkeypatch.setattr(btc_usd_price.settings, "BTC_USD_PRICE_ENABLED", True)
    cache = btc_usd_price.BtcUsdPriceCache()
    with _client({"time": 1_785_859_508, "USD": 64_000}) as client:
        expected = cache.refresh(client)
    with (
        _client({"time": 1_785_859_508, "USD": -1}) as client,
        pytest.raises(ValueError),
    ):
        cache.refresh(client)

    assert cache.current() == expected


def test_approximate_usd_uses_cached_rate_without_affecting_sats(monkeypatch) -> None:
    monkeypatch.setattr(btc_usd_price.settings, "BTC_USD_PRICE_ENABLED", True)
    cache = btc_usd_price.BtcUsdPriceCache()
    with _client({"time": 1_785_859_508, "USD": 64_000}) as client:
        cache.refresh(client)
    monkeypatch.setattr(btc_usd_price, "price_cache", cache)

    assert btc_usd_price.approximate_usd(7500) == "$4.80"
    assert btc_usd_price.approximate_usd(1) == "<$0.01"
    assert btc_usd_price.approximate_usd(0) == ""
