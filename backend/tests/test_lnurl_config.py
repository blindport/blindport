"""LNURL production does not need an LND connection or secret."""

import pytest
from pydantic import ValidationError
from test_config import _production_settings


def test_lnurl_production_needs_no_lnd_credentials():
    settings = _production_settings(
        PAYMENT_LIGHTNING_ADAPTER="lnurl",
        LND_INVOICE_HMAC_KEY="",
        LND_REST_URL="",
        LND_CERT_PATH="",
        LND_MACAROON_PATH="",
    )
    assert settings.LNURL_MERCHANT_ADDRESS == "blindport@coinos.io"
    assert settings.REFERRAL_COMMISSION_BPS == 1000


@pytest.mark.parametrize("address", ["alice@elsewhere.org", "http://coinos.io", "alice@127.0.0.1"])
def test_lnurl_merchant_cannot_redirect_requests(address):
    with pytest.raises(ValidationError):
        _production_settings(PAYMENT_LIGHTNING_ADAPTER="lnurl", LNURL_MERCHANT_ADDRESS=address)


@pytest.mark.parametrize("rate", [-1, 10001])
def test_commission_cannot_exceed_paid_service_value(rate):
    with pytest.raises(ValidationError):
        _production_settings(REFERRAL_COMMISSION_BPS=rate)
