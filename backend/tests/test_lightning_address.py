"""Offline Lightning Address syntax validation tests."""

from __future__ import annotations

import pytest

from blindport.core.lightning_address import validate_lightning_address


def test_lightning_address_is_canonicalized_to_lowercase_ascii() -> None:
    assert validate_lightning_address("Blind.Port@Coinos.IO") == "blind.port@coinos.io"


@pytest.mark.parametrize(
    "value",
    [
        "alice+sales@coinos.io",
        "alice@coinos",
        "alice@127.0.0.1",
        "alice@coinos.io:443",
        "https://alice@coinos.io",
        "alice@coinos.io/path",
        "alice@coinos%2eio",
        "alice @coinos.io",
        "alice@coinos.io\n",
        "al\u00edce@coinos.io",
        "alice@coinos.local",
        "alice@example.test",
        f"{'a' * 65}@coinos.io",
        f"alice@{'a' * 64}.{'b' * 64}.{'c' * 64}.{'d' * 64}.com",
    ],
)
def test_lightning_address_rejects_ambiguous_or_non_dns_input(value: str) -> None:
    with pytest.raises(ValueError):
        validate_lightning_address(value)


@pytest.mark.parametrize(
    "value",
    [
        "a@coinos.io",
        "a_b-c.d@sub.coinos.io",
        "a@123.co.uk",
        "a@xn--example-9d0b.com",
    ],
)
def test_lightning_address_accepts_dotted_dns_domains(value: str) -> None:
    assert validate_lightning_address(value) == value
