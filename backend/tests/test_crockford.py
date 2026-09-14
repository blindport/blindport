"""Unit tests for Crockford base32."""

from __future__ import annotations

import pytest

from blindport.core import crockford


def test_roundtrip_random_lengths() -> None:
    for n in (1, 5, 7, 16, 32, 64):
        data = bytes(range(min(n, 256)))[:n]
        encoded = crockford.encode(data)
        decoded = crockford.decode(encoded)
        # Decoding round-trips for byte-aligned lengths.
        assert decoded[: len(data)] == data


def test_alphabet_excludes_iluo() -> None:
    for ch in "ILOU":
        assert ch not in crockford.ALPHABET


def test_typo_folding() -> None:
    # I -> 1, L -> 1, O -> 0
    # AABB1 vs AABBI should decode equally after normalize.
    assert crockford.normalize("ABCDIL") == "ABCD11"
    assert crockford.normalize("a-b-c-O") == "ABC0"


def test_format_grouped() -> None:
    assert crockford.format_grouped("ABCDEFGHIJ", 5) == "ABCDE-FGHIJ"


def test_decode_rejects_invalid() -> None:
    with pytest.raises(ValueError):
        crockford.decode("!!!")
