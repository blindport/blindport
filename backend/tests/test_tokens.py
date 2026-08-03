"""Tests for token generation and verification."""

from __future__ import annotations

from blindport.core import tokens


def test_generate_and_verify() -> None:
    display, normalized = tokens.generate_token()
    assert display
    assert normalized
    hashed = tokens.hash_token(normalized)
    assert tokens.verify_token(display, hashed)
    # Same token presented with different casing / grouping still verifies.
    alt = display.lower().replace("-", "")
    assert tokens.verify_token(alt, hashed)


def test_wrong_token_does_not_verify() -> None:
    d1, n1 = tokens.generate_token()
    d2, n2 = tokens.generate_token()
    h1 = tokens.hash_token(n1)
    assert not tokens.verify_token(d2, h1)


def test_hashing_uses_dedicated_token_key(monkeypatch) -> None:
    monkeypatch.setattr(tokens.settings, "TOKEN_HASH_KEY", "token-hash-key-a")
    first = tokens.hash_token("ABC123")
    monkeypatch.setattr(tokens.settings, "TOKEN_HASH_KEY", "token-hash-key-b")

    assert tokens.hash_token("ABC123") != first
