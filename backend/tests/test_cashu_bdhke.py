"""Unit tests for the slim BDHKE primitives in :mod:`blindport.adapters.cashu_bdhke`.

We round-trip a single Cashu mint <-> client interaction in memory, without
talking to any real mint, to verify our blinding and unblinding match the
NUT-00 mint reference behavior:

    Alice: B_ = Y + r*G   where Y = hash_to_curve(secret)
    Bob:   C_ = k * B_
    Alice: C  = C_ - r*K  where K = k*G

The recovered ``C`` must equal ``k * Y`` (the "unblinded signature").
"""

from __future__ import annotations

import secrets

from coincurve import PrivateKey, PublicKey

from blindport.adapters.cashu_bdhke import (
    hash_to_curve,
    make_blinded_output,
    split_amount,
    unblind_signature,
)

_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _scalar_bytes(k: int) -> bytes:
    return k.to_bytes(32, "big")


def _expected_C(secret_str: str, k_int: int) -> str:
    """Compute the reference ``k * hash_to_curve(secret_str.utf8)``."""
    Y = hash_to_curve(secret_str.encode("utf-8"))
    kY = Y.multiply(_scalar_bytes(k_int))
    return kY.format(compressed=True).hex()


def test_hash_to_curve_is_deterministic() -> None:
    a = hash_to_curve(b"hello")
    b = hash_to_curve(b"hello")
    assert a.format(compressed=True) == b.format(compressed=True)


def test_hash_to_curve_differs_per_input() -> None:
    a = hash_to_curve(b"hello").format(compressed=True)
    b = hash_to_curve(b"world").format(compressed=True)
    assert a != b


def test_split_amount_sums_to_input() -> None:
    for n in (1, 2, 3, 7, 64, 1000, 12345):
        parts = split_amount(n)
        assert sum(parts) == n
        for p in parts:
            assert p & (p - 1) == 0  # power of two


def test_bdhke_roundtrip_unblinds_correctly() -> None:
    """Simulate one mint sign + client unblind cycle and verify equality."""
    # Mint keyset private scalar k and public point K = k*G.
    k_int = secrets.randbelow(_N - 1) + 1
    k_pub = PrivateKey(_scalar_bytes(k_int)).public_key
    k_pub_hex = k_pub.format(compressed=True).hex()

    # Client builds a blinded output for amount=1 with keyset id "00".
    out = make_blinded_output(amount=1, keyset_id="00")

    # Mint signs: C_ = k * B_.
    B_ = PublicKey(bytes.fromhex(out.B_))
    C_ = B_.multiply(_scalar_bytes(k_int))
    C_hex = C_.format(compressed=True).hex()

    # Client unblinds.
    C = unblind_signature(C_hex, out._r, k_pub_hex)

    # Must equal k * hash_to_curve(secret).
    assert _expected_C(out._secret, k_int) == C
