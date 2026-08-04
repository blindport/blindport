"""NUT-00 / NUT-03 Cashu BDHKE primitives.

Pure Python implementation on top of `coincurve` for the curve math. We
expose just enough to:

  * parse a Cashu V3 token (``cashuA`` prefix);
  * build blinded outputs and unblind the mint's signatures;
  * call a mint's ``/v1/swap`` endpoint to redeem inbound proofs.

The code follows the NUT specifications:
  * NUT-00 (blind diffie-hellman key exchange)
  * NUT-03 (swap)
  * NUT-04 (mint quote, bolt11)

References: https://github.com/cashubtc/nuts
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from coincurve import PrivateKey, PublicKey

# Domain separator from NUT-00.
_DOMAIN_SEPARATOR = b"Secp256k1_HashToCurve_Cashu_"

# Order of the secp256k1 group.
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


@dataclass
class Proof:
    """A single NUT-00 proof.

    Field names match the wire JSON exactly so we can serialize via
    ``dataclasses.asdict``.
    """

    amount: int
    id: str
    secret: str
    C: str  # noqa: N815 (wire-level name)


@dataclass
class BlindedOutput:
    """Wire shape for one blinded message we send to a mint."""

    amount: int
    id: str
    B_: str  # noqa: N815

    # Local-only fields: the secret and blinding scalar we need to keep so we
    # can unblind the response. Not serialized to wire.
    _secret: str = field(default="", repr=False)
    _r: int = field(default=0, repr=False)


# ---------------------------------------------------------------------------
# token codec
# ---------------------------------------------------------------------------


def _b64url_decode(s: str) -> bytes:
    s = s.rstrip("=")
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def parse_v3_token(token: str) -> dict[str, Any]:
    """Decode a ``cashuA``-prefixed token.

    Returns the parsed JSON dict (``{"token": [{"mint": URL, "proofs": [...]}]}``).
    Raises ``ValueError`` on malformed input.
    """
    token = token.strip()
    if not token.startswith("cashuA"):
        raise ValueError("only cashu V3 tokens (prefix 'cashuA') are supported")
    raw = _b64url_decode(token[len("cashuA") :])
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"malformed cashu token JSON: {e}") from e
    if "token" not in payload or not isinstance(payload["token"], list):
        raise ValueError("cashu token missing 'token' array")
    return payload


# ---------------------------------------------------------------------------
# BDHKE primitives
# ---------------------------------------------------------------------------


def hash_to_curve(message: bytes) -> PublicKey:
    """NUT-00 ``hash_to_curve`` map.

    Iterates ``Y = sha256(DOMAIN || x || counter)`` interpreted as a
    compressed point's x-coord, prefixing 0x02, until coincurve accepts it
    as a valid point. Always terminates in practice (~50% per try).
    """
    msg_hash = hashlib.sha256(_DOMAIN_SEPARATOR + message).digest()
    counter = 0
    while True:
        candidate = hashlib.sha256(msg_hash + counter.to_bytes(4, "little")).digest()
        try:
            return PublicKey(b"\x02" + candidate)
        except Exception:
            counter += 1
            if counter > 10_000:
                raise RuntimeError("hash_to_curve failed to find a valid point") from None


def _scalar_bytes(k: int) -> bytes:
    return k.to_bytes(32, "big")


def make_blinded_output(amount: int, keyset_id: str) -> BlindedOutput:
    """Build one ``BlindedOutput`` with a fresh secret and blinding scalar.

    ``B_ = Y + r*G`` where ``Y = hash_to_curve(secret_str.encode("utf-8"))``
    and ``secret_str`` is the UTF-8 hex string we'll later ship in the proof.
    Hashing the UTF-8 of the hex string (rather than the raw bytes) matches
    what the mint does at verification time.
    """
    secret_str = secrets.token_bytes(32).hex()
    r_int = secrets.randbelow(_N - 1) + 1
    Y = hash_to_curve(secret_str.encode("utf-8"))
    rG = PrivateKey(_scalar_bytes(r_int)).public_key
    B_ = PublicKey.combine_keys([Y, rG])
    return BlindedOutput(
        amount=amount,
        id=keyset_id,
        B_=B_.format(compressed=True).hex(),
        _secret=secret_str,
        _r=r_int,
    )


def unblind_signature(c_blinded_hex: str, r: int, k_pub_hex: str) -> str:
    """Compute ``C = C_ - r*K`` and return compressed-hex.

    ``r*K`` is point-scalar mul; subtraction is addition with the negated
    point.
    """
    C_ = PublicKey(bytes.fromhex(c_blinded_hex))
    K = PublicKey(bytes.fromhex(k_pub_hex))
    # r*K
    rK = K.multiply(_scalar_bytes(r))
    # Negate rK: compressed form, flip the 02/03 prefix to produce -P.
    rK_bytes = bytearray(rK.format(compressed=True))
    rK_bytes[0] = 0x03 if rK_bytes[0] == 0x02 else 0x02
    neg_rK = PublicKey(bytes(rK_bytes))
    C = PublicKey.combine_keys([C_, neg_rK])
    return C.format(compressed=True).hex()


# ---------------------------------------------------------------------------
# denomination split
# ---------------------------------------------------------------------------


def split_amount(amount: int) -> list[int]:
    """Greedy power-of-two split summing to ``amount``."""
    if amount <= 0:
        raise ValueError("amount must be positive")
    out: list[int] = []
    bit = 0
    while amount > 0:
        if amount & 1:
            out.append(1 << bit)
        amount >>= 1
        bit += 1
    return out


__all__ = [
    "BlindedOutput",
    "Proof",
    "hash_to_curve",
    "make_blinded_output",
    "parse_v3_token",
    "split_amount",
    "unblind_signature",
]
