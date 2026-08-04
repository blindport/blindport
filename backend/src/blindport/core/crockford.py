"""Crockford Base32 encoder/decoder.

Crockford's Base32 alphabet is human-friendly: ambiguous characters (I, L, O, U)
are excluded; case is insignificant; hyphens may be inserted for readability.

Reference: https://www.crockford.com/base32.html
"""

from __future__ import annotations

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
# Decoding map handles human typos: I/L -> 1, O -> 0, U excluded.
DECODE_MAP: dict[str, int] = {}
for i, c in enumerate(ALPHABET):
    DECODE_MAP[c] = i
    DECODE_MAP[c.lower()] = i
DECODE_MAP["I"] = DECODE_MAP["i"] = DECODE_MAP["1"]
DECODE_MAP["L"] = DECODE_MAP["l"] = DECODE_MAP["1"]
DECODE_MAP["O"] = DECODE_MAP["o"] = DECODE_MAP["0"]


def encode(data: bytes) -> str:
    """Encode raw bytes as Crockford base32 (no padding)."""
    if not data:
        return ""
    # Build a single big integer, then convert (preserves leading zero bits in
    # multiples of 8 by padding output length).
    bits = 0
    value = 0
    out = []
    for byte in data:
        value = (value << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            out.append(ALPHABET[(value >> bits) & 0x1F])
    if bits > 0:
        out.append(ALPHABET[(value << (5 - bits)) & 0x1F])
    return "".join(out)


def decode(s: str) -> bytes:
    """Decode a Crockford base32 string back to bytes.

    Hyphens are ignored. Raises ValueError for invalid characters.
    """
    cleaned = s.replace("-", "").replace(" ", "")
    if not cleaned:
        return b""
    bits = 0
    value = 0
    out = bytearray()
    for ch in cleaned:
        if ch not in DECODE_MAP:
            raise ValueError(f"invalid Crockford base32 character: {ch!r}")
        value = (value << 5) | DECODE_MAP[ch]
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def format_grouped(token: str, group_size: int = 5, sep: str = "-") -> str:
    """Insert separators every `group_size` characters for readability."""
    if group_size <= 0:
        return token
    return sep.join(token[i : i + group_size] for i in range(0, len(token), group_size))


def normalize(token: str) -> str:
    """Normalize a Crockford token for storage/comparison: upper, strip seps, fold typos."""
    cleaned = token.replace("-", "").replace(" ", "").upper()
    # Fold typo-prone characters.
    cleaned = cleaned.replace("I", "1").replace("L", "1").replace("O", "0")
    return cleaned
