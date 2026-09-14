"""Offline syntax validation for Lightning Addresses."""

from __future__ import annotations

import ipaddress
import re

_LOCAL_PART_RE = re.compile(r"^[a-z0-9_.-]+$")
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_RESERVED_SUFFIXES = (
    "example",
    "invalid",
    "local",
    "localhost",
    "test",
    "home.arpa",
)


def validate_lightning_address(value: str) -> str:
    """Return a canonical ASCII Lightning Address without performing I/O."""
    if not isinstance(value, str) or not value.isascii() or len(value) > 254:
        raise ValueError("Lightning Address must be ASCII and at most 254 characters")

    address = value.lower()
    if address.count("@") != 1:
        raise ValueError("Lightning Address must contain one @")
    local_part, domain = address.split("@")
    if not local_part or len(local_part) > 64 or not _LOCAL_PART_RE.fullmatch(local_part):
        raise ValueError("Lightning Address username is invalid")
    if not _is_dns_domain(domain):
        raise ValueError("Lightning Address domain is invalid")
    if any(domain == suffix or domain.endswith(f".{suffix}") for suffix in _RESERVED_SUFFIXES):
        raise ValueError("Lightning Address uses a reserved local domain")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return f"{local_part}@{domain}"
    raise ValueError("Lightning Address domain must not be an IP literal")


def _is_dns_domain(domain: str) -> bool:
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    return all(_DOMAIN_LABEL_RE.fullmatch(label) is not None for label in domain.split("."))
