"""Canonical DNS hostname validation shared by configuration and services."""

from __future__ import annotations

import re
from ipaddress import ip_address

_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def canonicalize_hostname(value: str) -> str:
    """Return a canonical DNS hostname or reject invalid and IP-like input."""
    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError as e:
        raise ValueError("domain must be a valid hostname") from e
    hostname = hostname[:-1] if hostname.endswith(".") else hostname
    if not hostname:
        raise ValueError("domain must be a valid hostname")
    if len(hostname) > 253:
        raise ValueError("domain must be at most 253 ASCII characters")
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        raise ValueError("domain must be a hostname, not an IP address")
    labels = hostname.split(".")
    if any(len(label) > 63 or not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError("domain contains an invalid hostname label")
    try:
        for label in labels:
            label.encode("ascii").decode("idna")
    except UnicodeError as e:
        raise ValueError("domain contains an invalid IDNA label") from e
    return hostname
