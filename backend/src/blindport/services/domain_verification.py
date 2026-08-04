"""DNS ownership verification for customer-managed Blindport Relay domains."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.resolver

from ..config import settings
from ..core.hostnames import canonicalize_hostname


@dataclass(frozen=True)
class DomainVerificationResult:
    verified: bool
    detail: str


class DomainVerifier(Protocol):
    def verify_txt(self, name: str, expected_value: str) -> DomainVerificationResult: ...

    def verify_cname(self, name: str, expected_target: str) -> DomainVerificationResult: ...


class ResolverFailureError(RuntimeError):
    """The configured resolver failed while processing a valid lookup."""


class ResolverUnavailableError(RuntimeError):
    """No usable local recursive resolver is configured."""


class DnsPythonDomainVerifier:
    """Resolve ownership records with an explicit total lookup lifetime."""

    def __init__(
        self,
        resolver: dns.resolver.Resolver | None = None,
        lifetime: float | None = None,
    ) -> None:
        try:
            self._resolver = resolver or dns.resolver.Resolver()
        except dns.resolver.NoResolverConfiguration as e:
            raise ResolverUnavailableError("DNS resolver is not configured") from e
        self._lifetime = lifetime or settings.RELAY_DNS_TIMEOUT_SECONDS

    def verify_txt(self, name: str, expected_value: str) -> DomainVerificationResult:
        try:
            answers = self._resolver.resolve(name, "TXT", search=False, lifetime=self._lifetime)
        except dns.resolver.NXDOMAIN:
            return DomainVerificationResult(False, "challenge name does not exist")
        except dns.resolver.NoAnswer:
            return DomainVerificationResult(False, "challenge TXT record was not found")
        except dns.exception.Timeout:
            return DomainVerificationResult(False, "DNS lookup timed out")
        except dns.resolver.NoResolverConfiguration as e:
            raise ResolverUnavailableError("DNS resolver is not configured") from e
        except dns.exception.DNSException as e:
            raise ResolverFailureError("DNS resolver failed") from e
        except OSError as e:
            raise ResolverUnavailableError("DNS resolver is unavailable") from e

        expected = expected_value.encode("ascii")
        for answer in answers:
            strings = getattr(answer, "strings", None)
            if strings is None:
                raise ResolverFailureError("DNS resolver returned an invalid TXT record")
            try:
                value = b"".join(strings)
            except TypeError as e:
                raise ResolverFailureError("DNS resolver returned an invalid TXT record") from e
            if value == expected:
                return DomainVerificationResult(True, "domain ownership verified")
        return DomainVerificationResult(False, "challenge TXT value did not match")

    def verify_cname(self, name: str, expected_target: str) -> DomainVerificationResult:
        try:
            answers = self._resolver.resolve(name, "CNAME", search=False, lifetime=self._lifetime)
        except dns.resolver.NXDOMAIN:
            return DomainVerificationResult(False, "record name does not exist")
        except dns.resolver.NoAnswer:
            return DomainVerificationResult(False, "CNAME record was not found")
        except dns.exception.Timeout:
            return DomainVerificationResult(False, "DNS lookup timed out")
        except dns.resolver.NoResolverConfiguration as e:
            raise ResolverUnavailableError("DNS resolver is not configured") from e
        except dns.exception.DNSException as e:
            raise ResolverFailureError("DNS resolver failed") from e
        except OSError as e:
            raise ResolverUnavailableError("DNS resolver is unavailable") from e

        records = list(answers)
        if len(records) != 1:
            raise ResolverFailureError("DNS resolver returned an invalid CNAME record")
        target = getattr(records[0], "target", None)
        try:
            if target is None or not target.is_absolute():
                raise ValueError
            canonical_target = canonicalize_hostname(target.to_text())
        except (AttributeError, TypeError, ValueError) as e:
            raise ResolverFailureError("DNS resolver returned an invalid CNAME record") from e
        if canonical_target == expected_target:
            return DomainVerificationResult(True, "domain ownership verified")
        return DomainVerificationResult(False, "CNAME target did not match")


def get_domain_verifier() -> DomainVerifier:
    return DnsPythonDomainVerifier()
