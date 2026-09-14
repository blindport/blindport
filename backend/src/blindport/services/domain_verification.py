"""DNS ownership verification for customer-managed Blindport Relay domains."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.flags
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


class _LookupDeadlineExceeded(RuntimeError):
    """The verification's single DNS lifetime has elapsed."""


_MAX_AUTHORITATIVE_NS_TARGETS = 8
_MAX_AUTHORITATIVE_NS_ADDRESSES = 16


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
        self._lifetime = lifetime if lifetime is not None else settings.RELAY_DNS_TIMEOUT_SECONDS

    def verify_txt(self, name: str, expected_value: str) -> DomainVerificationResult:
        """Verify TXT ownership directly from an authoritative nameserver.

        Recursive DNS is used only to find the serving zone, nameserver targets,
        and their addresses. The proof itself must come from a vetted numeric
        nameserver address with an authoritative response bit.
        """
        try:
            expected = expected_value.encode("ascii")
        except UnicodeEncodeError as e:
            raise ResolverFailureError("DNS resolver received an invalid TXT challenge") from e

        deadline = time.monotonic() + self._lifetime
        try:
            addresses = self._authoritative_nameserver_addresses(name, deadline)
            return self._verify_authoritative_txt(name, expected, addresses, deadline)
        except _LookupDeadlineExceeded:
            return DomainVerificationResult(False, "DNS lookup timed out")
        except dns.exception.Timeout:
            return DomainVerificationResult(False, "DNS lookup timed out")
        except dns.resolver.NoResolverConfiguration as e:
            raise ResolverUnavailableError("DNS resolver is not configured") from e
        except OSError as e:
            raise ResolverUnavailableError("DNS resolver is unavailable") from e
        except dns.exception.DNSException as e:
            raise ResolverFailureError("DNS resolver failed") from e

    def _remaining_lifetime(self, deadline: float) -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _LookupDeadlineExceeded
        return remaining

    def _authoritative_nameserver_addresses(self, name: str, deadline: float) -> list[str]:
        zone = dns.resolver.zone_for_name(
            name,
            resolver=self._resolver,
            lifetime=self._remaining_lifetime(deadline),
        )
        ns_answers = self._resolver.resolve(
            zone,
            "NS",
            search=False,
            lifetime=self._remaining_lifetime(deadline),
        )
        targets = self._nameserver_targets(ns_answers)
        addresses: list[str] = []
        seen_addresses: set[str] = set()
        saw_timeout = False
        saw_unavailable = False
        saw_failure = False
        remaining_queries = len(targets) * 2
        for target in targets:
            for record_type in ("A", "AAAA"):
                if len(addresses) >= _MAX_AUTHORITATIVE_NS_ADDRESSES:
                    return addresses
                try:
                    lifetime = self._remaining_lifetime(deadline) / remaining_queries
                    answers = self._resolver.resolve(
                        target,
                        record_type,
                        search=False,
                        lifetime=lifetime,
                    )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    continue
                except dns.exception.Timeout:
                    saw_timeout = True
                    continue
                except dns.resolver.NoResolverConfiguration:
                    saw_unavailable = True
                    continue
                except OSError:
                    saw_unavailable = True
                    continue
                except dns.exception.DNSException:
                    saw_failure = True
                    continue
                finally:
                    remaining_queries -= 1
                for address in self._public_nameserver_addresses(
                    answers,
                    _MAX_AUTHORITATIVE_NS_ADDRESSES - len(addresses),
                ):
                    if address not in seen_addresses:
                        seen_addresses.add(address)
                        addresses.append(address)
        if not addresses:
            if saw_timeout:
                raise _LookupDeadlineExceeded
            if saw_unavailable:
                raise ResolverUnavailableError("DNS resolver is unavailable")
            if saw_failure:
                raise ResolverFailureError("DNS authoritative server address lookup failed")
            raise ResolverFailureError("DNS authoritative server addresses are unusable")
        return addresses

    @staticmethod
    def _nameserver_targets(answers: object) -> list[object]:
        try:
            records = list(answers)  # type: ignore[arg-type]
        except TypeError as e:
            raise ResolverFailureError("DNS resolver returned invalid nameserver records") from e

        targets: list[object] = []
        seen: set[str] = set()
        for record in records:
            target = getattr(record, "target", None)
            try:
                if target is None or not target.is_absolute():
                    raise ValueError
                text = target.to_text()
            except (AttributeError, TypeError, ValueError) as e:
                raise ResolverFailureError(
                    "DNS resolver returned invalid nameserver records"
                ) from e
            if text in seen:
                continue
            seen.add(text)
            targets.append(target)
            if len(targets) == _MAX_AUTHORITATIVE_NS_TARGETS:
                break
        if not targets:
            raise ResolverFailureError("DNS resolver returned no authoritative nameservers")
        return targets

    @staticmethod
    def _public_nameserver_addresses(answers: object, limit: int) -> list[str]:
        try:
            records = list(answers)  # type: ignore[arg-type]
        except TypeError as e:
            raise ResolverFailureError(
                "DNS resolver returned invalid authoritative server addresses"
            ) from e

        addresses: list[str] = []
        seen: set[str] = set()
        for record in records:
            address = getattr(record, "address", None)
            if not isinstance(address, str):
                raise ResolverFailureError(
                    "DNS resolver returned invalid authoritative server addresses"
                )
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError as e:
                raise ResolverFailureError(
                    "DNS resolver returned invalid authoritative server addresses"
                ) from e
            if not _is_globally_routable_unicast(parsed):
                raise ResolverFailureError("DNS authoritative server address is unsafe")
            canonical = str(parsed)
            if canonical in seen:
                continue
            seen.add(canonical)
            addresses.append(canonical)
            if len(addresses) == limit:
                break
        return addresses

    def _verify_authoritative_txt(
        self,
        name: str,
        expected: bytes,
        addresses: list[str],
        deadline: float,
    ) -> DomainVerificationResult:
        saw_authoritative_result = False
        saw_timeout = False
        saw_mismatch = False
        saw_nxdomain = False
        saw_nodata = False
        saw_unavailable = False
        saw_failure = False
        validation_failure: ResolverFailureError | None = None

        for index, address in enumerate(addresses):
            try:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [address]
                    resolver.flags = 0
                    lifetime = self._remaining_lifetime(deadline) / (len(addresses) - index)
                    answers = resolver.resolve(
                        name,
                        "TXT",
                        search=False,
                        lifetime=lifetime,
                    )
                    self._remaining_lifetime(deadline)
                    self._require_authoritative_response(getattr(answers, "response", None))
                except dns.resolver.NXDOMAIN as e:
                    self._remaining_lifetime(deadline)
                    self._require_authoritative_nxdomain(e)
                    saw_authoritative_result = True
                    saw_nxdomain = True
                    continue
                except dns.resolver.NoAnswer as e:
                    self._remaining_lifetime(deadline)
                    self._require_authoritative_response_from_exception(e)
                    saw_authoritative_result = True
                    saw_nodata = True
                    continue
                except dns.exception.Timeout:
                    saw_timeout = True
                    continue
                except dns.resolver.NoResolverConfiguration:
                    saw_unavailable = True
                    continue
                except OSError:
                    saw_unavailable = True
                    continue
                except dns.exception.DNSException:
                    saw_failure = True
                    continue

                saw_authoritative_result = True
                if self._contains_expected_txt(answers, expected):
                    return DomainVerificationResult(True, "domain ownership verified")
                saw_mismatch = True
            except ResolverFailureError as e:
                validation_failure = validation_failure or e
                continue

        if saw_mismatch:
            return DomainVerificationResult(False, "challenge TXT value did not match")
        if saw_nxdomain:
            return DomainVerificationResult(False, "challenge name does not exist")
        if saw_nodata or saw_authoritative_result:
            return DomainVerificationResult(False, "challenge TXT record was not found")
        if validation_failure is not None:
            raise validation_failure
        if saw_timeout:
            return DomainVerificationResult(False, "DNS lookup timed out")
        if saw_unavailable:
            raise ResolverUnavailableError("DNS resolver is unavailable")
        if saw_failure:
            raise ResolverFailureError("DNS authoritative servers failed")
        raise ResolverFailureError("DNS authoritative servers are unavailable")

    @staticmethod
    def _require_authoritative_response(response: object) -> None:
        flags = getattr(response, "flags", None)
        try:
            authoritative = bool(flags & dns.flags.AA)
        except TypeError as e:
            raise ResolverFailureError(
                "DNS authoritative server returned an invalid response"
            ) from e
        if not authoritative:
            raise ResolverFailureError("DNS authoritative server did not answer authoritatively")

    def _require_authoritative_nxdomain(self, error: dns.resolver.NXDOMAIN) -> None:
        try:
            responses = error.responses().values()
        except (AttributeError, TypeError, ValueError) as e:
            raise ResolverFailureError(
                "DNS authoritative server returned an invalid response"
            ) from e
        if not responses:
            raise ResolverFailureError("DNS authoritative server returned an invalid response")
        for response in responses:
            self._require_authoritative_response(response)

    def _require_authoritative_response_from_exception(self, error: Exception) -> None:
        try:
            response = error.response()
        except (AttributeError, TypeError, ValueError) as e:
            raise ResolverFailureError(
                "DNS authoritative server returned an invalid response"
            ) from e
        self._require_authoritative_response(response)

    @staticmethod
    def _contains_expected_txt(answers: object, expected: bytes) -> bool:
        try:
            records = list(answers)  # type: ignore[arg-type]
        except TypeError as e:
            raise ResolverFailureError("DNS resolver returned an invalid TXT record") from e
        for answer in records:
            strings = getattr(answer, "strings", None)
            if strings is None:
                raise ResolverFailureError("DNS resolver returned an invalid TXT record")
            try:
                value = b"".join(strings)
            except TypeError as e:
                raise ResolverFailureError("DNS resolver returned an invalid TXT record") from e
            if value == expected:
                return True
        return False

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


def _is_globally_routable_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return (
        address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )
