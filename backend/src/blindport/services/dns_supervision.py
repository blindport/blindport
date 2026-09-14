"""Bounded public DNS observation worker."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any

import dns.exception
import dns.resolver
from loguru import logger
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlmodel import Session

from ..config import DnsSupervisionTarget, settings
from ..core.models import DnsObservation
from ..db import engine

DnsQuery = Callable[[str, str, float], Iterable[str]]
_ERROR_PRECEDENCE = ("nxdomain", "no_answer", "timeout", "resolver_error", "mismatch")


def _utc_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _public_ip_addresses(values: Iterable[str]) -> set[str]:
    from ipaddress import ip_address

    addresses: set[str] = set()
    for value in values:
        try:
            address = ip_address(value)
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            addresses.add(str(address))
    return addresses


def query_address_records(hostname: str, resolver_address: str, lifetime: float) -> Iterable[str]:
    """Resolve A and AAAA records via one configured recursive resolver."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [resolver_address]
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = resolver.resolve(hostname, record_type, search=False, lifetime=lifetime)
        except dns.resolver.NoAnswer:
            continue
        addresses.extend(answer.address for answer in answers)
    if not addresses:
        raise dns.resolver.NoAnswer
    return addresses


def _error_code(error: BaseException) -> str:
    if isinstance(error, dns.resolver.NXDOMAIN):
        return "nxdomain"
    if isinstance(error, dns.resolver.NoAnswer):
        return "no_answer"
    if isinstance(error, dns.exception.Timeout):
        return "timeout"
    return "resolver_error"


def _dns_observation_insert(session: Session) -> Any:
    dialect = session.get_bind().dialect.name
    if dialect == "postgresql":
        return postgresql_insert(DnsObservation)
    if dialect == "sqlite":
        return sqlite_insert(DnsObservation)
    raise RuntimeError(f"DNS supervision does not support database dialect {dialect!r}")


def _persist_observation(
    session: Session,
    target: DnsSupervisionTarget,
    *,
    observed_ips: set[str],
    healthy: bool,
    resolver_count: int,
    successful_resolvers: int,
    error_code: str | None,
    checked_at: datetime,
) -> DnsObservation:
    values = {
        "expected_ips": ",".join(target.expected_ips),
        "observed_ips": ",".join(sorted(observed_ips)),
        "healthy": healthy,
        "resolver_count": resolver_count,
        "successful_resolvers": successful_resolvers,
        "error_code": error_code,
        "checked_at": checked_at,
    }
    insert = _dns_observation_insert(session).values(hostname=target.hostname, **values)
    session.execute(
        insert.on_conflict_do_update(
            index_elements=["hostname"],
            set_=values,
            where=DnsObservation.checked_at < checked_at,  # type: ignore[arg-type]
        )
    )
    return DnsObservation(hostname=target.hostname, **values)


def _query_result(
    query: DnsQuery,
    hostname: str,
    resolver: str,
    timeout_seconds: float,
) -> tuple[set[str], str | None]:
    try:
        return _public_ip_addresses(query(hostname, resolver, timeout_seconds)), None
    except Exception as error:  # Durable observations contain only fixed error codes.
        return set(), _error_code(error)


def run_dns_supervision_cycle(
    *,
    query: DnsQuery = query_address_records,
    targets: Iterable[DnsSupervisionTarget] | None = None,
    resolvers: Iterable[str] | None = None,
    timeout_seconds: float | None = None,
    session: Session | None = None,
    now: datetime | None = None,
) -> list[DnsObservation]:
    """Check every configured target through every resolver and store latest results."""
    configured_targets = list(
        targets if targets is not None else settings.dns_supervision_targets_list
    )
    configured_resolvers = list(
        resolvers if resolvers is not None else settings.dns_supervision_resolvers_list
    )
    if len(configured_targets) * len(configured_resolvers) > 128:
        raise ValueError("DNS supervision cannot execute more than 128 queries per cycle")
    checked_at = _utc_datetime(now or datetime.now(UTC))
    query_timeout = (
        timeout_seconds if timeout_seconds is not None else settings.RELAY_DNS_TIMEOUT_SECONDS
    )
    owns_session = session is None
    active_session = session or Session(engine)
    observations: list[DnsObservation] = []
    try:
        query_results: list[list[tuple[set[str], str | None]]] = [
            [] for _target in configured_targets
        ]
        work = [
            (target_index, target.hostname, resolver)
            for target_index, target in enumerate(configured_targets)
            for resolver in configured_resolvers
        ]
        if work:
            with ThreadPoolExecutor(max_workers=len(work)) as executor:
                futures = {
                    executor.submit(
                        _query_result, query, hostname, resolver, query_timeout
                    ): target_index
                    for target_index, hostname, resolver in work
                }
                for future in as_completed(futures):
                    query_results[futures[future]].append(future.result())
        for target_index, target in enumerate(configured_targets):
            expected = set(target.expected_ips)
            observed: set[str] = set()
            successful = 0
            errors: set[str] = set()
            for answers, error_code in query_results[target_index]:
                if error_code is not None:
                    errors.add(error_code)
                    continue
                successful += 1
                observed.update(answers)
                if answers != expected:
                    errors.add("mismatch")
            healthy = successful == len(configured_resolvers) and not errors
            error_code = next((code for code in _ERROR_PRECEDENCE if code in errors), None)
            observations.append(
                _persist_observation(
                    active_session,
                    target,
                    observed_ips=observed,
                    healthy=healthy,
                    resolver_count=len(configured_resolvers),
                    successful_resolvers=successful,
                    error_code=error_code,
                    checked_at=checked_at,
                )
            )
        active_session.commit()
        return observations
    except Exception:
        active_session.rollback()
        raise
    finally:
        if owns_session:
            active_session.close()


async def run_dns_supervisor(stop_event: asyncio.Event) -> None:
    """Run immediately, then at a fixed cadence until the application stops."""
    while not stop_event.is_set():
        try:
            await asyncio.to_thread(run_dns_supervision_cycle)
        except Exception:
            logger.exception("DNS supervision cycle failed")
        with suppress(TimeoutError):
            await asyncio.wait_for(
                stop_event.wait(), timeout=settings.DNS_SUPERVISION_INTERVAL_SECONDS
            )
