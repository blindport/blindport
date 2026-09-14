"""DNS supervision parser and cycle coverage."""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime

import dns.exception
import pytest
from pydantic import ValidationError
from sqlmodel import Session


def test_dns_supervision_settings_require_canonical_targets_and_resolvers() -> None:
    from blindport.config import Settings

    settings = Settings(
        _env_file=None,
        DNS_SUPERVISION_ENABLED=True,
        DNS_SUPERVISION_TARGETS=(
            '[{"hostname":"edge.example.com","expected_ips":["1.1.1.1","8.8.8.8","2606:4700:4700::1111"]}]'
        ),
        DNS_SUPERVISION_RESOLVERS="1.1.1.1,8.8.8.8",
    )

    assert settings.dns_supervision_targets_list[0].expected_ips == (
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
    )
    with pytest.raises(ValidationError, match="canonical"):
        Settings(
            _env_file=None,
            DNS_SUPERVISION_TARGETS='[{"hostname":"Edge.example.com","expected_ips":["1.1.1.1"]}]',
        )
    with pytest.raises(ValidationError, match="two to four resolvers"):
        Settings(
            _env_file=None,
            DNS_SUPERVISION_ENABLED=True,
            DNS_SUPERVISION_TARGETS='[{"hostname":"edge.example.com","expected_ips":["1.1.1.1"]}]',
            DNS_SUPERVISION_RESOLVERS="1.1.1.1",
        )
    with pytest.raises(ValidationError, match="more than 32 targets"):
        Settings(
            _env_file=None,
            DNS_SUPERVISION_TARGETS=json.dumps(
                [
                    {"hostname": f"edge-{index}.example.com", "expected_ips": ["1.1.1.1"]}
                    for index in range(33)
                ]
            ),
        )
    with pytest.raises(ValidationError, match="two to four resolvers"):
        Settings(
            _env_file=None,
            DNS_SUPERVISION_ENABLED=True,
            DNS_SUPERVISION_TARGETS='[{"hostname":"edge.example.com","expected_ips":["1.1.1.1"]}]',
            DNS_SUPERVISION_RESOLVERS="1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9",
        )
    with pytest.raises(ValidationError, match="at least DNS_SUPERVISION_INTERVAL_SECONDS"):
        Settings(
            _env_file=None,
            DNS_SUPERVISION_INTERVAL_SECONDS=61,
            DNS_SUPERVISION_STALE_SECONDS=60,
        )


def test_dns_supervision_cycle_persists_sanitized_latest_result(app_client) -> None:
    from blindport.config import DnsSupervisionTarget
    from blindport.core.models import DnsObservation
    from blindport.db import engine
    from blindport.services.dns_supervision import run_dns_supervision_cycle

    _client, _ = app_client
    target = DnsSupervisionTarget("edge.example.com", ("1.1.1.1", "8.8.8.8"))

    def query(hostname: str, resolver: str, lifetime: float) -> list[str]:
        assert hostname == target.hostname
        assert lifetime == 2
        return ["8.8.8.8", "1.1.1.1"] if resolver == "1.1.1.1" else ["1.1.1.1", "8.8.8.8"]

    with Session(engine) as session:
        observations = run_dns_supervision_cycle(
            query=query,
            targets=[target],
            resolvers=["1.1.1.1", "8.8.8.8"],
            timeout_seconds=2,
            session=session,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        observation = session.get(DnsObservation, target.hostname)

    assert len(observations) == 1
    assert observation is not None
    assert observation.healthy is True
    assert observation.observed_ips == "1.1.1.1,8.8.8.8"
    assert observation.error_code is None


def test_dns_supervision_default_query_combines_a_and_aaaa(monkeypatch) -> None:
    from blindport.services import dns_supervision

    calls: list[tuple[str, str, bool, float]] = []

    class Answer:
        def __init__(self, address: str) -> None:
            self.address = address

    class Resolver:
        nameservers: list[str]

        def resolve(
            self, hostname: str, record_type: str, *, search: bool, lifetime: float
        ) -> list[Answer]:
            calls.append((hostname, record_type, search, lifetime))
            if record_type == "A":
                return [Answer("1.1.1.1")]
            return [Answer("2606:4700:4700::1111")]

    resolver = Resolver()
    monkeypatch.setattr(
        dns_supervision.dns.resolver,
        "Resolver",
        lambda *, configure: resolver,
    )

    assert list(dns_supervision.query_address_records("edge.example.com", "8.8.8.8", 2)) == [
        "1.1.1.1",
        "2606:4700:4700::1111",
    ]
    assert resolver.nameservers == ["8.8.8.8"]
    assert calls == [
        ("edge.example.com", "A", False, 2),
        ("edge.example.com", "AAAA", False, 2),
    ]


def test_dns_supervision_cycle_uses_fixed_error_codes_without_exception_text(app_client) -> None:
    from blindport.config import DnsSupervisionTarget
    from blindport.core.models import DnsObservation
    from blindport.db import engine
    from blindport.services.dns_supervision import run_dns_supervision_cycle

    _client, _ = app_client
    target = DnsSupervisionTarget("edge.example.com", ("1.1.1.1",))

    def query(_hostname: str, resolver: str, _lifetime: float) -> list[str]:
        if resolver == "1.1.1.1":
            raise dns.exception.Timeout("private resolver failure")
        return ["9.9.9.9"]

    with Session(engine) as session:
        run_dns_supervision_cycle(
            query=query,
            targets=[target],
            resolvers=["1.1.1.1", "8.8.8.8"],
            session=session,
        )
        observation = session.get(DnsObservation, target.hostname)

    assert observation is not None
    assert observation.healthy is False
    assert observation.successful_resolvers == 1
    assert observation.observed_ips == "9.9.9.9"
    assert observation.error_code == "timeout"


def test_dns_supervision_upserts_existing_and_multiple_targets(app_client) -> None:
    from blindport.config import DnsSupervisionTarget
    from blindport.core.models import DnsObservation
    from blindport.db import engine
    from blindport.services.dns_supervision import run_dns_supervision_cycle

    _client, _ = app_client
    first = DnsSupervisionTarget("edge-a.example.com", ("1.1.1.1",))
    second = DnsSupervisionTarget("edge-b.example.com", ("8.8.8.8",))

    def query(hostname: str, _resolver: str, _lifetime: float) -> list[str]:
        return list(first.expected_ips if hostname == first.hostname else second.expected_ips)

    with Session(engine) as session:
        session.add(
            DnsObservation(
                hostname=first.hostname,
                expected_ips="9.9.9.9",
                observed_ips="9.9.9.9",
                healthy=False,
                resolver_count=1,
                successful_resolvers=0,
                error_code="timeout",
                checked_at=datetime(2025, 1, 1, tzinfo=UTC),
            )
        )
        session.commit()
        run_dns_supervision_cycle(
            query=query,
            targets=[first, second],
            resolvers=["1.1.1.1", "8.8.8.8"],
            session=session,
            now=datetime(2026, 1, 1, tzinfo=UTC),
        )
        session.expire_all()
        first_observation = session.get(DnsObservation, first.hostname)
        second_observation = session.get(DnsObservation, second.hostname)

    assert first_observation is not None
    assert first_observation.expected_ips == "1.1.1.1"
    assert first_observation.observed_ips == "1.1.1.1"
    assert first_observation.healthy is True
    assert second_observation is not None
    assert second_observation.observed_ips == "8.8.8.8"
    assert second_observation.healthy is True


def test_dns_supervision_upsert_retains_newer_observation(app_client) -> None:
    from blindport.config import DnsSupervisionTarget
    from blindport.core.models import DnsObservation
    from blindport.db import engine
    from blindport.services.dns_supervision import run_dns_supervision_cycle

    _client, _ = app_client
    target = DnsSupervisionTarget("edge.example.com", ("1.1.1.1",))
    newer = datetime(2026, 1, 2, tzinfo=UTC)
    older = datetime(2026, 1, 1, tzinfo=UTC)
    with Session(engine) as session:
        run_dns_supervision_cycle(
            query=lambda *_args: ["1.1.1.1"],
            targets=[target],
            resolvers=["1.1.1.1", "8.8.8.8"],
            session=session,
            now=newer,
        )
        run_dns_supervision_cycle(
            query=lambda *_args: ["9.9.9.9"],
            targets=[target],
            resolvers=["1.1.1.1", "8.8.8.8"],
            session=session,
            now=older,
        )
        session.expire_all()
        observation = session.get(DnsObservation, target.hostname)

    assert observation is not None
    checked_at = (
        observation.checked_at.replace(tzinfo=UTC)
        if observation.checked_at.tzinfo is None
        else observation.checked_at
    )
    assert checked_at == newer
    assert observation.healthy is True
    assert observation.observed_ips == "1.1.1.1"


def test_dns_supervision_runs_resolver_lookups_concurrently(app_client) -> None:
    from blindport.config import DnsSupervisionTarget
    from blindport.services.dns_supervision import run_dns_supervision_cycle

    _client, _ = app_client
    target = DnsSupervisionTarget("edge.example.com", ("1.1.1.1",))
    barrier = threading.Barrier(2, timeout=5)

    def query(_hostname: str, _resolver: str, _lifetime: float) -> list[str]:
        barrier.wait()
        return ["1.1.1.1"]

    observations = run_dns_supervision_cycle(
        query=query,
        targets=[target],
        resolvers=["1.1.1.1", "8.8.8.8"],
    )

    assert observations[0].healthy is True
