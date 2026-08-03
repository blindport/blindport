"""Readiness and liveness behavior for backend dependencies."""

from __future__ import annotations

import pytest


def test_health_routes_report_ready_components(app_client) -> None:
    client, _ = app_client

    for path in ("/api/v1/health", "/api/v1/health/ready"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "components": {
                "database": "ok",
                "migrations": "ok",
                "lightning": "ok",
            },
        }

    assert client.get("/api/v1/health/live").json() == {"status": "ok"}


@pytest.mark.parametrize("dependency", ["database", "migrations", "lightning"])
def test_readiness_returns_sanitized_503_for_failed_dependency(
    app_client, monkeypatch: pytest.MonkeyPatch, dependency: str
) -> None:
    client, factory = app_client
    from blindport.services import health

    provider_error = "sensitive-provider-error"
    if dependency == "database":

        class UnavailableEngine:
            def connect(self):
                raise RuntimeError(provider_error)

        monkeypatch.setattr(health, "engine", UnavailableEngine())
        monkeypatch.setattr(health, "database_revisions", lambda engine: ("0001", "0001"))
    elif dependency == "migrations":
        monkeypatch.setattr(health, "database_revisions", lambda engine: ("0000", "0001"))
    else:
        adapter = factory.get_lightning_adapter()

        def fail_health() -> bool:
            raise RuntimeError(provider_error)

        monkeypatch.setattr(adapter, "health", fail_health)

    response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["status"] == "unavailable"
    assert response.json()["components"][dependency] == "unavailable"
    assert provider_error not in response.text


def test_liveness_does_not_probe_dependencies(app_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _ = app_client
    from blindport.api import v1

    def unexpected_readiness():
        raise AssertionError("liveness must not check dependencies")

    monkeypatch.setattr(v1, "readiness_status", unexpected_readiness)

    response = client.get("/api/v1/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_enabled_reconciler_is_sanitized_and_stale_readiness_fails(
    app_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = app_client
    from blindport.services import health
    from blindport.services.payment_reconciliation import ReconcilerHealth

    now = 100.0
    state = ReconcilerHealth(clock=lambda: now)
    state.configure(enabled=True, startup_grace_seconds=1, stale_after_seconds=2)
    state.record_completed_cycle()
    now = 103.0
    monkeypatch.setattr(health.settings, "PAYMENT_RECONCILIATION_ENABLED", True)
    monkeypatch.setattr(health, "reconciler_health", state)

    response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    assert response.json()["components"]["reconciler"] == "unavailable"
    assert set(response.json()["components"]) == {
        "database",
        "migrations",
        "lightning",
        "reconciler",
    }
