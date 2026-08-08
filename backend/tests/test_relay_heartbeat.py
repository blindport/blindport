"""Authenticated relay heartbeat ingestion coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlmodel import Session

_EDGE_A_TOKEN = "a" * 64
_EDGE_B_TOKEN = "b" * 64


def _utc_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _payload(**overrides) -> dict:
    return {
        "edge_id": "edge-a",
        "ready": True,
        "components": {
            "authorization": "ok",
            "certificate": "ok",
            "lifecycle": "serving",
            "listeners": "ok",
            "wireguard": "disabled",
        },
        "active_tunnels": 2,
        "active_streams": 3,
        "accepted_connections_total": 4,
        "forwarded_bytes_total": 5,
    } | overrides


def _configure_heartbeat_edges(monkeypatch, settings, *, two_edges: bool = False) -> None:
    edges = '[{"id":"edge-a","endpoint":"edge-a.test:5443"}]'
    keys = f'{{"edge-a":"{_EDGE_A_TOKEN}"}}'
    if two_edges:
        edges = (
            '[{"id":"edge-a","endpoint":"edge-a.test:5443"},'
            '{"id":"edge-b","endpoint":"edge-b.test:5443"}]'
        )
        keys = f'{{"edge-a":"{_EDGE_A_TOKEN}","edge-b":"{_EDGE_B_TOKEN}"}}'
    monkeypatch.setattr(settings, "RELAY_EDGES", edges)
    monkeypatch.setattr(settings, "RELAY_HEARTBEAT_KEYS", keys)


def test_relay_heartbeat_requires_valid_secret(app_client, monkeypatch) -> None:
    from blindport.api import internal

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)

    assert client.post("/internal/v1/relay/heartbeat", json=_payload()).status_code == 401
    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(),
            headers={"X-Relay-Secret": "wrong", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN},
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(),
            headers={"X-Relay-Secret": "test-secret"},
        ).status_code
        == 401
    )


def test_relay_heartbeat_rejects_unconfigured_edge(app_client, monkeypatch) -> None:
    from blindport.api import internal

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)

    response = client.post(
        "/internal/v1/relay/heartbeat",
        json=_payload(edge_id="edge-b"),
        headers={"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN},
    )

    assert response.status_code == 401


def test_relay_heartbeat_rejects_a_different_edges_token(app_client, monkeypatch) -> None:
    from blindport.api import internal

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings, two_edges=True)

    response = client.post(
        "/internal/v1/relay/heartbeat",
        json=_payload(edge_id="edge-b"),
        headers={"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN},
    )

    assert response.status_code == 401


def test_relay_heartbeat_inserts_and_updates_latest_row(app_client, monkeypatch) -> None:
    from blindport.api import internal
    from blindport.core.models import RelayHeartbeat
    from blindport.db import engine

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    headers = {"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN}

    assert client.post("/internal/v1/relay/heartbeat", json=_payload(), headers=headers).json() == {
        "status": "accepted"
    }
    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(
                active_tunnels=9,
                ready=False,
                components=_payload()["components"] | {"authorization": "degraded"},
            ),
            headers=headers,
        ).status_code
        == 200
    )
    with Session(engine) as session:
        heartbeat = session.get(RelayHeartbeat, "edge-a")

    assert heartbeat is not None
    assert heartbeat.active_tunnels == 9
    assert heartbeat.ready is False
    assert heartbeat.authorization == "degraded"


def test_relay_heartbeat_upsert_retains_newer_server_received_state(app_client) -> None:
    from blindport.api.internal import RelayHeartbeatRequest, persist_relay_heartbeat
    from blindport.core.models import RelayHeartbeat
    from blindport.db import engine

    _client, _ = app_client
    older = datetime(2026, 1, 1, tzinfo=UTC)
    newer = older + timedelta(seconds=1)
    with Session(engine) as session:
        persist_relay_heartbeat(
            session,
            RelayHeartbeatRequest.model_validate(_payload(active_tunnels=2)),
            received_at=older,
        )
        session.commit()
        persist_relay_heartbeat(
            session,
            RelayHeartbeatRequest.model_validate(_payload(active_tunnels=9, ready=False)),
            received_at=newer,
        )
        session.commit()
        persist_relay_heartbeat(
            session,
            RelayHeartbeatRequest.model_validate(_payload(active_tunnels=1)),
            received_at=older,
        )
        session.commit()
        session.expire_all()
        heartbeat = session.get(RelayHeartbeat, "edge-a")

    assert heartbeat is not None
    assert heartbeat.active_tunnels == 9
    assert heartbeat.ready is False
    assert _utc_datetime(heartbeat.received_at) == newer


def test_relay_heartbeat_rejects_invalid_component_and_counter(app_client, monkeypatch) -> None:
    from blindport.api import internal

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    headers = {"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN}

    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(components=_payload()["components"] | {"listeners": "starting"}),
            headers=headers,
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(active_streams=9_223_372_036_854_775_808),
            headers=headers,
        ).status_code
        == 422
    )
