"""Authenticated relay heartbeat ingestion coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlmodel import Session, select

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
        "active_subscription_ids": [],
        "active_subscription_ids_truncated": False,
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
        assert persist_relay_heartbeat(
            session,
            RelayHeartbeatRequest.model_validate(_payload(active_tunnels=2)),
            received_at=older,
        )
        session.commit()
        assert persist_relay_heartbeat(
            session,
            RelayHeartbeatRequest.model_validate(_payload(active_tunnels=9, ready=False)),
            received_at=newer,
        )
        session.commit()
        assert not persist_relay_heartbeat(
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


def test_relay_heartbeat_legacy_omitted_snapshot_preserves_connections_then_complete_empty_disconnects(
    app_client, monkeypatch
) -> None:
    from blindport.api import internal
    from blindport.core.models import RelaySubscriptionConnection
    from blindport.db import engine

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    token = client.post("/api/v1/signup").json()["token"]
    subscription_id = client.post(
        "/api/v1/subscriptions",
        json={"product": "port"},
        headers={"Authorization": f"Bearer {token}"},
    ).json()["id"]
    headers = {"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN}

    connected = client.post(
        "/internal/v1/relay/heartbeat",
        json=_payload(active_subscription_ids=[subscription_id]),
        headers=headers,
    )
    assert connected.status_code == 200
    with Session(engine) as session:
        row = session.exec(select(RelaySubscriptionConnection)).one()
        first_connected_at = _utc_datetime(row.last_connected_at)  # type: ignore[arg-type]
        assert row.active is True
        assert _utc_datetime(row.observed_at) == first_connected_at

    legacy_payload = _payload(active_tunnels=1)
    del legacy_payload["active_subscription_ids"]
    legacy = client.post(
        "/internal/v1/relay/heartbeat",
        json=legacy_payload,
        headers=headers,
    )
    assert legacy.status_code == 200
    with Session(engine) as session:
        row = session.exec(select(RelaySubscriptionConnection)).one()
        assert row.active is True
        assert _utc_datetime(row.last_connected_at) == first_connected_at  # type: ignore[arg-type]
        assert _utc_datetime(row.observed_at) == first_connected_at  # type: ignore[arg-type]

    disconnected = client.post(
        "/internal/v1/relay/heartbeat",
        json=_payload(active_tunnels=0, active_subscription_ids=[]),
        headers=headers,
    )
    assert disconnected.status_code == 200
    with Session(engine) as session:
        row = session.exec(select(RelaySubscriptionConnection)).one()
        assert row.active is False
        assert _utc_datetime(row.last_connected_at) == first_connected_at  # type: ignore[arg-type]
        assert _utc_datetime(row.observed_at) >= first_connected_at


def test_relay_heartbeat_truncated_snapshot_preserves_unreported_connections(
    app_client, monkeypatch
) -> None:
    from blindport.api import internal
    from blindport.core.models import RelaySubscriptionConnection, Subscription
    from blindport.db import engine

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    token = client.post("/api/v1/signup").json()["token"]
    subscription_ids = sorted(
        client.post(
            "/api/v1/subscriptions",
            json={"product": "port"},
            headers={"Authorization": f"Bearer {token}"},
        ).json()["id"]
        for _ in range(2)
    )
    headers = {"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN}

    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(active_subscription_ids=subscription_ids),
            headers=headers,
        ).status_code
        == 200
    )
    with Session(engine) as session:
        rows = session.exec(select(RelaySubscriptionConnection)).all()
        observed_by_subscription = {
            row.subscription_id: _utc_datetime(row.observed_at) for row in rows
        }

    assert (
        client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(
                active_subscription_ids=[subscription_ids[0]],
                active_subscription_ids_truncated=True,
            ),
            headers=headers,
        ).status_code
        == 200
    )
    with Session(engine) as session:
        rows = session.exec(select(RelaySubscriptionConnection)).all()
        assert all(row.active for row in rows)
        unreported_subscription_id = next(
            subscription.id
            for subscription in session.exec(select(Subscription)).all()
            if str(subscription.public_id) == subscription_ids[1]
        )
        unreported = next(row for row in rows if row.subscription_id == unreported_subscription_id)
        assert (
            _utc_datetime(unreported.observed_at)
            == observed_by_subscription[unreported.subscription_id]
        )


def test_relay_heartbeat_unknown_subscription_rolls_back_health(app_client, monkeypatch) -> None:
    from blindport.api import internal
    from blindport.core.models import RelayHeartbeat, RelaySubscriptionConnection
    from blindport.db import engine

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    response = client.post(
        "/internal/v1/relay/heartbeat",
        json=_payload(active_subscription_ids=[str(uuid4())]),
        headers={"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN},
    )

    assert response.status_code == 422
    with Session(engine) as session:
        assert session.exec(select(RelayHeartbeat)).all() == []
        assert session.exec(select(RelaySubscriptionConnection)).all() == []


def test_relay_heartbeat_rejects_unsorted_duplicate_and_oversized_subscription_sets(
    app_client, monkeypatch
) -> None:
    from blindport.api import internal

    client, _ = app_client
    _configure_heartbeat_edges(monkeypatch, internal.settings)
    headers = {"X-Relay-Secret": "test-secret", "X-Relay-Heartbeat-Token": _EDGE_A_TOKEN}
    first, second = sorted((str(uuid4()), str(uuid4())))

    for subscription_ids in (
        [second, first],
        [first, first],
        sorted(str(uuid4()) for _ in range(1001)),
    ):
        response = client.post(
            "/internal/v1/relay/heartbeat",
            json=_payload(active_subscription_ids=subscription_ids),
            headers=headers,
        )
        assert response.status_code == 422

    missing_snapshot = _payload(active_subscription_ids_truncated=True)
    del missing_snapshot["active_subscription_ids"]
    response = client.post(
        "/internal/v1/relay/heartbeat",
        json=missing_snapshot,
        headers=headers,
    )
    assert response.status_code == 422
