"""Daily privacy-preserving bandwidth metric API and cleanup coverage."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlmodel import Session, select


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _activate(client, factory, token: str) -> dict[str, object]:
    subscription = client.post(
        "/api/v1/subscriptions", json={"product": "ip"}, headers=_auth(token)
    ).json()
    payment = client.post(
        "/api/v1/payments",
        json={"subscription_id": subscription["id"], "method": "lightning"},
        headers=_auth(token),
    ).json()
    factory.get_lightning_adapter().mark_paid(payment["payment_hash"])
    assert client.get(f"/api/v1/payments/{payment['id']}", headers=_auth(token)).status_code == 200
    return subscription


def _enable(monkeypatch) -> dict[str, str]:
    from blindport.api import internal

    monkeypatch.setattr(internal.settings, "BANDWIDTH_METRICS_ENABLED", True)
    monkeypatch.setattr(
        internal.settings, "RELAY_EDGES", '[{"id":"edge-a","endpoint":"relay:5443"}]'
    )
    monkeypatch.setattr(
        internal.settings,
        "RELAY_HEARTBEAT_KEYS",
        '{"edge-a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}',
    )
    return {
        "X-Relay-Secret": "test-secret",
        "X-Relay-Heartbeat-Token": "a" * 64,
    }


def _payload(subscription_id: str, *, boot_id: str, sequence: int, ingress: int, egress: int):
    return {
        "edge_id": "edge-a",
        "boot_id": boot_id,
        "sequence": sequence,
        "reports": [
            {
                "subscription_id": subscription_id,
                "day": datetime.now(UTC).date().isoformat(),
                "ingress_bytes": ingress,
                "egress_bytes": egress,
            }
        ],
    }


def test_daily_bandwidth_ingestion_is_idempotent_and_owner_scoped(app_client, monkeypatch) -> None:
    client, factory = app_client
    headers = _enable(monkeypatch)
    owner = client.post("/api/v2/signup").json()
    other = client.post("/api/v2/signup").json()
    subscription = _activate(client, factory, owner["token"])
    boot_id = str(uuid4())

    first = _payload(subscription["id"], boot_id=boot_id, sequence=1, ingress=100, egress=40)
    assert (
        client.post("/internal/v1/relay/bandwidth/daily", json=first, headers=headers).status_code
        == 200
    )
    assert (
        client.post("/internal/v1/relay/bandwidth/daily", json=first, headers=headers).status_code
        == 200
    )
    advanced = _payload(subscription["id"], boot_id=boot_id, sequence=2, ingress=150, egress=70)
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily", json=advanced, headers=headers
        ).status_code
        == 200
    )
    out_of_order = _payload(
        subscription["id"], boot_id=boot_id, sequence=1, ingress=999, egress=999
    )
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily", json=out_of_order, headers=headers
        ).status_code
        == 200
    )

    result = client.get(
        f"/api/v2/subscriptions/{subscription['id']}/bandwidth", headers=_auth(owner["token"])
    )
    assert result.status_code == 200
    assert result.headers["cache-control"] == "no-store"
    assert result.json()["rows"] == [
        {
            "day": datetime.now(UTC).date().isoformat(),
            "ingress_bytes": "150",
            "egress_bytes": "70",
        }
    ]
    assert (
        client.get(
            f"/api/v2/subscriptions/{subscription['id']}/bandwidth", headers=_auth(other["token"])
        ).status_code
        == 404
    )


def test_daily_bandwidth_rejects_counter_decrease_without_partial_write(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    headers = _enable(monkeypatch)
    owner = client.post("/api/v1/signup").json()
    first = _activate(client, factory, owner["token"])
    second = _activate(client, factory, owner["token"])
    boot_id = str(uuid4())
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily",
            json=_payload(first["id"], boot_id=boot_id, sequence=1, ingress=100, egress=100),
            headers=headers,
        ).status_code
        == 200
    )
    day = datetime.now(UTC).date().isoformat()
    response = client.post(
        "/internal/v1/relay/bandwidth/daily",
        json={
            "edge_id": "edge-a",
            "boot_id": boot_id,
            "sequence": 2,
            "reports": [
                {
                    "subscription_id": second["id"],
                    "day": day,
                    "ingress_bytes": 10,
                    "egress_bytes": 10,
                },
                {
                    "subscription_id": first["id"],
                    "day": day,
                    "ingress_bytes": 99,
                    "egress_bytes": 100,
                },
            ],
        },
        headers=headers,
    )
    assert response.status_code == 409
    assert (
        client.get(
            f"/api/v2/subscriptions/{first['id']}/bandwidth", headers=_auth(owner["token"])
        ).json()["rows"][0]["ingress_bytes"]
        == "100"
    )
    assert (
        client.get(
            f"/api/v2/subscriptions/{second['id']}/bandwidth", headers=_auth(owner["token"])
        ).json()["rows"]
        == []
    )


def test_daily_bandwidth_rejects_invalid_reports_and_edge_auth(app_client, monkeypatch) -> None:
    client, factory = app_client
    headers = _enable(monkeypatch)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _activate(client, factory, token)
    payload = _payload(subscription["id"], boot_id=str(uuid4()), sequence=0, ingress=0, egress=0)
    assert client.post("/internal/v1/relay/bandwidth/daily", json=payload).status_code == 401
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily",
            json={**payload, "extra": True},
            headers=headers,
        ).status_code
        == 422
    )
    duplicate = {**payload, "reports": payload["reports"] * 2}
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily", json=duplicate, headers=headers
        ).status_code
        == 422
    )
    future = _payload(subscription["id"], boot_id=str(uuid4()), sequence=0, ingress=0, egress=0)
    future["reports"][0]["day"] = (datetime.now(UTC).date() + timedelta(days=1)).isoformat()
    assert (
        client.post("/internal/v1/relay/bandwidth/daily", json=future, headers=headers).status_code
        == 422
    )


def test_daily_bandwidth_is_hidden_when_disabled(app_client) -> None:
    client, _ = app_client
    response = client.post(
        "/internal/v1/relay/bandwidth/daily",
        json={
            "edge_id": "edge-a",
            "boot_id": str(uuid4()),
            "sequence": 0,
            "reports": [
                {
                    "subscription_id": str(uuid4()),
                    "day": datetime.now(UTC).date().isoformat(),
                    "ingress_bytes": 0,
                    "egress_bytes": 0,
                }
            ],
        },
    )
    assert response.status_code == 404


def test_disabled_bandwidth_query_is_hidden_before_subscription_lookup(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    from blindport.api import v2

    owner = client.post("/api/v1/signup").json()
    subscription = _activate(client, factory, owner["token"])
    monkeypatch.setattr(v2.settings, "BANDWIDTH_METRICS_ENABLED", False)
    response = client.get(
        f"/api/v2/subscriptions/{subscription['id']}/bandwidth", headers=_auth(owner["token"])
    )
    assert response.status_code == 404
    assert response.headers["cache-control"] == "no-store"


def test_daily_bandwidth_rejects_int64_aggregate_overflow_without_partial_write(
    app_client, monkeypatch
) -> None:
    client, factory = app_client
    headers = _enable(monkeypatch)
    owner = client.post("/api/v1/signup").json()
    first = _activate(client, factory, owner["token"])
    second = _activate(client, factory, owner["token"])
    maximum = 9_223_372_036_854_775_807
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily",
            json=_payload(
                second["id"], boot_id=str(uuid4()), sequence=1, ingress=maximum, egress=0
            ),
            headers=headers,
        ).status_code
        == 200
    )
    day = datetime.now(UTC).date().isoformat()
    response = client.post(
        "/internal/v1/relay/bandwidth/daily",
        json={
            "edge_id": "edge-a",
            "boot_id": str(uuid4()),
            "sequence": 1,
            "reports": [
                {
                    "subscription_id": first["id"],
                    "day": day,
                    "ingress_bytes": 10,
                    "egress_bytes": 0,
                },
                {
                    "subscription_id": second["id"],
                    "day": day,
                    "ingress_bytes": maximum,
                    "egress_bytes": 0,
                },
            ],
        },
        headers=headers,
    )
    assert response.status_code == 409
    first_rows = client.get(
        f"/api/v2/subscriptions/{first['id']}/bandwidth", headers=_auth(owner["token"])
    ).json()["rows"]
    second_rows = client.get(
        f"/api/v2/subscriptions/{second['id']}/bandwidth", headers=_auth(owner["token"])
    ).json()["rows"]
    assert first_rows == []
    assert second_rows[0]["ingress_bytes"] == str(maximum)


def test_cleanup_removes_only_expired_privacy_minimized_rows(app_client, monkeypatch) -> None:
    client, factory = app_client
    headers = _enable(monkeypatch)
    from blindport.core.models import RelayBandwidthCursor, SubscriptionDailyBandwidth
    from blindport.db import engine
    from blindport.services import bandwidth

    monkeypatch.setattr(bandwidth.settings, "BANDWIDTH_INGEST_MAX_AGE_DAYS", 3)
    monkeypatch.setattr(bandwidth.settings, "BANDWIDTH_RETENTION_DAYS", 400)
    token = client.post("/api/v1/signup").json()["token"]
    subscription = _activate(client, factory, token)
    assert (
        client.post(
            "/internal/v1/relay/bandwidth/daily",
            json=_payload(
                subscription["id"], boot_id=str(uuid4()), sequence=1, ingress=10, egress=10
            ),
            headers=headers,
        ).status_code
        == 200
    )
    with Session(engine) as session:
        cursor = session.exec(select(RelayBandwidthCursor)).one()
        aggregate = session.exec(select(SubscriptionDailyBandwidth)).one()
        cursor.day = datetime.now(UTC).date() - timedelta(days=4)
        aggregate.day = datetime.now(UTC).date() - timedelta(days=401)
        session.add(cursor)
        session.add(aggregate)
        session.commit()
    with Session(engine) as session:
        assert bandwidth.cleanup_daily_bandwidth(session) == (1, 1)
        session.commit()
        assert session.exec(select(RelayBandwidthCursor)).all() == []
        assert session.exec(select(SubscriptionDailyBandwidth)).all() == []
