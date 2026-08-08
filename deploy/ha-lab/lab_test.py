from __future__ import annotations

import concurrent.futures
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


API = os.environ.get("LAB_API_URL", "http://api-lb:8000")
STATE = Path("/lab-state")
PORT_EDGES = {"relay-a": "10.253.241.10", "relay-b": "10.253.242.10"}


def request(path: str, *, method: str = "GET", token: str = "", body: dict | None = None):
    headers = {}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        try:
            body = json.load(error)
        except (UnicodeDecodeError, ValueError):
            body = {"detail": error.reason}
        return error.code, body


def signup() -> str:
    status, response = request("/api/v1/signup", method="POST")
    assert status == 200, response
    return response["token"]


def settle(token: str, payment_id: int) -> dict:
    for _ in range(20):
        status, payment = request(f"/api/v1/payments/{payment_id}", token=token)
        assert status == 200, payment
        if payment["status"] == "paid":
            return payment
        time.sleep(0.2)
    raise AssertionError("mock payment did not settle through either API replica")


def setup() -> None:
    token = signup()
    status, relay_subscription = request(
        "/api/v1/subscriptions",
        method="POST",
        token=token,
        body={"product": "relay", "domain": "ha.relay.test"},
    )
    assert status == 200, relay_subscription
    status, port_subscription = request(
        "/api/v1/subscriptions", method="POST", token=token, body={"product": "port"}
    )
    assert status == 200, port_subscription
    for subscription in (relay_subscription, port_subscription):
        status, payment = request(
            "/api/v1/payments",
            method="POST",
            token=token,
            body={"subscription_id": subscription["id"], "method": "lightning"},
        )
        assert status == 200, payment
        settle(token, payment["id"])
    status, config = request("/api/v1/client/config", token=token)
    assert status == 200, config
    by_product = {item["product"]: item for item in config}
    assert by_product["relay"]["relay_endpoints"] == ["relay-a:5443", "relay-b:5443"]
    status, account = request("/api/v1/me", token=token)
    assert status == 200, account
    port = next(item for item in account["subscriptions"] if item["product"] == "port")
    assert port["port_ips"] == list(PORT_EDGES.values()), port
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.joinpath("token").write_text(token + "\n", encoding="ascii")
    STATE.joinpath("port.json").write_text(
        json.dumps({"assigned_port": port["assigned_port"]}), encoding="ascii"
    )
    STATE.joinpath("config.json").write_text(
        json.dumps(
            {
                "version": 2,
                "mappings": [
                    {
                        "subscription_id": relay_subscription["id"],
                        "upstream": "origin:8443",
                        "tls_mode": "passthrough",
                    },
                    {
                        "subscription_id": port_subscription["id"],
                        "upstream": "origin:8443",
                        "tls_mode": "passthrough",
                    }
                ],
            }
        ),
        encoding="ascii",
    )
    os.chmod(STATE / "token", 0o600)
    os.chmod(STATE / "port.json", 0o600)
    os.chmod(STATE / "config.json", 0o600)
    print("PASS provisioning returned both Relay and Port edges")


def relay_request(edge: str) -> None:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((edge, 4443), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="ha.relay.test") as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: ha.relay.test\r\nConnection: close\r\n\r\n")
            response = b""
            while chunk := tls.recv(8192):
                response += chunk
    assert b"ha-origin\n" in response, response


def port_request(edge: str) -> None:
    port = json.loads((STATE / "port.json").read_text(encoding="ascii"))["assigned_port"]
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((PORT_EDGES[edge], port), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="ha.relay.test") as tls:
            tls.sendall(b"GET / HTTP/1.1\r\nHost: ha.relay.test\r\nConnection: close\r\n\r\n")
            response = b""
            while chunk := tls.recv(8192):
                response += chunk
    assert b"ha-origin\n" in response, response


def forwarding(edges: list[str]) -> None:
    deadline = time.monotonic() + 30
    pending = set(edges)
    while pending and time.monotonic() < deadline:
        for edge in list(pending):
            try:
                relay_request(edge)
                port_request(edge)
            except (AssertionError, ConnectionError, OSError, ssl.SSLError):
                continue
            pending.remove(edge)
        if pending:
            time.sleep(0.5)
    assert not pending, f"no forwarding tunnel at: {sorted(pending)}"
    print(f"PASS new Relay and Port connections through {', '.join(edges)}")


def unavailable(edges: list[str]) -> None:
    attempts = [("relay", edge, relay_request) for edge in edges]
    attempts += [("port", edge, port_request) for edge in edges]
    deadline = time.monotonic() + 75
    consecutive_failures = 0
    last_available: list[str] = []
    while time.monotonic() < deadline:
        available = []
        for kind, edge, check in attempts:
            try:
                check(edge)
            except (AssertionError, ConnectionError, OSError, ssl.SSLError):
                continue
            available.append(f"{kind}:{edge}")
        last_available = available
        if available:
            consecutive_failures = 0
        else:
            consecutive_failures += 1
            if consecutive_failures == 3:
                print("PASS online denial removed Relay and Port tunnels on both edges")
                return
        time.sleep(0.5)
    raise AssertionError(f"traffic remained available after online denial: {last_available}")


def revoked() -> None:
    token = (STATE / "token").read_text(encoding="ascii").strip()
    deadline = time.monotonic() + 30
    last_response = None
    while time.monotonic() < deadline:
        try:
            status, config = request("/api/v1/client/config", token=token)
        except (ConnectionError, OSError) as error:
            last_response = error
            time.sleep(0.25)
            continue
        last_response = (status, config)
        if status == 200 and config == []:
            print("PASS recovered API returned authoritative empty provisioning")
            return
        time.sleep(0.25)
    raise AssertionError(f"recovered API did not return empty provisioning: {last_response}")


def api_continuity() -> None:
    token = (STATE / "token").read_text(encoding="ascii").strip()
    successes = 0
    deadline = time.monotonic() + 30
    while successes < 12 and time.monotonic() < deadline:
        try:
            status, config = request("/api/v1/client/config", token=token)
        except (ConnectionError, OSError):
            time.sleep(0.25)
            continue
        if status == 200 and {item["product"] for item in config} == {"relay", "port"}:
            successes += 1
        else:
            time.sleep(0.25)
    assert successes == 12, f"only {successes} API requests reached the surviving replica"
    print("PASS API requests with one replica stopped")


def reserve_port(index: int) -> tuple[int, int | None, str | None]:
    token = signup()
    status, subscription = request(
        "/api/v1/subscriptions", method="POST", token=token, body={"product": "port"}
    )
    assert status == 200, subscription
    status, payment = request(
        "/api/v1/payments",
        method="POST",
        token=token,
        body={"subscription_id": subscription["id"], "method": "lightning"},
    )
    if status == 409:
        return status, None, None
    assert status == 200, (index, status, payment)
    status, account = request("/api/v1/me", token=token)
    assert status == 200, account
    allocated = account["subscriptions"][0]
    return 200, payment["id"], f'{allocated["assigned_ip"]}:{allocated["assigned_port"]}/tcp'


def concurrency() -> None:
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(reserve_port, range(12)))
    successes = [result for result in results if result[0] == 200]
    conflicts = [result for result in results if result[0] == 409]
    assert len(successes) == 4, results
    assert len(conflicts) == 8, results
    assert len({result[1] for result in successes}) == 4
    assert len({result[2] for result in successes}) == 4
    print("PASS 12 concurrent payments produced 4 unique reservations and 8 capacity conflicts")


def retained() -> None:
    token = (STATE / "token").read_text(encoding="ascii").strip()
    status, config = request("/api/v1/client/config", token=token)
    assert status == 200 and any(item["domain"] == "ha.relay.test" for item in config), config
    print("PASS migration round trip retained active provisioning")


COMMANDS = {
    "setup": setup,
    "api-continuity": api_continuity,
    "concurrency": concurrency,
    "revoked": revoked,
    "retained": retained,
}


if __name__ == "__main__":
    command = sys.argv[1]
    if command in {"forwarding", "unavailable"}:
        globals()[command](sys.argv[2:])
    else:
        COMMANDS[command]()
