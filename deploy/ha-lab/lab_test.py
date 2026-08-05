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
        return error.code, json.load(error)


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
    status, subscription = request(
        "/api/v1/subscriptions",
        method="POST",
        token=token,
        body={"product": "relay", "domain": "ha.relay.test"},
    )
    assert status == 200, subscription
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
    assert config[0]["relay_endpoints"] == ["relay-a:5443", "relay-b:5443"]
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.joinpath("token").write_text(token + "\n", encoding="ascii")
    STATE.joinpath("config.json").write_text(
        json.dumps(
            {
                "version": 2,
                "mappings": [
                    {
                        "subscription_id": subscription["id"],
                        "upstream": "origin:8443",
                        "tls_mode": "passthrough",
                    }
                ],
            }
        ),
        encoding="ascii",
    )
    os.chmod(STATE / "token", 0o600)
    os.chmod(STATE / "config.json", 0o600)
    print("PASS provisioning returned both Relay edges")


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


def forwarding(edges: list[str]) -> None:
    deadline = time.monotonic() + 30
    pending = set(edges)
    while pending and time.monotonic() < deadline:
        for edge in list(pending):
            try:
                relay_request(edge)
            except (AssertionError, ConnectionError, OSError, ssl.SSLError):
                continue
            pending.remove(edge)
        if pending:
            time.sleep(0.5)
    assert not pending, f"no forwarding tunnel at: {sorted(pending)}"
    print(f"PASS new Relay connections through {', '.join(edges)}")


def api_continuity() -> None:
    token = (STATE / "token").read_text(encoding="ascii").strip()
    for _ in range(12):
        status, config = request("/api/v1/client/config", token=token)
        assert status == 200 and len(config) == 1, config
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
    assert status == 200 and config[0]["domain"] == "ha.relay.test", config
    print("PASS migration round trip retained active provisioning")


COMMANDS = {
    "setup": setup,
    "api-continuity": api_continuity,
    "concurrency": concurrency,
    "retained": retained,
}


if __name__ == "__main__":
    command = sys.argv[1]
    if command == "forwarding":
        forwarding(sys.argv[2:])
    else:
        COMMANDS[command]()
