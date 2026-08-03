"""End-to-end tests for the Blindport stack.

These tests assume they run inside the `tester` container of
`docker/docker-compose.yaml`. They exercise the full path:

  1. Sign up via the backend API and obtain a Crockford-base32 token.
  2. Subscribe to framed or routed Blindport IP and pay via mock Lightning.
  3. Spawn `blindportd`, using an isolated network namespace for WireGuard.
  4. Confirm HTTP reaches the selected local origin through the relay.
  5. Repeat for Blindport Port exact-socket and Blindport Relay SNI/HTTP-01 dispatch.
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from uuid import uuid4

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

BACKEND = os.environ["BLINDPORT_BACKEND_URL"]
RELAY_HOST = os.environ["BLINDPORT_RELAY_HOST"]
SECOND_IP = os.environ["BLINDPORT_SECOND_IP"]
SNI_HOST = os.environ["BLINDPORT_SNI_HOST"]
SNI_PORT = int(os.environ["BLINDPORT_SNI_PORT"])
HTTP_CHALLENGE_PORT = int(os.environ["BLINDPORT_HTTP_CHALLENGE_PORT"])
SHARED_IP = os.environ["BLINDPORT_SHARED_IP"]
ORIGIN_UPSTREAM = os.environ["BLINDPORT_ORIGIN_UPSTREAM"]
WIREGUARD_BACKEND = os.environ["BLINDPORT_WIREGUARD_BACKEND_URL"]
WIREGUARD_AGENT_IP = os.environ["BLINDPORT_WIREGUARD_AGENT_IP"]
WIREGUARD_ROUTED_IP = os.environ["BLINDPORT_WIREGUARD_ROUTED_IP"]
RELAY_ADMIN = os.environ["BLINDPORT_RELAY_ADMIN_URL"]
ROUTED_REQUESTER = os.environ["BLINDPORT_ROUTED_REQUESTER_URL"]


def _wait_for_backend(timeout: float = 30) -> None:
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"{BACKEND}/api/v1/health", timeout=2)
            if r.status_code == 200:
                return
        except Exception as e:
            last = e
        time.sleep(0.5)
    raise RuntimeError(f"backend never became healthy: {last!r}")


def _signup() -> str:
    r = httpx.post(f"{BACKEND}/api/v1/signup", timeout=5)
    r.raise_for_status()
    return r.json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _subscribe(
    token: str,
    product: str,
    domain: str | None = None,
    transport: str = "tcp",
    delivery: str = "framed",
    billing_term: str = "monthly",
) -> dict:
    body: dict = {
        "product": product,
        "delivery": delivery,
        "billing_term": billing_term,
    }
    if domain:
        body["domain"] = domain
    body["transport"] = transport
    r = httpx.post(
        f"{BACKEND}/api/v1/subscriptions",
        headers=_auth(token),
        json=body,
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


def _create_payment(token: str, sub_id: int, method: str = "lightning") -> dict:
    r = httpx.post(
        f"{BACKEND}/api/v1/payments",
        headers=_auth(token),
        json={"subscription_id": sub_id, "method": method},
        timeout=5,
    )
    r.raise_for_status()
    return r.json()


def _wait_for_background_activation(token: str, subscription_id: int) -> None:
    # Do not poll the payment endpoint. The backend reconciler must observe the
    # mock-auto provider settlement and activate the subscription independently.
    deadline = time.time() + 10
    while time.time() < deadline:
        r = httpx.get(
            f"{BACKEND}/api/v1/subscriptions", headers=_auth(token), timeout=5
        )
        r.raise_for_status()
        if any(
            subscription["id"] == subscription_id and subscription["status"] == "active"
            for subscription in r.json()
        ):
            return
        time.sleep(0.5)
    raise RuntimeError(
        f"subscription {subscription_id} was not activated in the background"
    )


def _get_config(token: str) -> list[dict]:
    r = httpx.get(f"{BACKEND}/api/v1/client/config", headers=_auth(token), timeout=5)
    r.raise_for_status()
    return r.json()


@contextmanager
def _spawn_client(
    token: str,
    kind: str,
    ip: str | None = None,
    port: int | None = None,
    domain: str | None = None,
    upstream: str | None = None,
    http_challenge_upstream: str | None = None,
    transport: str = "tcp",
):
    """Run blindportd in the background, yielding its Popen handle."""
    env = os.environ.copy()
    env["BLINDPORT_TOKEN"] = token
    env["BLINDPORT_BACKEND_URL"] = BACKEND
    env["BLINDPORT_UPSTREAM"] = ORIGIN_UPSTREAM if upstream is None else upstream
    env["BLINDPORT_KIND"] = kind
    env["BLINDPORT_TRANSPORT"] = transport
    state_dir = TemporaryDirectory(prefix="blindport-e2e-identity-")
    env["BLINDPORT_STATE_DIR"] = state_dir.name
    if ip:
        env["BLINDPORT_IP"] = ip
    if port:
        env["BLINDPORT_PORT"] = str(port)
    if domain:
        env["BLINDPORT_DOMAIN"] = domain
    if http_challenge_upstream:
        env["BLINDPORT_HTTP_CHALLENGE_UPSTREAM"] = http_challenge_upstream
    proc = subprocess.Popen(
        ["/usr/local/bin/blindportd"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        time.sleep(1.5)  # let the tunnel come up
        if proc.poll() is not None:
            out = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            raise RuntimeError(f"blindportd exited early: {out}")
        yield proc
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
        if proc.stdout:
            proc.stdout.close()
        state_dir.cleanup()


def _run(*command: str) -> None:
    result = subprocess.run(
        command, check=False, capture_output=True, text=True, timeout=10
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"command {command!r} failed: {detail}")


def _in_namespace(namespace: str, *command: str) -> tuple[str, ...]:
    return ("nsenter", f"--net=/run/netns/{namespace}", *command)


def _capture_in_namespace(namespace: str, *command: str) -> str:
    result = subprocess.run(
        _in_namespace(namespace, *command),
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return f"exit={result.returncode}\n{result.stdout}{result.stderr}".strip()


def _stop_process(proc: subprocess.Popen[bytes]) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=3)
    if proc.stdout:
        proc.stdout.close()


@contextmanager
def _spawn_wireguard_client(token: str):
    """Run the routed agent and origin outside the requester's namespace."""
    suffix = uuid4().hex[:8]
    namespace = f"bpwg-{suffix}"
    link = f"bpa{suffix}"
    state_dir = TemporaryDirectory(prefix="blindport-e2e-wireguard-")
    origin = None
    agent = None
    try:
        _run("ip", "netns", "add", namespace)
        _run(
            "ip",
            "link",
            "add",
            link,
            "link",
            "eth0",
            "type",
            "macvlan",
            "mode",
            "bridge",
        )
        _run("ip", "link", "set", link, "netns", namespace)
        _run(*_in_namespace(namespace, "ip", "link", "set", "lo", "up"))
        _run(*_in_namespace(namespace, "ip", "link", "set", link, "name", "eth0"))
        _run(
            *_in_namespace(
                namespace,
                "ip",
                "address",
                "add",
                f"{WIREGUARD_AGENT_IP}/24",
                "dev",
                "eth0",
            )
        )
        _run(*_in_namespace(namespace, "ip", "link", "set", "eth0", "up"))
        _run(
            *_in_namespace(
                namespace, "ip", "route", "add", "default", "via", "10.50.0.1"
            )
        )

        origin = subprocess.Popen(
            [
                "nsenter",
                f"--net=/run/netns/{namespace}",
                "python",
                "-m",
                "http.server",
                "8080",
                "--bind",
                "0.0.0.0",
                "--directory",
                "/repo/docker/origin",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        env = os.environ.copy()
        env.update(
            {
                "BLINDPORT_TOKEN": token,
                "BLINDPORT_BACKEND_URL": WIREGUARD_BACKEND,
                "BLINDPORT_STATE_DIR": state_dir.name,
            }
        )
        agent = subprocess.Popen(
            [*_in_namespace(namespace, "/usr/local/bin/blindportd", "--wireguard")],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        startup_deadline = time.time() + 10
        while time.time() < startup_deadline:
            if agent.poll() is not None:
                output = (
                    agent.stdout.read().decode(errors="replace") if agent.stdout else ""
                )
                raise RuntimeError(f"WireGuard blindportd exited early: {output}")
            interface = subprocess.run(
                _in_namespace(namespace, "ip", "link", "show", "bpwg0"),
                check=False,
                capture_output=True,
                timeout=2,
            )
            if interface.returncode == 0:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(
                "WireGuard blindportd did not create bpwg0 within 10 seconds"
            )
        if origin.poll() is not None:
            output = (
                origin.stdout.read().decode(errors="replace") if origin.stdout else ""
            )
            raise RuntimeError(f"WireGuard origin exited early: {output}")
        yield namespace
    finally:
        if agent is not None and agent.poll() is None:
            _stop_process(agent)
        elif agent is not None and agent.stdout:
            agent.stdout.close()
        if origin is not None and origin.poll() is None:
            _stop_process(origin)
        elif origin is not None and origin.stdout:
            origin.stdout.close()
        subprocess.run(
            ["ip", "netns", "delete", namespace],
            check=False,
            capture_output=True,
            timeout=10,
        )
        state_dir.cleanup()


@contextmanager
def _tls_http_origin(domain: str):
    response_body = f"relay-tls-origin-{uuid4().hex}".encode()

    class TLSOriginHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/relay":
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, _format, *args):
            pass

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    with TemporaryDirectory(prefix="blindport-tls-origin-") as temp_dir:
        cert_path = Path(temp_dir, "cert.pem")
        key_path = Path(temp_dir, "key.pem")
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(cert_path, key_path)
        server = ThreadingHTTPServer(("127.0.0.1", 0), TLSOriginHandler)
        server.daemon_threads = False
        thread = None
        thread_started = False
        try:
            server.socket = tls_context.wrap_socket(server.socket, server_side=True)
            thread = Thread(
                target=server.serve_forever,
                name="blindport-tls-origin",
                daemon=False,
            )
            thread.start()
            thread_started = True
            port = server.server_address[1]
            yield f"127.0.0.1:{port}", response_body
        finally:
            if thread_started:
                server.shutdown()
            server.server_close()
            if thread_started:
                thread.join(timeout=5)
                if thread.is_alive():
                    raise RuntimeError("temporary TLS origin did not stop")


@contextmanager
def _http_challenge_origin(path: str):
    response_body = f"relay-http-challenge-{uuid4().hex}".encode()

    class ChallengeOriginHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != path:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(response_body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, _format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), ChallengeOriginHandler)
    server.daemon_threads = False
    thread = Thread(
        target=server.serve_forever,
        name="blindport-http-challenge-origin",
        daemon=False,
    )
    thread.start()
    try:
        yield f"127.0.0.1:{server.server_address[1]}", response_body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("temporary HTTP challenge origin did not stop")


@contextmanager
def _udp_echo_origin():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server.settimeout(0.2)
    stopped = Event()

    def echo() -> None:
        while not stopped.is_set():
            try:
                packet, source = server.recvfrom(65507)
            except TimeoutError:
                continue
            except OSError:
                return
            server.sendto(packet, source)

    thread = Thread(target=echo, name="blindport-udp-origin", daemon=False)
    thread.start()
    try:
        host, port = server.getsockname()
        yield f"{host}:{port}"
    finally:
        stopped.set()
        server.close()
        thread.join(timeout=5)
        if thread.is_alive():
            raise RuntimeError("temporary UDP origin did not stop")


@pytest.fixture(scope="session", autouse=True)
def wait_backend():
    _wait_for_backend()


def test_ip_end_to_end():
    token = _signup()
    sub = _subscribe(token, "ip", billing_term="yearly")
    assert (sub["billing_term"], sub["period_days"], sub["yearly_price_sats"]) == (
        "yearly",
        365,
        75000,
    )
    payment = _create_payment(token, sub["id"])
    assert (
        payment["billing_term"],
        payment["period_days"],
        payment["amount_sats"],
    ) == (
        "yearly",
        365,
        75000,
    )
    _wait_for_background_activation(token, sub["id"])
    cfg = _get_config(token)
    assert any(row["product"] == "ip" and row["assigned_ip"] for row in cfg), cfg
    assigned = next(row["assigned_ip"] for row in cfg if row["product"] == "ip")

    with _spawn_client(token, "ip", ip=assigned):
        r = httpx.get(f"http://{assigned}/", timeout=5)
        assert r.status_code == 200
        assert "hello from origin" in r.text


def test_wireguard_ip_end_to_end():
    token = _signup()
    sub = _subscribe(token, "ip", delivery="wireguard")
    assert sub["delivery"] == "wireguard"
    _create_payment(token, sub["id"])
    _wait_for_background_activation(token, sub["id"])
    assert _get_config(token) == []

    subscriptions = httpx.get(
        f"{BACKEND}/api/v1/subscriptions", headers=_auth(token), timeout=5
    ).json()
    lease = next(row for row in subscriptions if row["id"] == sub["id"])
    assert lease["assigned_ip"] == WIREGUARD_ROUTED_IP

    with _spawn_wireguard_client(token) as namespace:
        deadline = time.time() + 15
        last_error = None
        while time.time() < deadline:
            try:
                response = httpx.get(ROUTED_REQUESTER, timeout=2)
                if response.status_code == 200 and "hello from origin" in response.text:
                    break
            except httpx.HTTPError as error:
                last_error = error
            time.sleep(0.5)
        else:
            diagnostics = {
                "address": _capture_in_namespace(
                    namespace, "ip", "-s", "address", "show", "dev", "bpwg0"
                ),
                "rules": _capture_in_namespace(namespace, "ip", "rule", "show"),
                "policy_routes": _capture_in_namespace(
                    namespace, "ip", "route", "show", "table", "51820"
                ),
                "listener": _capture_in_namespace(
                    namespace, "ss", "-lnt", "sport", "=", ":8080"
                ),
                "local_http": _capture_in_namespace(
                    namespace,
                    "curl",
                    "--fail",
                    "--max-time",
                    "2",
                    f"http://{WIREGUARD_ROUTED_IP}:8080/",
                ),
            }
            raise AssertionError(
                f"routed Blindport IP did not become reachable: {last_error!r}; "
                f"diagnostics={diagnostics!r}"
            )

        address_state = subprocess.run(
            [
                *_in_namespace(
                    namespace,
                    "ip",
                    "-json",
                    "address",
                    "show",
                    "dev",
                    "bpwg0",
                )
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        addresses = json.loads(address_state.stdout)[0]["addr_info"]
        assert any(
            row["local"] == WIREGUARD_ROUTED_IP and row["prefixlen"] == 32
            for row in addresses
        )

        metrics = httpx.get(f"{RELAY_ADMIN}/metrics", timeout=5).text
        assert "blindport_relay_wireguard_peers_active 1" in metrics
        assert "blindport_relay_wireguard_prefixes_active 1" in metrics


def test_port_end_to_end():
    token = _signup()
    sub = _subscribe(token, "port")
    _create_payment(token, sub["id"])
    _wait_for_background_activation(token, sub["id"])
    cfg = _get_config(token)
    lease = next(row for row in cfg if row["product"] == "port")
    assert lease["assigned_ip"] == SHARED_IP
    assert 10000 <= lease["assigned_port"] <= 10007
    assert lease["transport"] == "tcp"

    with _spawn_client(
        token,
        "port",
        ip=lease["assigned_ip"],
        port=lease["assigned_port"],
    ):
        r = httpx.get(
            f"http://{lease['assigned_ip']}:{lease['assigned_port']}/",
            timeout=5,
        )
        assert r.status_code == 200
        assert "hello from origin" in r.text


def test_udp_port_end_to_end():
    token = _signup()
    sub = _subscribe(token, "port", transport="udp")
    _create_payment(token, sub["id"])
    _wait_for_background_activation(token, sub["id"])
    lease = next(row for row in _get_config(token) if row["product"] == "port")
    assert lease["assigned_ip"] == SHARED_IP
    assert 10000 <= lease["assigned_port"] <= 10007
    assert lease["transport"] == "udp"

    with _udp_echo_origin() as upstream:
        with _spawn_client(
            token,
            "port",
            ip=lease["assigned_ip"],
            port=lease["assigned_port"],
            upstream=upstream,
            transport="udp",
        ):
            destination = (lease["assigned_ip"], lease["assigned_port"])
            payloads = [
                b"",
                b"first-source",
                os.urandom(20 * 1024),
                os.urandom(65_507),
            ]
            clients = [
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in payloads
            ]
            try:
                for client, payload in zip(clients, payloads, strict=True):
                    client.settimeout(5)
                    client.sendto(payload, destination)
                    response, source = client.recvfrom(65507)
                    assert source == destination
                    assert response == payload
            finally:
                for client in clients:
                    client.close()


def test_relay_end_to_end():
    token = _signup()
    sub = _subscribe(token, "relay", domain="alice.relay.test")
    _create_payment(token, sub["id"])
    _wait_for_background_activation(token, sub["id"])
    cfg = _get_config(token)
    assert any(row["product"] == "relay" and row["domain"] for row in cfg), cfg
    domain = next(row["domain"] for row in cfg if row["product"] == "relay")
    challenge_path = f"/.well-known/acme-challenge/{uuid4().hex}"

    with (
        _tls_http_origin(domain) as (upstream, expected_body),
        _http_challenge_origin(challenge_path) as (challenge_upstream, challenge_body),
    ):
        with _spawn_client(
            token,
            "relay",
            domain=domain,
            upstream=upstream,
            http_challenge_upstream=challenge_upstream,
        ):
            deadline = time.time() + 5
            challenge_status = 0
            challenge_response = b""
            while time.time() < deadline:
                with socket.create_connection(
                    (SNI_HOST, HTTP_CHALLENGE_PORT), timeout=5
                ) as sock:
                    sock.sendall(
                        f"GET {challenge_path} HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    response = HTTPResponse(sock)
                    response.begin()
                    challenge_status = response.status
                    challenge_response = response.read()
                if challenge_status == 200:
                    break
                time.sleep(0.2)
            assert challenge_status == 200, challenge_response
            assert challenge_response == challenge_body

            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            client_context.check_hostname = False
            client_context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((SNI_HOST, SNI_PORT), timeout=5) as sock:
                with client_context.wrap_socket(
                    sock, server_hostname=domain
                ) as tls_sock:
                    tls_sock.sendall(
                        f"GET /relay HTTP/1.1\r\n"
                        f"Host: {domain}\r\n"
                        "Connection: close\r\n\r\n".encode()
                    )
                    response = HTTPResponse(tls_sock)
                    response.begin()
                    assert response.status == 200
                    assert response.read() == expected_body
