"""Test-only HTTP requester that shares the relay network namespace."""

from __future__ import annotations

import os
import socket
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import httpx

TARGET = os.environ["BLINDPORT_ROUTED_TARGET"]
TARGET_HOST = urlsplit(TARGET).hostname
if TARGET_HOST is None:
    raise ValueError("BLINDPORT_ROUTED_TARGET must contain a hostname")


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path == "/udp":
            self._udp()
            return
        if self.path == "/icmp":
            self._icmp()
            return
        try:
            response = httpx.get(TARGET, timeout=2)
        except httpx.HTTPError as error:
            body = str(error).encode()
            self.send_response(502)
        else:
            body = response.content
            self.send_response(response.status_code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _udp(self) -> None:
        expected = b"blindport-routed-udp"
        body = b"routed UDP probe timed out"
        status = 502
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                deadline = time.monotonic() + 3
                while time.monotonic() < deadline:
                    client.settimeout(min(0.5, deadline - time.monotonic()))
                    client.sendto(expected, (TARGET_HOST, 8081))
                    try:
                        received, _ = client.recvfrom(65_507)
                    except TimeoutError:
                        continue
                    body = received
                    if received == expected:
                        status = 200
                        break
        except OSError as error:
            body = str(error).encode()
        self._respond(status, body)

    def _icmp(self) -> None:
        try:
            result = subprocess.run(
                ["ping", "-c", "2", "-W", "1", TARGET_HOST],
                check=False,
                capture_output=True,
                timeout=3,
            )
        except subprocess.TimeoutExpired:
            self._respond(502, b"routed ICMP probe timed out")
            return
        if result.returncode == 0:
            self._respond(200, b"blindport-routed-icmp")
            return
        self._respond(
            502, result.stderr or result.stdout or b"routed ICMP probe failed"
        )

    def _respond(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9191), RequestHandler).serve_forever()
