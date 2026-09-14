"""Test-only HTTP and UDP origin for routed WireGuard coverage."""

from __future__ import annotations

import socket
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class HTTPHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, directory="/repo/docker/origin", **kwargs)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def serve_udp() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind(("0.0.0.0", 8081))
        while True:
            payload, source = server.recvfrom(65_507)
            server.sendto(payload, source)


if __name__ == "__main__":
    Thread(target=serve_udp, name="routed-udp-origin", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), HTTPHandler).serve_forever()
