"""Test-only public observer for routed source identity and TCP/25 policy."""

from __future__ import annotations

import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class SourceHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path != "/source":
            self.send_error(404)
            return
        body = self.client_address[0].encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


def serve_smtp_probe() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", 25))
        server.listen()
        while True:
            connection, source = server.accept()
            with connection:
                connection.sendall(f"220 {source[0]} blindport-policy-test\r\n".encode("ascii"))


if __name__ == "__main__":
    Thread(target=serve_smtp_probe, name="smtp-policy-probe", daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 9292), SourceHandler).serve_forever()
