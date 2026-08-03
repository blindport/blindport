"""Test-only HTTP requester that shares the relay network namespace."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

TARGET = os.environ["BLINDPORT_ROUTED_TARGET"]


class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
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

    def log_message(self, _format: str, *_args: object) -> None:
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9191), RequestHandler).serve_forever()
