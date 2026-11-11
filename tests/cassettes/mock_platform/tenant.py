"""A stand-in tenant for the recorded-HTTP harness's sample connector (UC-4.1, #831).

``cargo xtask cassettes record mock-platform/deploy`` starts it on a free loopback
port (printed on the first line of stdout) and routes ``mock-tenant.invalid`` to
it, so the Python client below talks to a host of its own through the recording
proxy. Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

RULES: dict[str, dict[str, Any]] = {}


class Handler(BaseHTTPRequestHandler):
    """The mock platform's rules API."""

    server_version = "mock-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "mock-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _answer(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _authorised(self) -> bool:
        expected = f"Bearer {os.environ['MOCK_PLATFORM_TOKEN']}"
        if self.headers.get("Authorization") == expected:
            return True
        self._answer(401, {"error": "unauthorised"})
        return False

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        data = json.loads(self.rfile.read(length) or b"{}")
        return data if isinstance(data, dict) else {}

    def do_GET(self) -> None:
        if not self._authorised():
            return
        parts = urlsplit(self.path)
        if parts.path == "/api/v1/rules":
            rule_id = parse_qs(parts.query).get("rule_id", [""])[0]
            found = [rule for rule in RULES.values() if rule.get("rule_id") == rule_id]
            self._answer(200, {"data": found})
        elif parts.path.removeprefix("/api/v1/rules/") in RULES:
            self._answer(200, RULES[parts.path.removeprefix("/api/v1/rules/")])
        else:
            self._answer(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._authorised():
            return
        rule = self._body()
        remote = f"r-{len(RULES) + 1}"
        RULES[remote] = {"id": remote, **rule}
        self._answer(201, {"id": remote})

    def do_PUT(self) -> None:
        if not self._authorised():
            return
        remote = self.path.removeprefix("/api/v1/rules/")
        if remote not in RULES:
            self._answer(404, {"error": "not found"})
            return
        RULES[remote] = {"id": remote, **self._body()}
        self._answer(200, {"id": remote, "updated": True})

    def do_PATCH(self) -> None:
        if not self._authorised():
            return
        remote = self.path.removeprefix("/api/v1/rules/")
        if remote not in RULES:
            self._answer(404, {"error": "not found"})
            return
        RULES[remote].update(self._body())
        self._answer(200, {"id": remote, "enabled": RULES[remote].get("enabled")})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
