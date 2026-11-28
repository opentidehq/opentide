"""A stand-in Sysdig Secure tenant for the recorded-HTTP scenarios (UC-4.2, #832).

``cargo xtask cassettes record sysdig/deploy`` starts it on a free loopback
port (printed on the first line of stdout) and routes
``sysdig-tenant.invalid`` to it. It answers the runtime API as
``FakeSysdig`` in ``tests/test_platforms/test_sysdig_deployer.py`` does:
custom Falco rules at ``/api/secure/rules`` (ids from 42, a version that an
update must carry and that it bumps) and runtime policies at
``/api/v2/policies``. Rule 401 is one the token may not read. Standard library
only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

POLICY = "opentide managed detections"
RULES: dict[int, dict[str, Any]] = {}
POLICIES: list[dict[str, Any]] = [
    {"id": 7, "name": POLICY, "ruleNames": ["Other rule"], "type": "falco", "version": 2},
    {"id": 8, "name": "Ünïcode policy", "ruleNames": [], "type": "falco", "version": 1},
]
STATE = {"next_id": 42}


class Handler(BaseHTTPRequestHandler):
    """Sysdig Secure's rules and policies."""

    server_version = "sysdig-stand-in"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "sysdig-stand-in"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _answer(self, status: int, payload: object | None = None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> Any:
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"null")

    def _handle(self, method: str) -> None:
        if self.headers.get("Authorization") != f"Bearer {os.environ['SYSDIG_SECURE_API_TOKEN']}":
            self._answer(401, {"message": "Bad credentials"})
            return
        body = self._body() if method in ("POST", "PUT") else None
        path = self.path.split("?", 1)[0]
        parts = path.strip("/").split("/")
        if path == "/api/secure/rules" and method == "POST":
            if "Rejected" in str(body.get("name")):
                self._answer(422, {"errors": [{"reason": "condition does not compile"}]})
                return
            rule = {**body, "id": STATE["next_id"], "version": 1}
            RULES[STATE["next_id"]] = rule
            STATE["next_id"] += 1
            self._answer(201, rule)
            return
        if path.startswith("/api/secure/rules/"):
            rule_id = int(parts[-1])
            if rule_id == 401:
                self._answer(403, {"message": "Forbidden: missing permission secure.rules.read"})
                return
            if rule_id not in RULES:
                self._answer(404, {"message": "not found"})
                return
            if method == "GET":
                self._answer(200, RULES[rule_id])
                return
            if method == "PUT":
                if body.get("version") != RULES[rule_id]["version"]:
                    self._answer(409, {"message": "version conflict"})
                    return
                RULES[rule_id] = {**body, "version": body["version"] + 1}
                self._answer(200, RULES[rule_id])
                return
            if method == "DELETE":
                del RULES[rule_id]
                self._answer(204)
                return
        if path == "/api/v2/policies" and method == "GET":
            self._answer(200, POLICIES)
            return
        if path.startswith("/api/v2/policies/") and method == "PUT":
            policy_id = int(parts[-1])
            for index, policy in enumerate(POLICIES):
                if policy["id"] == policy_id:
                    POLICIES[index] = {**body, "version": policy["version"] + 1}
                    self._answer(200, POLICIES[index])
                    return
        self._answer(404, {"message": f"no route for {method} {path}"})

    def do_GET(self) -> None:
        self._handle("GET")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_DELETE(self) -> None:
        self._handle("DELETE")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
