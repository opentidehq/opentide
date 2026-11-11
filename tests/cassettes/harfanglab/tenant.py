"""A stand-in HarfangLab EDR tenant for the recorded-HTTP scenarios (UC-4.2, #832).

``cargo xtask cassettes record harfanglab/...`` starts it on a free loopback
port (printed on the first line of stdout) and routes ``hl-tenant.invalid`` to
it. It answers the threat-intelligence and telemetry calls the Python client
makes, with the bodies the Python tests stand in with
(``tests/test_platforms/test_query_runners.py``): Sigma rules (``PUT`` of a
rule it does not hold is a 404, so the client creates it with ``POST``), YARA
files, and a telemetry source's search. Standard library only; deterministic
answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

SIGMA = "/api/data/threat_intelligence/SigmaRule/"
YARA = "/api/data/threat_intelligence/YaraFile/"
TELEMETRY = "/api/data/telemetry/"

SIGMA_RULES: dict[str, dict[str, Any]] = {}
YARA_FILES: dict[str, dict[str, Any]] = {}


class Handler(BaseHTTPRequestHandler):
    """HarfangLab's threat-intelligence and telemetry APIs."""

    server_version = "hl-stand-in"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "hl-stand-in"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _answer(self, status: int, payload: object | None, *, text: str | None = None) -> None:
        if text is not None:
            body = text.encode()
            kind = "text/html; charset=utf-8"
        else:
            body = b"" if payload is None else json.dumps(payload).encode()
            kind = "application/json"
        self.send_response(status)
        if body:
            self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        data = json.loads(self.rfile.read(length) or b"{}")
        return data if isinstance(data, dict) else {}

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"Token {os.environ['HARFANGLAB_API_TOKEN']}":
            return True
        self._answer(401, {"detail": "Invalid token."})
        return False

    def _refused(self, rule: dict[str, Any]) -> bool:
        name = str(rule.get("name", ""))
        if "Forbidden" in name:
            self._answer(403, {"detail": "You do not have permission to perform this action."})
            return True
        if "Rejected" in name:
            self._answer(400, {"content": ["Invalid rule: detection.condition is missing"]})
            return True
        return False

    def do_PUT(self) -> None:
        if not self._authorised():
            return
        path = urlsplit(self.path).path
        rule = self._body()
        if path.startswith(SIGMA) and path != SIGMA:
            if self._refused(rule):
                return
            rule_id = path[len(SIGMA) :].strip("/")
            if rule_id not in SIGMA_RULES:
                self._answer(404, {"detail": "Not found."})
                return
            SIGMA_RULES[rule_id] = {"id": rule_id, **rule}
            self._answer(
                200, {"id": rule_id, "name": rule.get("name"), "enabled": rule.get("enabled")}
            )
            return
        self._answer(404, {"detail": "Not found."})

    def do_POST(self) -> None:
        if not self._authorised():
            return
        path = urlsplit(self.path).path
        rule = self._body()
        if self._refused(rule):
            return
        if path == SIGMA:
            rule_id = f"sigma-{len(SIGMA_RULES) + 1}"
            SIGMA_RULES[rule_id] = rule
            self._answer(201, {"id": rule_id, "name": rule.get("name")})
            return
        if path == YARA:
            rule_id = f"yara-{len(YARA_FILES) + 1}"
            YARA_FILES[rule_id] = rule
            self._answer(201, {"id": rule_id, "name": rule.get("name")})
            return
        self._answer(404, {"detail": "Not found."})

    def do_DELETE(self) -> None:
        if not self._authorised():
            return
        path = urlsplit(self.path).path
        for prefix in (SIGMA, YARA):
            if path.startswith(prefix):
                rule_id = path[len(prefix) :].strip("/")
                if rule_id.endswith("-missing"):
                    self._answer(404, {"detail": "Not found."})
                else:
                    self._answer(204, None)
                return
        self._answer(404, {"detail": "Not found."})

    def do_GET(self) -> None:
        if not self._authorised():
            return
        parts = urlsplit(self.path)
        if parts.path.startswith(TELEMETRY):
            params = dict(parse_qsl(parts.query))
            if params.get("process_name") == "gateway.exe":
                self._answer(
                    502,
                    None,
                    text=(
                        "<html><head><title>502 Bad Gateway</title></head><body>nginx</body></html>"
                    ),
                )
                return
            if params.get("process_name") == "broken.exe":
                self._answer(400, {"detail": "Unknown field: process_nam"})
                return
            self._answer(
                200,
                {
                    "count": 5,
                    "next": None,
                    "previous": None,
                    "results": [
                        {
                            "process_name": "cmd.exe",
                            "agent": {"hostname": "ws-01", "agentid": "a1"},
                            "@event_create_date": "2026-10-26T09:00:00.000Z",
                        },
                        {"process_name": "cmd.exe", "agent": {"hostname": "ws-02"}, "pid": 4242},
                    ],
                },
            )
            return
        self._answer(404, {"detail": "Not found."})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
