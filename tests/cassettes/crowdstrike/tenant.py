"""A stand-in CrowdStrike Falcon tenant for the recorded-HTTP scenarios (UC-4.2, #832).

``cargo xtask cassettes record crowdstrike/...`` starts it on a free loopback
port (printed on the first line of stdout) and routes the EU-1 cloud,
``api.eu-1.crowdstrike.com``, to it. It answers as Falcon answers the calls
the Python client makes, with the bodies the Python tests stand in with
(``tests/test_platforms/test_query_runners.py``,
``tests/test_platforms/test_crowdstrike_client.py``): the OAuth2 token, the
correlation rules API and the Next-Gen SIEM query jobs. Standard library only;
deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

RULES_PATH = "/correlation-rules/entities/rules/v1"
JOBS_PREFIX = "/humio/api/v1/repositories/"
META = {"query_time": 0.012, "trace_id": "00000000-0000-4000-8000-0000000000aa"}

STATE: dict[str, Any] = {"rules": 0, "jobs": 0, "polls": {}}


def _token() -> str:
    return f"at-{os.environ['CROWDSTRIKE_CLIENT_SECRET']}"


class Handler(BaseHTTPRequestHandler):
    """Falcon's OAuth2, correlation rules and query jobs APIs."""

    server_version = "falcon-stand-in"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "falcon-stand-in"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _answer(self, status: int, payload: object | None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if payload is not None:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length)

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"Bearer {_token()}":
            return True
        self._answer(
            401,
            {
                "meta": META,
                "errors": [{"code": 401, "message": "access denied, invalid bearer token"}],
            },
        )
        return False

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        raw = self._body()
        if parts.path == "/oauth2/token":
            form = parse_qs(raw.decode())
            if form.get("client_secret") != [os.environ["CROWDSTRIKE_CLIENT_SECRET"]]:
                self._answer(
                    401, {"meta": META, "errors": [{"code": 401, "message": "access denied"}]}
                )
                return
            self._answer(
                201, {"access_token": _token(), "token_type": "bearer", "expires_in": 1799}
            )
            return
        if not self._authorised():
            return
        if parts.path == RULES_PATH:
            rule = json.loads(raw)
            if "Rejected" in rule.get("name", ""):
                self._answer(
                    400,
                    {
                        "meta": META,
                        "resources": [],
                        "errors": [{"code": 400, "message": "search.filter: invalid query"}],
                    },
                )
                return
            STATE["rules"] += 1
            remote = f"cs-rule-{STATE['rules']}"
            self._answer(
                200,
                {
                    "meta": META,
                    "resources": [
                        {"id": remote, "name": rule.get("name"), "status": rule.get("status")}
                    ],
                    "errors": [],
                },
            )
            return
        if parts.path.startswith(JOBS_PREFIX) and parts.path.endswith("/queryjobs"):
            repository = parts.path[len(JOBS_PREFIX) : -len("/queryjobs")]
            if repository == "forbidden_view":
                self._answer(
                    403,
                    {
                        "meta": META,
                        "errors": [{"code": 403, "message": "access denied, authorization failed"}],
                    },
                )
                return
            STATE["jobs"] += 1
            job = f"{repository}-job-{STATE['jobs']}"
            STATE["polls"][job] = 0
            self._answer(200, {"id": job, "hashedQueryOnView": "f00d"})
            return
        self._answer(404, {"meta": META, "errors": [{"code": 404, "message": "not found"}]})

    def do_PATCH(self) -> None:
        parts = urlsplit(self.path)
        raw = self._body()
        if not self._authorised():
            return
        if parts.path == RULES_PATH:
            rules = json.loads(raw)
            if any("Rejected" in rule.get("name", "") for rule in rules):
                self._answer(
                    400,
                    {
                        "meta": META,
                        "resources": [],
                        "errors": [{"code": 400, "message": "bad rule"}],
                    },
                )
                return
            self._answer(
                200,
                {
                    "meta": META,
                    "resources": [
                        {"id": rule.get("id"), "status": rule.get("status")} for rule in rules
                    ],
                    "errors": [],
                },
            )
            return
        self._answer(404, {"meta": META, "errors": [{"code": 404, "message": "not found"}]})

    def do_DELETE(self) -> None:
        parts = urlsplit(self.path)
        if not self._authorised():
            return
        if parts.path == RULES_PATH:
            ids = parse_qs(parts.query).get("ids", [""])
            if ids == ["cs-rule-missing"]:
                self._answer(
                    404,
                    {
                        "meta": META,
                        "resources": [],
                        "errors": [{"code": 404, "message": "rule not found"}],
                    },
                )
                return
            self._answer(200, {"meta": META, "resources": ids, "errors": []})
            return
        if parts.path.startswith(JOBS_PREFIX) and "/queryjobs/" in parts.path:
            self._answer(204, None)
            return
        self._answer(404, {"meta": META, "errors": [{"code": 404, "message": "not found"}]})

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if not self._authorised():
            return
        if parts.path.startswith(JOBS_PREFIX) and "/queryjobs/" in parts.path:
            job = parts.path.rsplit("/", 1)[1]
            polls = STATE["polls"].get(job)
            if polls is None:
                self._answer(
                    404, {"meta": META, "errors": [{"code": 404, "message": "no such job"}]}
                )
                return
            STATE["polls"][job] = polls + 1
            if job.startswith("slow_view-") or polls == 0:
                self._answer(200, {"done": False, "events": [], "metaData": {"eventCount": 0}})
                return
            if job.startswith("cancelled_view-"):
                self._answer(200, {"done": False, "cancelled": True, "events": []})
                return
            self._answer(
                200,
                {
                    "done": True,
                    "cancelled": False,
                    "events": [
                        {
                            "ComputerName": "ws-01",
                            "aid": {"id": "a1", "cid": "c1"},
                            "@timestamp": 1761465600000,
                        },
                        {
                            "ComputerName": "ws-02",
                            "aid": {"id": "a2"},
                            "UserName": "Ünïcode",
                            "tags": ["x", 1],
                        },
                        "not an event",
                    ],
                    "messages": [{"message": "the search hit a limit"}, "plain warning"],
                    "metaData": {"eventCount": 3},
                },
            )
            return
        self._answer(404, {"meta": META, "errors": [{"code": 404, "message": "not found"}]})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
