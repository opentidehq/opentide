"""A stand-in SentinelOne tenant: the management console's API (UC-4.2).

``cargo xtask cassettes record sentinel_one/<scenario>`` starts it on a free loopback
port (printed on the first line of stdout) and routes ``s1.invalid`` to it. Its
answers are the ones the Python suite mocks (``tests/test_platforms/
test_query_runners.py``, ``test_sentinel_one_deployer.py``):

- a PowerQuery naming ``slow`` is still running at its first poll; one naming
  ``fails`` ends FAILED; ``| syntax`` is refused (400) with the API's detail; any
  other finishes at once;
- a STAR rule update of an id the console does not hold is a 404.

``POST /__stand-in/reset`` forgets every rule and query, as a fresh start would:
the cross-SDK conformance suite (``tests/conformance/``) runs each SDK's runner
on one stand-in and resets it before each, so that every runner sees the same
ids. Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

API = "/web/api/v2.1"
RULES = API + "/cloud-detection/rules"
PQ = API + "/dv/events/pq"
PING = API + "/dv/events/pq-ping"
RESET = "/__stand-in/reset"

RULE_IDS: list[str] = []
QUERIES: dict[str, dict[str, Any]] = {}

COLUMNS = [{"name": "src.process.name", "type": "string"}, {"name": "endpoint.name"}]
ROWS = [["cmd.exe", "ws-1"], ["powershell.exe", "ws-2"]]


class Handler(BaseHTTPRequestHandler):
    server_version = "s1-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "s1-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _errors(self, status: int, code: int, title: str, detail: str) -> None:
        self._json(status, {"errors": [{"code": code, "title": title, "detail": detail}]})

    def _read(self) -> Any:
        data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        return json.loads(data) if data else None

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"ApiToken {os.environ['S1_API_TOKEN']}":
            return True
        self._errors(401, 4010010, "Authentication Failed", "Invalid API token")
        return False

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == RESET:
            RULE_IDS.clear()
            QUERIES.clear()
            self._json(200, {"reset": True})
            return
        if not self._authorised():
            return
        body = self._read()
        if path == RULES:
            remote = str(1900000000000000001 + len(RULE_IDS))
            RULE_IDS.append(remote)
            self._json(200, {"data": {"id": remote, **body["data"]}})
        elif path == PQ:
            query = str(body.get("query") or "")
            if "| syntax" in query:
                self._errors(400, 4000010, "Validation Error", "Syntax error at 3")
                return
            query_id = f"pq-{len(QUERIES) + 1}"
            pending = "slow" in query or "fails" in query
            QUERIES[query_id] = {"query": query, "polls": 0}
            if pending:
                self._json(200, {"data": {"queryId": query_id, "status": "RUNNING", "progress": 0}})
            else:
                self._json(200, {"data": self._finished(query_id)})
        else:
            self._errors(404, 4040000, "Not Found", "no such resource")

    def _finished(self, query_id: str) -> dict[str, Any]:
        return {
            "queryId": query_id,
            "status": "FINISHED",
            "progress": 100,
            "columns": COLUMNS,
            "data": ROWS,
            "recommendations": ["Add a filter on event.type to speed up the query"],
        }

    def do_GET(self) -> None:
        if not self._authorised():
            return
        parts = urlsplit(self.path)
        if parts.path != PING:
            self._errors(404, 4040000, "Not Found", "no such resource")
            return
        query_id = parse_qs(parts.query).get("queryId", [""])[0]
        state = QUERIES.get(query_id)
        if state is None:
            self._errors(404, 4040000, "Not Found", "unknown query")
            return
        state["polls"] += 1
        if "fails" in state["query"]:
            data = {"queryId": query_id, "status": "FAILED", "responseError": "out of memory"}
        elif state["polls"] < 2:
            data = {"queryId": query_id, "status": "RUNNING", "progress": 50}
        else:
            data = self._finished(query_id)
        self._json(200, {"data": data})

    def do_PUT(self) -> None:
        if not self._authorised():
            return
        path = urlsplit(self.path).path
        body = self._read()
        if path == RULES:
            self._json(200, {"data": {"affected": len(body["filter"]["ids"])}})
            return
        remote = path.removeprefix(RULES + "/")
        if remote not in RULE_IDS:
            self._errors(404, 4040010, "Not Found", f"Rule {remote} not found")
            return
        self._json(200, {"data": {"id": remote, **body["data"]}})

    def do_DELETE(self) -> None:
        if not self._authorised():
            return
        body = self._read()
        self._json(200, {"data": {"affected": len(body["filter"]["ids"])}})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
