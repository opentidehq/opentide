"""A stand-in Carbon Black Cloud tenant (UC-4.3).

``cargo xtask cassettes record carbon_black/<scenario>`` starts it on a free loopback
port (printed on the first line of stdout) and routes ``cbc.invalid`` to it. Its
answers are the ones the Python suite mocks (``tests/test_platforms/
test_carbon_black_deployer.py``, ``test_query_runners.py``):

- watchlists (``threathunter/watchlistmgr/v3``): the org holds the watchlist
  ``opentide`` (one report of another rule's IOC) and ``empty``; reports are
  created, read, replaced and deleted, and a watchlist's report ids replaced;
- process searches (``api/investigate/v2``): a query is validated, then a search
  job started, polled once still running, then read in pages; ``process_name:x``
  finds nothing, a query with ``(`` is refused by the validation, one with
  ``slow`` never completes, one with ``denied`` is a 403;
- ``search_validation`` (POST): ``valid`` false for a query with a ``(``.

Every request needs ``X-Auth-Token: <token>``. Standard library only;
deterministic answers.
"""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

ORG = "ORGKEY01"
WATCHLISTS = f"/threathunter/watchlistmgr/v3/orgs/{ORG}/watchlists"
REPORTS = f"/threathunter/watchlistmgr/v3/orgs/{ORG}/reports"
PROCESSES = f"/api/investigate/v2/orgs/{ORG}/processes"
OTHER_REPORT = {
    "id": "report-other",
    "timestamp": 1790000000,
    "title": "Another rule",
    "description": "Another rule's report.",
    "severity": 3,
    "link": None,
    "tags": ["PRODUCTION"],
    "iocs_v2": [
        {
            "id": "ioc-other",
            "match_type": "query",
            "values": ["process_name:other.exe"],
            "field": None,
            "link": None,
        }
    ],
    "visibility": None,
}
STATE: dict[str, Any] = {
    "watchlists": {
        "wl-1": {
            "id": "wl-1",
            "name": "opentide",
            "description": "opentide detections",
            "timestamp": 1790000000,
            "last_update": 1790000000,
            "report_ids": ["report-other"],
            "classifier": None,
            "alerts_enabled": True,
            "tags_enabled": True,
        },
        "wl-2": {
            "id": "wl-2",
            "name": "empty",
            "description": "",
            "timestamp": 1790000000,
            "last_update": 1790000000,
            "report_ids": [],
            "classifier": None,
            "alerts_enabled": False,
            "tags_enabled": True,
        },
    },
    "reports": {"report-other": OTHER_REPORT},
    "jobs": {},
    "polls": {},
}


def _process(number: int) -> dict[str, Any]:
    return {
        "process_name": "c:\\windows\\system32\\cmd.exe",
        "process_pid": [4000 + number],
        "device_name": f"ws-{number}",
        "device_timestamp": f"2026-10-27T07:5{number}:00.000Z",
        "process_guid": f"ORGKEY01-0000000{number}-00000fa0-00000000-1dc0000000000000",
        "backend_timestamp": f"2026-10-27T07:5{number}:01.000Z",
        "process_hash": ["a" * 64],
        "parent": {"name": "explorer.exe", "pid": 100 + number},
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "cbc-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "cbc-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, payload: object | None) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if body:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self) -> Any:
        raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        return json.loads(raw) if raw else None

    def _serve(self) -> None:
        url = urlsplit(self.path)
        args = parse_qs(url.query)
        body = self._read()
        if self.headers.get("X-Auth-Token") != os.environ["CBC_TOKEN"]:
            self._send(401, {"success": False, "message": "Unauthorized"})
            return
        path = url.path
        if path == WATCHLISTS and self.command == "GET":
            self._send(200, {"results": list(STATE["watchlists"].values())})
            return
        match = re.fullmatch(re.escape(WATCHLISTS) + r"/([^/]+)", path)
        if match:
            watchlist = STATE["watchlists"].get(match.group(1))
            if watchlist is None:
                self._send(404, {"error_code": "NOT_FOUND", "message": "no such watchlist"})
            elif self.command == "PUT":
                watchlist.update(body)
                watchlist["last_update"] = 1790000100
                self._send(200, watchlist)
            else:
                self._send(200, watchlist)
            return
        if path == REPORTS and self.command == "POST":
            number = len(STATE["reports"])
            report = dict(body, id=f"report-{number}")
            STATE["reports"][report["id"]] = report
            self._send(200, report)
            return
        match = re.fullmatch(re.escape(REPORTS) + r"/([^/]+)", path)
        if match:
            report_id = match.group(1)
            report = STATE["reports"].get(report_id)
            if report is None:
                self._send(
                    404, {"error_code": "NOT_FOUND", "message": f"report {report_id} not found"}
                )
            elif self.command == "PUT":
                STATE["reports"][report_id] = dict(body, id=report_id)
                self._send(200, STATE["reports"][report_id])
            elif self.command == "DELETE":
                del STATE["reports"][report_id]
                for watchlist in STATE["watchlists"].values():
                    if report_id in watchlist["report_ids"]:
                        watchlist["report_ids"].remove(report_id)
                self._send(204, None)
            else:
                self._send(200, report)
            return
        if path == f"{PROCESSES}/search_validation":
            query = (body or {}).get("query") or args.get("q", [""])[0]
            if "(" in query:
                self._send(
                    200,
                    {
                        "valid": False,
                        "invalid_message": "unbalanced parenthesis",
                        "value_search_query": False,
                    },
                )
            else:
                self._send(200, {"valid": True, "value_search_query": True})
            return
        if path == f"{PROCESSES}/search_jobs" and self.command == "POST":
            query = body.get("query", "")
            if "denied" in query:
                self._send(
                    403, {"error_code": "FORBIDDEN", "message": "Access denied to process search"}
                )
                return
            job = f"job-{len(STATE['jobs']) + 1}"
            STATE["jobs"][job] = body
            self._send(200, {"job_id": job})
            return
        match = re.fullmatch(re.escape(PROCESSES) + r"/search_jobs/([^/]+)/results", path)
        if match:
            job = STATE["jobs"].get(match.group(1))
            if job is None:
                self._send(404, {"error_code": "NOT_FOUND", "message": "no such job"})
                return
            query = job.get("query", "")
            found = [] if "process_name:x" in query else [_process(n) for n in range(1, 4)]
            rows = int(args.get("rows", ["0"])[0])
            start = int(args.get("start", ["0"])[0])
            if rows == 0:
                polls = STATE["polls"].get(match.group(1), 0)
                STATE["polls"][match.group(1)] = polls + 1
                completed = 0 if "slow" in query or polls == 0 else 5
                self._send(
                    200,
                    {
                        "num_found": len(found),
                        "num_available": len(found),
                        "contacted": 5,
                        "completed": completed,
                        "approximate_unaggregated": len(found),
                        "num_aggregated": len(found),
                        "results": [],
                    },
                )
                return
            self._send(
                200,
                {
                    "num_found": len(found),
                    "num_available": len(found),
                    "contacted": 5,
                    "completed": 5,
                    "approximate_unaggregated": len(found),
                    "num_aggregated": len(found),
                    "results": found[start : start + rows],
                },
            )
            return
        self._send(404, {"error_code": "NOT_FOUND", "message": f"no route {self.command} {path}"})

    do_GET = do_POST = do_PUT = do_DELETE = _serve


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
