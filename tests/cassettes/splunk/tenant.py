"""A stand-in Splunk management port (UC-4.3).

``cargo xtask cassettes record splunk/<scenario>`` starts it on a free loopback port
(printed on the first line of stdout) and routes ``splunk.invalid`` to it. Its answers
are the ones the Python suite's Splunk stand-in gives (``tests/splunk_support.py``) and
its mocks (``tests/test_platforms/test_query_runners.py``):

- ``server/info``: Splunk 9.3.0, so splunklib takes the v2 search endpoints;
- ``saved/searches``: an Atom feed per saved search, 404 for one it does not hold;
  an argument the REST handler does not know is refused (400);
- ``search/v2/jobs`` (``exec_mode=oneshot``): rows as JSON; ``badcommand`` is a
  refusal (400, ``FATAL``), ``errors`` an answer carrying an ``ERROR`` message,
  ``missing_index`` a ``WARN``, ``gateway`` a gateway's HTML page (502);
- ``search/v2/parser``: ``|badcommand`` is a parse error (400), ``|unreachable`` the
  gateway's 307 ``Network Error``, ``|gateway`` a gateway's 504 page.

Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

SAVED_SEARCHES = "/servicesNS/nobody/search/saved/searches"
SERVER_INFO = "/services/server/info"
JOBS = "/servicesNS/nobody/search/search/v2/jobs"
PARSER = "/servicesNS/nobody/search/search/v2/parser"
#: savedsearches.conf spellings the saved/searches REST handler refuses.
CONF_ONLY_ARGUMENTS = frozenset({"counttype", "relation", "quantity"})
GATEWAY_TIMEOUT_PAGE = (
    b"<html><head><title>504 Gateway Time-out</title></head>"
    b"<body><center><h1>504 Gateway Time-out</h1></center></body></html>"
)
BAD_GATEWAY_PAGE = b"<html><head><title>502 Bad Gateway</title></head><body></body></html>"
SAVED: dict[str, dict[str, str]] = {}


def _entry(name: str, content: dict[str, str]) -> str:
    keys = "".join(f'<s:key name="{key}">{value}</s:key>' for key, value in content.items())
    path = f"{SAVED_SEARCHES}/{urllib.parse.quote(name)}"
    return (
        f"<entry><title>{name}</title><id>https://splunk.invalid:8089{path}</id>"
        f'<link href="{path}" rel="alternate"/>'
        f'<content type="text/xml"><s:dict>{keys}'
        '<s:key name="eai:acl"><s:dict><s:key name="app">search</s:key>'
        '<s:key name="owner">nobody</s:key><s:key name="sharing">app</s:key>'
        "</s:dict></s:key></s:dict></content></entry>"
    )


def _feed(*entries: str) -> bytes:
    return (
        '<feed xmlns="http://www.w3.org/2005/Atom" xmlns:s="http://dev.splunk.com/ns/rest">'
        + "".join(entries)
        + "</feed>"
    ).encode()


def _rows(count: int) -> list[dict[str, Any]]:
    return [
        {"_time": f"2026-10-27T07:5{n}:00.000+00:00", "host": f"ws-{n}", "count": str(n)}
        for n in range(1, count + 1)
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "splunk-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "splunk-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _reply(self, status: int, body: bytes, content_type: str = "text/xml") -> None:
        self.send_response(status)
        if body or status != 404:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._reply(status, json.dumps(payload).encode(), "application/json; charset=UTF-8")

    def _serve(self) -> None:
        url = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode() if length else url.query
        args = dict(urllib.parse.parse_qsl(raw, keep_blank_values=True))
        path = urllib.parse.unquote_plus(url.path).rstrip("/")
        if self.headers.get("Authorization") != f"Splunk {os.environ['SPLUNK_TOKEN']}":
            self._reply(
                401,
                b'<response><messages><msg type="WARN">call not properly '
                b"authenticated</msg></messages></response>",
            )
            return
        if path == SERVER_INFO:
            info = {"version": "9.3.0", "instance_type": "download", "serverName": "stand-in"}
            self._reply(200, _feed(_entry("server-info", info)))
            return
        if path == PARSER:
            query = args.get("q", "")
            if "|unreachable" in query:
                self._reply(307, b"Network Error", "text/plain")
            elif "|gateway" in query:
                self._reply(504, GATEWAY_TIMEOUT_PAGE, "text/html")
            elif "|badcommand" in query:
                self._json(
                    400,
                    {
                        "messages": [
                            {"type": "FATAL", "text": "Unknown search command 'badcommand'."}
                        ]
                    },
                )
            else:
                self._json(200, {"commands": [{"command": "search", "rawargs": query}]})
            return
        if path == JOBS:
            query = args.get("search", "")
            if "gateway" in query:
                self._reply(502, BAD_GATEWAY_PAGE, "text/html")
            elif "badcommand" in query:
                self._json(
                    400,
                    {
                        "messages": [
                            {"type": "FATAL", "text": "Unknown search command 'badcommand'."}
                        ]
                    },
                )
            elif "errors" in query:
                self._json(
                    200,
                    {
                        "messages": [
                            {
                                "type": "ERROR",
                                "text": (
                                    "Error in 'lookup' command: "
                                    "The lookup table 'x' does not exist."
                                ),
                            }
                        ],
                        "results": [],
                    },
                )
            elif "missing_index" in query:
                self._json(
                    200,
                    {
                        "fields": [{"name": "_time"}, {"name": "host"}],
                        "messages": [
                            {
                                "type": "WARN",
                                "text": (
                                    "Search filters specified using splunk_server/"
                                    "splunk_server_group do not match any search peer."
                                ),
                            },
                            {"type": "INFO", "text": "Your timerange was substituted"},
                        ],
                        "results": [],
                    },
                )
            elif "nofields" in query:
                self._json(
                    200, {"results": [{"host": "ws-1", "b": "1"}, {"a": "x", "host": "ws-2"}]}
                )
            else:
                count = int(args.get("count") or 0)
                self._json(
                    200,
                    {
                        "preview": False,
                        "init_offset": 0,
                        "messages": [],
                        "fields": [{"name": "_time"}, {"name": "host"}, {"name": "count"}],
                        "results": _rows(min(count, 3)),
                    },
                )
            return
        if not path.startswith(SAVED_SEARCHES):
            self._reply(404, b"")
            return
        name = path.removeprefix(SAVED_SEARCHES).removeprefix("/")
        if self.command == "POST":
            refused = sorted(set(args) & CONF_ONLY_ARGUMENTS)
            if refused:
                message = f'Argument "{refused[0]}" is not supported by this handler.'
                body = (
                    f'<response><messages><msg type="ERROR">{message}</msg></messages></response>'
                )
                self._reply(400, body.encode())
                return
            if not name:
                name = args.pop("name")
                SAVED[name] = {}
                status = 201
            elif name not in SAVED:
                self._reply(404, b"")
                return
            else:
                status = 200
            SAVED[name].update(args)
            self._reply(status, _feed(_entry(name, SAVED[name])))
            return
        if self.command == "DELETE":
            if SAVED.pop(name, None) is None:
                self._reply(404, b"")
                return
            self._reply(200, _feed())
            return
        if name in SAVED:
            self._reply(200, _feed(_entry(name, SAVED[name])))
            return
        self._reply(
            404,
            b'<?xml version="1.0" encoding="UTF-8"?>\n<response>\n  <messages>\n'
            b'    <msg type="ERROR">Could not find object id=absent</msg>\n  </messages>\n'
            b"</response>\n",
        )

    do_GET = do_POST = do_DELETE = _serve


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
