"""A stand-in Elastic Security tenant: Kibana's detection engine and Elasticsearch (UC-4.2).

``cargo xtask cassettes record elastic/<scenario>`` starts it on a free loopback port
(printed on the first line of stdout) and routes ``kibana.elastic.invalid`` and
``es.elastic.invalid`` to it. Its answers are the ones the Python suite mocks
(``tests/test_platforms/test_elastic_client_deployer.py``,
``test_elastic_validation.py``, ``test_query_runners.py``). Kibana's space is ``soc``.

Rules it holds before a deploy: ``...0002`` (a query rule with actions, exceptions and
a timeline to preserve), ``...0003`` (a query rule the deploy turns into EQL),
``...0004`` (a prebuilt rule). Rule ``...000a`` answers 401, as a key without the
privilege does.

Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

KIBANA = "/s/soc/api"
RULES = KIBANA + "/detection_engine/rules"
PREVIEW = RULES + "/preview"
DATA_VIEWS = KIBANA + "/data_views/data_view/"
UUID = "6b2e9c14-7a31-4f58-9d0c-1e8a4b7c00"

STORE: dict[str, dict[str, Any]] = {
    f"{UUID}02": {
        "id": "kb-2",
        "rule_id": f"{UUID}02",
        "type": "query",
        "actions": [{"id": "slack-connector", "group": "default", "params": {}}],
        "exceptions_list": [{"id": "endpoint_list", "list_id": "endpoint_list"}],
        "timeline_id": "db366523-f1c6-4c1f-8731-6ce5ed9e5717",
        "timeline_title": "Generic Endpoint Timeline",
    },
    f"{UUID}03": {"id": "kb-3", "rule_id": f"{UUID}03", "type": "query"},
    f"{UUID}04": {
        "id": "kb-4",
        "rule_id": f"{UUID}04",
        "type": "query",
        "immutable": True,
        "rule_source": {"type": "external", "is_customized": False},
    },
}
DENIED = f"{UUID}0a"
PREVIEWS = 0

FIELD_CAPS = {
    "user.name": {"keyword": {"type": "keyword", "searchable": True, "aggregatable": True}},
    "source.ip": {"ip": {"type": "ip", "searchable": True, "aggregatable": True}},
    "message": {"text": {"type": "text", "searchable": True, "aggregatable": False}},
    "event.created": {"date": {"type": "date", "searchable": True, "aggregatable": True}},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "elastic-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "elastic-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json; charset=utf-8")

    def _es_error(self, status: int, kind: str, reason: str) -> None:
        error = {"root_cause": [{"type": kind, "reason": reason}], "type": kind, "reason": reason}
        self._json(status, {"error": error, "status": status})

    def _read(self) -> Any:
        data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        return json.loads(data) if data else None

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"ApiKey {os.environ['ELASTIC_API_KEY']}":
            return True
        self._json(401, {"statusCode": 401, "error": "Unauthorized", "message": "unauthorized"})
        return False

    def _parts(self) -> tuple[str, dict[str, list[str]]]:
        parts = urlsplit(self.path)
        return parts.path, parse_qs(parts.query)

    def do_GET(self) -> None:
        if not self._authorised():
            return
        path, query = self._parts()
        if path == RULES:
            rule_id = query.get("rule_id", [""])[0]
            if rule_id == DENIED:
                self._json(
                    401,
                    {"statusCode": 401, "error": "Unauthorized", "message": "missing privilege"},
                )
            elif rule_id in STORE:
                self._json(200, STORE[rule_id])
            else:
                message = f'rule_id: "{rule_id}" not found'
                self._json(404, {"message": message, "status_code": 404})
        elif path.startswith(DATA_VIEWS):
            view = path.removeprefix(DATA_VIEWS)
            if view == "dv-logs":
                title = "logs-*,winlogbeat-*"
                self._json(200, {"data_view": {"id": view, "title": title, "name": "Logs"}})
            else:
                message = f"Saved object [index-pattern/{view}] not found"
                self._json(404, {"statusCode": 404, "error": "Not Found", "message": message})
        elif path.startswith("/_resolve/index/"):
            self._json(200, {"indices": [], "aliases": [], "data_streams": []})
        elif path.endswith("/_field_caps"):
            sources = unquote(path.removesuffix("/_field_caps").lstrip("/"))
            fields = query.get("fields", [""])[0].split(",")
            if sources.startswith("empty-"):
                self._json(200, {"indices": [], "fields": {}})
                return
            found = {name: FIELD_CAPS[name] for name in fields if name in FIELD_CAPS}
            self._json(200, {"indices": sources.split(","), "fields": found})
        else:
            self._json(404, {"message": "no such resource"})

    def do_POST(self) -> None:
        global PREVIEWS
        if not self._authorised():
            return
        path, _ = self._parts()
        body = self._read()
        if path == RULES:
            rule_id = body.get("rule_id", "")
            STORE[rule_id] = {"id": f"kb-{len(STORE) + 1}", **body}
            self._json(200, STORE[rule_id])
        elif path == PREVIEW:
            PREVIEWS += 1
            query = str(body.get("query") or "")
            if "::" in query:
                logs = [{"errors": ["Expected AND but found ':'"], "warnings": []}]
                self._json(200, {"previewId": f"p-{PREVIEWS}", "logs": logs, "isAborted": False})
            elif "bad-schema" in query:
                self._json(
                    400, {"statusCode": 400, "error": "Bad Request", "message": "[from]: bad"}
                )
            else:
                logs = [{"errors": [], "warnings": ["the rule matched no index yet"]}]
                self._json(200, {"previewId": f"p-{PREVIEWS}", "logs": logs, "isAborted": False})
        elif path == "/_query":
            self._esql(str(body.get("query") or ""))
        elif path.endswith("/_eql/search"):
            events = [
                {"_index": "logs-1", "_source": {"process": {"name": "cmd.exe"}}},
                {"_index": "logs-1", "_source": {"process": {"name": "whoami.exe"}}},
            ]
            hits = {"total": {"value": 1, "relation": "eq"}, "sequences": [{"events": events}]}
            self._json(200, {"is_partial": False, "timed_out": False, "hits": hits})
        elif path.startswith("/.preview.alerts-security.alerts-"):
            source = {
                "@timestamp": "2026-10-27T07:58:00.000Z",
                "process": {"name": "powershell.exe", "pid": 4242},
                "kibana": {"alert": {"rule": {"uuid": "p-1"}}},
                "signal": {"rule": {"id": "p-1"}},
            }
            hit = {"_index": ".internal.preview.alerts-security.alerts-soc", "_source": source}
            self._json(200, {"timed_out": False, "hits": {"total": {"value": 1}, "hits": [hit]}})
        elif path.endswith("/_search"):
            index = unquote(path.removesuffix("/_search").lstrip("/"))
            if index.startswith("broken-"):
                page = b"<!DOCTYPE html><html><head><title>Gateway Timeout</title></head></html>"
                self._send(504, page, "text/html")
                return
            hits = [
                {"_index": "logs-1", "_source": {"process": {"name": "cmd.exe"}, "tags": ["a"]}},
                {"_index": "logs-2", "_source": {"process": {"name": "cmd.exe"}, "host": {}}},
            ]
            self._json(200, {"timed_out": False, "hits": {"total": {"value": 7}, "hits": hits}})
        else:
            self._json(404, {"message": "no such resource"})

    def _esql(self, query: str) -> None:
        if "parse error" in query:
            self._es_error(400, "parsing_exception", "line 1:20: mismatched input 'error'")
        elif "FROM missing-" in query:
            self._es_error(400, "verification_exception", "Unknown index [missing-*]")
        elif "FROM nope" in query:
            self._es_error(400, "verification_exception", "Unknown index [nope]")
        else:
            columns = [
                {"name": "host.name", "type": "keyword"},
                {"name": "user.name", "type": "keyword"},
            ]
            values = [] if "LIMIT 0" in query else [["ws-1", "alice"], ["ws-2", "bob"]]
            self._json(200, {"columns": columns, "values": values, "is_partial": False})

    def do_PUT(self) -> None:
        if not self._authorised():
            return
        _, query = self._parts()
        body = self._read()
        rule_id = query.get("rule_id", [""])[0]
        if rule_id not in STORE:
            self._json(404, {"message": f'rule_id: "{rule_id}" not found', "status_code": 404})
            return
        STORE[rule_id] = {"id": STORE[rule_id]["id"], **body}
        self._json(200, STORE[rule_id])

    def do_DELETE(self) -> None:
        if not self._authorised():
            return
        _, query = self._parts()
        rule_id = query.get("rule_id", [""])[0]
        if STORE.pop(rule_id, None) is None:
            self._json(404, {"message": f'rule_id: "{rule_id}" not found', "status_code": 404})
            return
        self._json(200, {"rule_id": rule_id})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
