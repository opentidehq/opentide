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


# The rules `generate extract elastic` exports (UC-4.4b), on one page of `_find`.
EXPORTED: list[dict[str, Any]] = [
    {
        "id": "kb-101",
        "rule_id": "7d1c0f00-0000-4000-8000-000000000101",
        "name": 'Encoded PowerShell: "-enc" flag',
        "description": "  PowerShell started with an encoded command.  ",
        "author": ["Elastic", "SOC team"],
        "created_at": "2026-02-03T04:05:06.789Z",
        "updated_at": "2026-03-04T05:06:07.890Z",
        "severity": "high",
        "risk_score": 73,
        "risk_score_mapping": [
            {"field": "event.risk_score", "operator": "equals", "value": "", "risk_score": 50}
        ],
        "severity_mapping": [
            {
                "field": "host.os.type",
                "operator": "equals",
                "value": "windows",
                "severity": "critical",
            }
        ],
        "enabled": True,
        "type": "query",
        "language": "kuery",
        "query": 'process.name : "powershell.exe" and process.args : "-enc"\n',
        "index": ["logs-endpoint.events.process-*", "winlogbeat-*"],
        "interval": "5m",
        "from": "now-9m",
        "max_signals": 100,
        "tags": ["OpenTide", "Domain: Endpoint", "OS: Windows"],
        "threat": [
            {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": "TA0002", "name": "Execution"},
                "technique": [
                    {"id": "T1059", "name": "Command", "subtechnique": [{"id": "T1059.001"}]},
                    {"id": "T1027", "name": "Obfuscated Files or Information"},
                ],
            }
        ],
        "references": ["https://attack.mitre.org/techniques/T1059/001/"],
        "required_fields": [
            {"name": "process.name", "type": "keyword", "ecs": True},
            {"name": "process.args", "type": "unknown", "ecs": True},
        ],
        "related_integrations": [
            {"package": "endpoint", "version": "*"},
            {"package": "windows", "integration": "powershell", "version": "^1.5.0"},
        ],
        "filters": [
            {
                "meta": {
                    "type": "phrase",
                    "key": "host.os.type",
                    "params": {"query": "windows"},
                    "negate": False,
                },
                "$state": {"store": "appState"},
            },
            {
                "meta": {"type": "exists", "key": "user.name", "disabled": True},
                "query": {"exists": {"field": "user.name"}},
            },
        ],
        "investigation_fields": {"field_names": ["user.name", "host.name"]},
        "alert_suppression": {
            "group_by": ["host.name"],
            "duration": {"value": 5, "unit": "m"},
            "missing_fields_strategy": "suppress",
        },
        "note": "## Triage\n\nCheck the parent process.\n",
        "setup": "",
        "false_positives": ["Administrators running scripts"],
        "exceptions_list": [
            {
                "id": "endpoint_list",
                "list_id": "endpoint_list",
                "type": "endpoint",
                "namespace_type": "agnostic",
            },
            {"id": "ex-1", "list_id": "allowlist", "type": "detection"},
        ],
        "actions": [{"id": "slack-connector", "group": "default", "params": {"message": "Alert"}}],
        "response_actions": [
            {"action_type_id": ".endpoint", "params": {"command": "isolate", "comment": "Contain"}},
            {"action_type_id": ".endpoint", "params": {"command": "get-file"}},
            {"action_type_id": ".osquery", "params": {"pack_id": "p1"}},
        ],
        "timeline_id": "db366523-f1c6-4c1f-8731-6ce5ed9e5717",
        "timeline_title": "Generic Endpoint Timeline",
        "building_block_type": "default",
        "immutable": False,
        "rule_source": {"type": "internal"},
    },
    {
        "id": "kb-102",
        "rule_id": "7d1c0f00-0000-4000-8000-000000000102",
        "name": "Process sequence – résumé",
        "description": "A sequence of processes.",
        "author": "Detection team",
        "created_at": "2026-02-03T00:00:00Z",
        "severity": "low",
        "risk_score": 21,
        "enabled": False,
        "type": "eql",
        "language": "eql",
        "query": (
            'sequence by host.id\n  [process where process.name == "cmd.exe"]\n'
            "  [network where true]"
        ),
        "index": ["logs-*"],
        "interval": "1h",
        "from": "now-2w",
        "timestamp_field": "event.ingested",
        "tiebreaker_field": "event.sequence",
        "immutable": False,
    },
    {
        "id": "kb-103",
        "rule_id": "7d1c0f00-0000-4000-8000-000000000103",
        "name": 'Encoded PowerShell: "-enc" flag',
        "description": "Many failed logons from one source.",
        "author": [],
        "severity": "medium",
        "risk_score": 47,
        "enabled": True,
        "type": "threshold",
        "language": "kuery",
        "query": "event.outcome : failure",
        "data_view_id": "dv-logs",
        "interval": "5m",
        "from": "now-3m",
        "threshold": {
            "field": "source.ip",
            "value": 20,
            "cardinality": [{"field": "user.name", "value": 5}],
        },
    },
    {
        "id": "kb-104",
        "rule_id": "7d1c0f00-0000-4000-8000-000000000104",
        "name": "New service name",
        "description": "",
        "severity": "medium",
        "risk_score": 47,
        "enabled": True,
        "type": "new_terms",
        "language": "kuery",
        "query": "event.category : process",
        "index": ["logs-*"],
        "new_terms_fields": ["service.name"],
        "history_window_start": "now-7d",
        "interval": "bogus",
    },
    {
        "id": "kb-105",
        "rule_id": "7d1c0f00-0000-4000-8000-000000000105",
        "name": "ES|QL aggregation",
        "description": "Counts per host.",
        "severity": "critical",
        "risk_score": 99,
        "enabled": True,
        "type": "esql",
        "language": "esql",
        "query": "FROM logs-* | STATS count = COUNT(*) BY host.name | WHERE count > 100",
        "index": ["ignored-*"],
    },
    {
        "id": "kb-106",
        "rule_id": "9a8b7c6d-prebuilt",
        "name": "Prebuilt rule",
        "description": "Shipped by Elastic.",
        "severity": "low",
        "risk_score": 21,
        "type": "query",
        "query": "x : y",
        "immutable": True,
        "rule_source": {"type": "external"},
    },
    {
        "id": "kb-107",
        "rule_id": "legacy-rule-7",
        "name": "Rule with a legacy id",
        "description": "Not a UUID.",
        "severity": "low",
        "risk_score": 21,
        "type": "query",
        "query": "x : y",
    },
]


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
        if path == RULES + "/_find":
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["20"])[0])
            data = EXPORTED[(page - 1) * per_page : page * per_page]
            self._json(
                200, {"page": page, "perPage": per_page, "total": len(EXPORTED), "data": data}
            )
            return
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
