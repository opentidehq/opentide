"""A stand-in Microsoft Defender tenant: Entra ID's token endpoint and Microsoft Graph's beta
custom detection API (RFC 0021, microsoft-defender-1.0).

The recorder starts it on a free loopback port (printed on the first line of stdout) and
routes ``login.microsoftonline.com`` and ``graph.microsoft.com`` to it. It holds custom
detection rules by their client-provided ``id`` (the rule's uuid):

- ``PATCH {base}/{id}`` refuses a query holding ``// refused`` (400), updates a rule it
  holds (200), and answers 404 with no body for an id it does not hold;
- ``POST {base}`` creates the rule under its ``id`` (201), or answers 409 when that id
  exists; the id ``...0000d3`` is created by "another run" when its first ``PATCH``
  answers 404, so its ``POST`` meets the 409;
- ``DELETE {base}/{id}`` deletes a rule (204), or answers 404;
- ``GET {base}`` lists the rules ``generate extract`` imports, in the beta shape, over two
  pages;
- a hunting query returns the columns its ``| project`` names (the default schema
  otherwise); ``whre`` is a syntax error (400), a ``// forbidden`` query a missing
  permission (403), a ``// gateway`` query a proxy's HTML page (502).

Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs

TOKEN = "graph-access-token-for-the-stand-in"
RULES = "/beta/security/rules/detectionRules"
HUNTING = "/beta/security/runHuntingQuery"
DEFAULT_SCHEMA = [
    ("Timestamp", "DateTime"),
    ("DeviceId", "String"),
    ("DeviceName", "String"),
    ("ReportId", "Int64"),
]
# The rules the tenant holds, by id: the golden deploy's update target.
CREATED: dict[str, dict[str, Any]] = {"00000000-0000-4000-8047-0000000000d2": {}}
# Ids another run creates as soon as this run's PATCH has found none.
RACING = {"00000000-0000-4000-8047-0000000000d3"}


def _row(names: list[str], number: int) -> dict[str, Any]:
    values = {
        "Timestamp": f"2026-10-27T07:5{number}:00.0000000Z",
        "DeviceId": f"dev-{number}",
        "DeviceName": f"ws-{number}.contoso.example",
        "ReportId": 1000 + number,
    }
    return {name: values.get(name, f"{name.lower()}-{number}") for name in names}


def _listed(rule_id: str, name: str, **changes: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": rule_id,
        "displayName": name,
        "description": "PowerShell started by an Office application.",
        "status": "enabled",
        "createdBy": "alice@contoso.example",
        "createdDateTime": "2026-01-02T03:04:05.123Z",
        "lastModifiedBy": "alice@contoso.example",
        "lastModifiedDateTime": "2026-02-03T04:05:06Z",
        "queryCondition": {
            "queryText": 'DeviceProcessEvents\n  | where FileName == "powershell.exe"\n'
        },
        "schedule": {"frequency": "PT1H"},
        "detectionAction": {
            "alertTemplate": {
                "title": name,
                "description": (
                    "PowerShell started by an Office application.\nInvestigate the parent."
                ),
                "severity": "high",
                "recommendedActions": None,
                "tactics": [],
                "entityMappings": {"hosts": [{"deviceIdColumn": "DeviceId"}]},
            },
        },
    }
    rule.update(changes)
    return rule


LISTED: list[dict[str, Any]] = [
    _listed(
        "8d7c6b5a-0000-4000-8000-000000000201",
        'Suspicious PowerShell: "encoded" command',
        lastModifiedBy="bob@contoso.example",
        schedule={"frequency": "PT1H", "lookback": "PT4H"},
        detectionAction={
            "alertTemplate": {
                "title": "Encoded PowerShell",
                "description": "An encoded command line.",
                "severity": "medium",
                "recommendedActions": "Isolate the device.\n  Collect the investigation package.",
                "tactics": [
                    {
                        "tactic": "Execution",
                        "techniques": [{"technique": "T1059", "subTechniques": ["T1059.001"]}],
                    },
                    {"tactic": "DefenseEvasion", "techniques": [{"technique": "T1027"}]},
                ],
                "entityMappings": {
                    "hosts": [{"deviceIdColumn": "DeviceId", "nameColumn": "DeviceName"}],
                    "accounts": [{"upnColumn": "AccountUpn"}],
                },
                "customDetails": {"CommandLine": "ProcessCommandLine"},
                "eventGroupingKind": "singleAlert",
            },
            "automatedActions": {
                "isolateDevices": [{"deviceIdColumn": "DeviceId", "isolationType": "full"}]
            },
            "organizationalScope": {"deviceGroups": ["Tier 0"]},
            "incidentConfiguration": {"isExcludedFromIncidentCorrelation": True},
        },
    ),
    _listed(
        "8d7c6b5a-0000-4000-8000-000000000202",
        "Office spawns PowerShell",
        status="disabled",
        schedule={"frequency": "PT0S"},
    ),
    _listed(
        "8d7c6b5a-0000-4000-8000-000000000203",
        "office spawns powershell",
    ),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "defender-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "defender-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: object) -> None:
        self._send(status, json.dumps(payload).encode())

    def _error(self, status: int, code: str, message: str) -> None:
        self._json(status, {"error": {"code": code, "message": message}})

    def _read(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"Bearer {TOKEN}":
            return True
        self._error(401, "InvalidAuthenticationToken", "Access token is empty.")
        return False

    def do_GET(self) -> None:
        # The custom detection rules `generate extract defender` lists (UC-4.4b):
        # two pages, the second through `@odata.nextLink`.
        if not self._authorised():
            return
        if self.path == RULES:
            self._json(
                200,
                {
                    "value": LISTED[:2],
                    "@odata.nextLink": f"https://graph.microsoft.com{RULES}?$skiptoken=2",
                },
            )
        elif self.path == RULES + "?$skiptoken=2":
            self._json(200, {"value": LISTED[2:]})
        else:
            self._error(404, "ResourceNotFound", "no such resource")

    def do_POST(self) -> None:
        if self.path.endswith("/oauth2/v2.0/token"):
            form = parse_qs(self._read().decode())
            secret = form.get("client_secret", [""])[0]
            if secret != os.environ["DEFENDER_CLIENT_SECRET"]:
                self._json(401, {"error": "invalid_client"})
                return
            self._json(
                200,
                {
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "ext_expires_in": 3599,
                    "access_token": TOKEN,
                },
            )
            return
        if not self._authorised():
            return
        body = json.loads(self._read() or b"{}")
        if self.path == RULES:
            remote = body.get("id", "")
            if remote in CREATED:
                self._error(409, "Conflict", f"A rule with id {remote} already exists.")
                return
            CREATED[remote] = body
            self._json(201, body)
            return
        if self.path == HUNTING:
            query = body["Query"]
            if "// forbidden" in query:
                self._error(403, "Forbidden", "Insufficient privileges to complete the operation.")
            elif "// gateway" in query:
                page = b"<html><head><title>502 Bad Gateway</title></head><body></body></html>"
                self._send(502, page, "text/html")
            elif "whre" in query:
                self._error(400, "BadRequest", "Syntax error near 'whre'")
            else:
                project = re.search(r"\|\s*project\s+([^|\n]+)", query)
                if project:
                    names = [name.strip() for name in project.group(1).split(",")]
                    schema = [{"Name": name, "Type": "String"} for name in names]
                else:
                    names = [name for name, _ in DEFAULT_SCHEMA]
                    schema = [{"name": name, "type": kind} for name, kind in DEFAULT_SCHEMA]
                rows = [_row(names, number) for number in (1, 2)]
                key = "Schema" if project else "schema"
                self._json(200, {key: schema, "results": rows})
            return
        self._error(404, "ResourceNotFound", "no such resource")

    def do_PATCH(self) -> None:
        if not self._authorised():
            return
        body = json.loads(self._read() or b"{}")
        remote = self.path.removeprefix(RULES + "/")
        if "// refused" in body.get("queryCondition", {}).get("queryText", ""):
            self._error(400, "BadRequest", "The query is not valid for a custom detection.")
            return
        if remote not in CREATED:
            if remote in RACING:
                # Another run creates it now: this run's POST meets a 409.
                RACING.discard(remote)
                CREATED[remote] = {}
            # Graph's answer to an id it does not know: no body at all.
            self._send(404, b"")
            return
        CREATED[remote] = body
        self._json(200, {"id": remote, **body})

    def do_DELETE(self) -> None:
        if not self._authorised():
            return
        remote = self.path.removeprefix(RULES + "/")
        if CREATED.pop(remote, None) is None:
            self._error(404, "NotFound", f"rule {remote} not found")
            return
        self._send(204, b"")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
