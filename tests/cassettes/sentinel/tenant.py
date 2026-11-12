"""A stand-in Microsoft Sentinel tenant (UC-4.3).

Entra ID, Azure Resource Manager and Log Analytics.

``cargo xtask cassettes record sentinel/<scenario>`` starts it on a free loopback port
(printed on the first line of stdout) and routes ``login.microsoftonline.com``,
``management.azure.com`` and ``api.loganalytics.io`` to it. Its answers are the
ones the Python suite mocks (``tests/test_platforms/test_sentinel_deployer.py``,
``test_query_runners.py``):

- Entra ID: the tenant's OpenID configuration, then a token for the client
  credentials (``invalid_client`` for any other secret);
- ARM ``alertRules``: a rule ``PUT`` is created (201) or replaced (200), a
  ``DELETE`` of a rule it does not hold is a 404 with ARM's error body, the list
  comes in two pages (``nextLink``);
- ARM ``alertRules`` of the workspace ``extract``: the analytics rules of
  :data:`EXTRACT_RULES`, listed in two pages, for ``generate extract sentinel``
  (UC-4.4e): scheduled rules with every block the importer writes, a
  near-real-time one, a Fusion rule it skips, and two rules of one name;
- Log Analytics ``query``: one table of the columns a ``| project`` names; a
  ``// partial`` query answers with its rows and an error (a partial result),
  ``// tables`` with two tables, ``whre`` is a syntax error (400) with the parser's
  message nested in ``innererror``, ``// forbidden`` a 403.

Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

TOKEN = "arm-access-token-for-the-stand-in"
LOGIN = "https://login.microsoftonline.com"
RULES: dict[str, dict[str, Any]] = {}
SCHEMA = [
    ("TimeGenerated", "datetime"),
    ("Computer", "string"),
    ("EventID", "int"),
]


EXTRACT_RULES: list[dict[str, Any]] = [
    {
        "kind": "Scheduled",
        "name": "00000000-0000-4000-8044-000000000001",
        "etag": '"0300bf09-0000-0000-0000-5c37296e0001"',
        "properties": {
            "displayName": "Encoded PowerShell \u2014 \u00dcn\u00efcode",
            "description": (
                "A process ran PowerShell with an encoded command.\nSee the runbook: step 1."
            ),
            "severity": "High",
            "enabled": True,
            "query": 'SecurityEvent\n| where CommandLine has "-enc"\n| extend Host = Computer',
            "queryFrequency": "PT1H",
            "queryPeriod": "P1D",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": True,
            "tactics": ["Execution", "DefenseEvasion"],
            "techniques": ["T1059", "T1027"],
            "subTechniques": ["T1059.001", "T1564.003"],
            "customDetails": {"Host": "Computer", "CommandLine": "CommandLine"},
            "entityMappings": [
                {
                    "entityType": "Host",
                    "fieldMappings": [{"identifier": "HostName", "columnName": "Computer"}],
                },
                {
                    "entityType": "Account",
                    "fieldMappings": [
                        {"identifier": "Name", "columnName": "Account"},
                        {"identifier": "NTDomain", "columnName": "Domain"},
                    ],
                },
            ],
            "alertDetailsOverride": {
                "alertDisplayNameFormat": "{{Computer}} ran PowerShell: encoded",
                "alertDescriptionFormat": "PowerShell ran on {{Computer}}.\nCheck the parent.",
                "alertDynamicProperties": [{"alertProperty": "AlertLink", "value": "Link"}],
            },
            "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "Selected",
                    "groupByEntities": ["Host", "Account"],
                    "groupByAlertDetails": ["DisplayName"],
                    "groupByCustomDetails": ["Host"],
                },
            },
            "lastModifiedUtc": "2026-03-04T05:06:07.1234567Z",
            "templateVersion": "1.0.2",
        },
    },
    {
        "kind": "NRT",
        "name": "00000000-0000-4000-8044-000000000002",
        "properties": {
            "displayName": "Sign-in from a new country",
            "description": "  Indented: the first line starts with spaces.\nThe second does not.",
            "severity": "Medium",
            "enabled": False,
            "query": "SigninLogs\n| where ResultType == 0",
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": [],
            "techniques": None,
            "incidentConfiguration": {
                "createIncident": False,
                "groupingConfiguration": {
                    "enabled": False,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "AllEntities",
                },
            },
            "lastModifiedUtc": "2026-05-06T00:00:00Z",
        },
    },
    {
        "kind": "Fusion",
        "name": "00000000-0000-4000-8044-000000000003",
        "properties": {
            "displayName": "Advanced Multistage Attack Detection",
            "enabled": True,
            "alertRuleTemplateName": "f71aba3d-28fb-450b-b192-4e76a83015c8",
            "lastModifiedUtc": "2026-01-01T00:00:00Z",
        },
    },
    {
        "kind": "Scheduled",
        "name": "00000000-0000-4000-8044-000000000004",
        "properties": {
            "displayName": "Encoded PowerShell \u2014 \u00dcn\u00efcode",
            "description": "The same name: written beside the first, its file suffixed.",
            "severity": "Informational",
            "enabled": True,
            "query": "  SecurityEvent\n  | take 1",
            "queryFrequency": "PT30M",
            "queryPeriod": "PT2H",
            "triggerOperator": "Equal",
            "triggerThreshold": 5,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "subTechniques": ["T1003.001"],
            "customDetails": {"1": "yes", "Empty": "", "Path": "C:\\Windows\\Temp"},
            "alertDetailsOverride": {
                "alertDisplayNameFormat": None,
                "alertDescriptionFormat": "  {{Account}} signed in",
                "alertDynamicProperties": [],
            },
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": True,
                    "lookbackDuration": "P1D",
                    "matchingMethod": "AnyAlert",
                    "groupByEntities": [],
                },
            },
            "lastModifiedUtc": "2026-07-08T09:10:11Z",
        },
    },
    {
        "kind": "Scheduled",
        "name": "00000000-0000-4000-8044-000000000005",
        "properties": {
            "displayName": 'Quotes "and" back\\slash: a <name>',
            "description": "Characters a file name cannot hold, and a name that needs quoting.",
            "severity": "Low",
            "enabled": True,
            "query": "AuditLogs",
            "queryFrequency": "P1D",
            "queryPeriod": "P14D",
            "triggerOperator": "LessThan",
            "triggerThreshold": 10,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "alertDetailsOverride": {"alertDisplayNameFormat": "Audit: {{OperationName}}"},
            "eventGroupingSettings": {"aggregationKind": "SingleAlert"},
            "incidentConfiguration": {
                "createIncident": False,
                "groupingConfiguration": {"enabled": False},
            },
            "lastModifiedUtc": "2026-09-10T11:12:13Z",
        },
    },
]


def _extract_rules(path: str) -> list[dict[str, Any]]:
    return [dict(rule, id=f"{path}/{rule['name']}") for rule in EXTRACT_RULES]


def _openid(tenant: str) -> dict[str, Any]:
    base = f"{LOGIN}/{tenant}"
    return {
        "token_endpoint": f"{base}/oauth2/v2.0/token",
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "private_key_jwt",
            "client_secret_basic",
        ],
        "jwks_uri": f"{LOGIN}/{tenant}/discovery/v2.0/keys",
        "response_modes_supported": ["query", "fragment", "form_post"],
        "subject_types_supported": ["pairwise"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "response_types_supported": ["code", "id_token", "code id_token", "id_token token"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "issuer": f"{LOGIN}/{tenant}/v2.0",
        "request_uri_parameter_supported": False,
        "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
        "authorization_endpoint": f"{base}/oauth2/v2.0/authorize",
        "device_authorization_endpoint": f"{base}/oauth2/v2.0/devicecode",
        "http_logout_supported": True,
        "frontchannel_logout_supported": True,
        "end_session_endpoint": f"{base}/oauth2/v2.0/logout",
        "claims_supported": ["sub", "iss", "aud", "exp", "iat"],
        "kerberos_endpoint": f"{base}/kerberos",
        "tenant_region_scope": "EU",
        "cloud_instance_name": "microsoftonline.com",
        "cloud_graph_host_name": "graph.windows.net",
        "msgraph_host": "graph.microsoft.com",
        "rbac_url": "https://pas.windows.net",
    }


def _rows(names: list[str], count: int) -> list[list[Any]]:
    values = {
        "TimeGenerated": "2026-10-27T07:5{n}:00Z",
        "Computer": "ws-{n}.contoso.example",
        "EventID": None,
    }
    rows = []
    for number in range(1, count + 1):
        row = []
        for name in names:
            if name == "EventID":
                row.append(4688 + number)
            else:
                row.append(values.get(name, f"{name.lower()}-{{n}}").format(n=number))
        rows.append(row)
    return rows


class Handler(BaseHTTPRequestHandler):
    server_version = "sentinel-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "sentinel-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(
        self,
        status: int,
        payload: object | None,
        content_type: str = "application/json; charset=utf-8",
    ) -> None:
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        if body:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self) -> bytes:
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def _authorised(self) -> bool:
        if self.headers.get("Authorization") == f"Bearer {TOKEN}":
            return True
        self._send(
            401, {"error": {"code": "AuthenticationFailed", "message": "Authentication failed."}}
        )
        return False

    def _serve(self) -> None:
        url = urlsplit(self.path)
        body = self._read()
        path = url.path
        if path.endswith("/v2.0/.well-known/openid-configuration"):
            self._send(200, _openid(path.split("/")[1]))
            return
        if path.endswith("/oauth2/v2.0/token"):
            form = parse_qs(body.decode())
            if form.get("client_secret", [""])[0] != os.environ["AZURE_CLIENT_SECRET"]:
                self._send(
                    401,
                    {
                        "error": "invalid_client",
                        "error_description": "AADSTS7000215: Invalid client secret provided.",
                        "error_codes": [7000215],
                    },
                )
                return
            self._send(
                200,
                {
                    "token_type": "Bearer",
                    "expires_in": 3599,
                    "ext_expires_in": 3599,
                    "access_token": TOKEN,
                },
            )
            return
        if path == "/common/discovery/instance":
            self._send(
                200,
                {
                    "tenant_discovery_endpoint": (
                        f"{LOGIN}/contoso-tenant-id/v2.0/.well-known/openid-configuration"
                    ),
                    "api-version": "1.1",
                    "metadata": [
                        {
                            "preferred_network": "login.microsoftonline.com",
                            "preferred_cache": "login.windows.net",
                            "aliases": ["login.microsoftonline.com", "login.windows.net"],
                        }
                    ],
                },
            )
            return
        if not self._authorised():
            return
        query = re.search(r"/v1/workspaces/([^/]+)/query$", path)
        if query:
            request = json.loads(body or b"{}")
            text = request.get("query", "")
            if "// forbidden" in text:
                self._send(
                    403,
                    {
                        "error": {
                            "code": "InsufficientAccessError",
                            "message": (
                                "The provided credentials have insufficient access to "
                                "perform the requested operation"
                            ),
                        }
                    },
                )
                return
            if "whre" in text:
                self._send(
                    400,
                    {
                        "error": {
                            "message": "The request had some invalid properties",
                            "code": "BadArgumentError",
                            "correlationId": "00000000-0000-4000-8000-0000000000aa",
                            "innererror": {
                                "code": "SyntaxError",
                                "message": "A recognition error occurred in the query.",
                                "innererror": {
                                    "code": "SYN0002",
                                    "message": "Query could not be parsed at 'whre' on line [1,22]",
                                    "line": 1,
                                    "pos": 22,
                                },
                            },
                        }
                    },
                )
                return
            project = re.search(r"\|\s*project\s+([^|\n]+)", text)
            names = (
                [name.strip() for name in project.group(1).split(",")]
                if project
                else [n for n, _ in SCHEMA]
            )
            kinds = dict(SCHEMA)
            columns = [{"name": name, "type": kinds.get(name, "string")} for name in names]
            take = re.search(r"\|\s*take\s+(\d+)\s*$", text)
            count = min(int(take.group(1)), 3) if take else 3
            table = {"name": "PrimaryResult", "columns": columns, "rows": _rows(names, count)}
            answer: dict[str, Any] = {"tables": [table]}
            if "// tables" in text:
                answer["tables"].append(
                    {
                        "name": "Table_1",
                        "columns": [{"name": "Count", "type": "long"}],
                        "rows": [[3]],
                    }
                )
            if "// partial" in text:
                answer["error"] = {
                    "message": "Response size too large",
                    "code": "PartialError",
                    "details": [
                        {"code": "EngineError", "message": "Query result set exceeded the limit."}
                    ],
                }
            self._send(200, answer)
            return
        rule = re.search(r"/providers/Microsoft\.SecurityInsights/alertRules(?:/([^/]+))?$", path)
        if rule:
            rule_id = rule.group(1)
            if self.command == "PUT" and rule_id:
                created = rule_id not in RULES
                stored = json.loads(body)
                stored["name"] = rule_id
                stored["etag"] = '"0300bf09-0000-0000-0000-5c37296e0000"'
                RULES[rule_id] = stored
                self._send(201 if created else 200, stored)
                return
            if self.command == "DELETE" and rule_id:
                if RULES.pop(rule_id, None) is None:
                    self._send(
                        404,
                        {
                            "error": {
                                "code": "NotFound",
                                "message": f"Alert rule with id '{rule_id}' was not found.",
                            }
                        },
                    )
                    return
                self._send(200, None)
                return
            if self.command == "GET" and not rule_id:
                skip = parse_qs(url.query).get("$skipToken", [""])[0]
                items = [dict(value, id=f"{path}/{key}") for key, value in sorted(RULES.items())]
                if "/workspaces/extract/" in path:
                    items = _extract_rules(path)
                    if not skip:
                        next_link = f"https://management.azure.com{path}?api-version=2025-10-01-preview&$skipToken=page2"
                        self._send(200, {"value": items[:3], "nextLink": next_link})
                    else:
                        self._send(200, {"value": items[3:]})
                    return
                if not skip:
                    next_link = f"https://management.azure.com{path}?api-version=2025-10-01-preview&$skipToken=page2"
                    self._send(200, {"value": items[:1], "nextLink": next_link})
                else:
                    self._send(200, {"value": items[1:]})
                return
        self._send(
            404, {"error": {"code": "NotFound", "message": f"no route {self.command} {path}"}}
        )

    do_GET = do_POST = do_PUT = do_DELETE = _serve


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
