"""A stand-in Graylog tenant for the recorded-HTTP scenarios (graylog-1.0).

``cargo xtask cassettes record graylog/...`` starts it on a free loopback port
(printed on the first line of stdout) and routes ``graylog-tenant.invalid`` and
``graylog-63.invalid`` to it. It answers the calls the Python client makes:

- ``GET /api/system``: the version, ``7.2.2+94adc86`` by default and
  ``6.3.5+eaa4b5d`` for a request whose ``Host`` is ``graylog-63.invalid``, so
  one recording covers both body shapes.
- ``POST /api/search/validate``: ``OK`` for most queries, one ``WARNING``
  explanation for a query naming the field ``unknown_field``, and ``ERROR`` for
  a query with an unbalanced ``(``.
- ``POST /api/events/definitions?schedule=true``: creates a definition and
  answers its 24-hex id; the title ``Unconfirmed`` answers a proxy's HTML page
  with 200, and ``Refused`` a 400 with ``errors``.
- ``PUT``/``DELETE /api/events/definitions/{id}``: the definition's update,
  with ``?schedule=false`` for a disablement; an id that is not held is a 404,
  the id ending ``f0ff`` is immutable, and a ``DELETE`` of the id ending
  ``inuse`` is refused as in use.
- ``POST /api/search/messages``: two messages, the newest first, with the
  fields the body asks for.

``POST /__stand-in/reset`` forgets every definition, as a fresh start would.
Standard library only; deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qsl, urlsplit

SYSTEM = "/api/system"
VALIDATE = "/api/search/validate"
MESSAGES = "/api/search/messages"
DEFINITIONS = "/api/events/definitions"
RESET = "/__stand-in/reset"

#: The host that runs Graylog 6.3, so one recording holds both body shapes.
OLD_HOST = "graylog-63.invalid"
VERSIONS = {OLD_HOST: "6.3.5+eaa4b5d"}
DEFAULT_VERSION = "7.2.2+94adc86"

#: The ids the stand-in hands out, in order.
IDS = [
    "65f1c0de2a3b4c5d6e7f8091",
    "65f1c0de2a3b4c5d6e7f8092",
    "65f1c0de2a3b4c5d6e7f8093",
]
#: Held definitions, by id.
DEFINITIONS_HELD: dict[str, dict[str, Any]] = {}

#: A message the search answers with, newest first.
MESSAGES_HELD: list[dict[str, Any]] = [
    {
        "timestamp": "2026-10-26T09:00:00.000Z",
        "source": "ws-01",
        "message": "powershell.exe -enc ZQBj",
        "EventID": "1",
    },
    {
        "timestamp": "2026-10-26T08:30:00.000Z",
        "source": "ws-02",
        "message": "powershell.exe -encodedcommand ZQBj",
        "EventID": "1",
    },
]


class Handler(BaseHTTPRequestHandler):
    """Graylog's system, search and event-definition APIs."""

    server_version = "graylog-stand-in"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "graylog-stand-in"

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
        """HTTP Basic ``<token>:token``, as Graylog takes an access token."""
        import base64

        token = os.environ["GRAYLOG_TOKEN"]
        expected = base64.b64encode(f"{token}:token".encode()).decode()
        if self.headers.get("Authorization") == f"Basic {expected}":
            return True
        self._answer(401, {"message": "Invalid credentials.", "type": "ApiError"})
        return False

    def _definition(self, body: dict[str, Any]) -> dict[str, Any]:
        """The definition of a create body: 6.3 sends it flat, 7.x under ``entity``."""
        entity = body.get("entity")
        return entity if isinstance(entity, dict) else body

    def do_GET(self) -> None:
        if urlsplit(self.path).path != SYSTEM:
            self._answer(404, {"message": "Not found."})
            return
        if not self._authorised():
            return
        host = (self.headers.get("Host") or "").split(":")[0]
        self._answer(
            200,
            {
                "facility": "graylog-server",
                "hostname": host or "graylog",
                "version": VERSIONS.get(host, DEFAULT_VERSION),
                "is_processing": True,
            },
        )

    def do_POST(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == RESET:
            DEFINITIONS_HELD.clear()
            self._answer(200, {"reset": True})
            return
        if not self._authorised():
            return
        body = self._body()
        if parts.path == VALIDATE:
            self._verdict(str(body.get("query") or ""))
            return
        if parts.path == MESSAGES:
            self._search(body)
            return
        if parts.path == DEFINITIONS:
            self._create(body, dict(parse_qsl(parts.query)))
            return
        self._answer(404, {"message": "Not found."})

    def _verdict(self, query: str) -> None:
        if query.count("(") != query.count(")"):
            self._answer(
                200,
                {
                    "status": "ERROR",
                    "explanations": [
                        {
                            "error_type": "QUERY_PARSING_ERROR",
                            "error_title": "Cannot parse query",
                            "error_message": "incomplete query, expected `)`",
                            "begin_line": 1,
                            "begin_column": len(query),
                            "end_line": 1,
                            "end_column": len(query) + 1,
                        }
                    ],
                },
            )
            return
        if "unknown_field" in query:
            self._answer(
                200,
                {
                    "status": "WARNING",
                    "explanations": [
                        {
                            "error_type": "UNKNOWN_FIELD",
                            "error_title": "Unknown field",
                            "error_message": "Unknown field: unknown_field",
                            "begin_line": 1,
                            "begin_column": 0,
                            "end_line": 1,
                            "end_column": 13,
                        }
                    ],
                },
            )
            return
        self._answer(200, {"status": "OK", "explanations": []})

    def _search(self, body: dict[str, Any]) -> None:
        asked = body.get("fields")
        fields = (
            [str(field) for field in asked]
            if isinstance(asked, list)
            else ["timestamp", "source", "message", "EventID"]
        )
        size = body.get("size")
        limit = size if isinstance(size, int) and size > 0 else len(MESSAGES_HELD)
        rows = [[message.get(field, "-") for field in fields] for message in MESSAGES_HELD[:limit]]
        self._answer(
            200,
            {
                "schema": [
                    {"field": field, "type": "date" if field == "timestamp" else "string"}
                    for field in fields
                ],
                "datarows": rows,
                "metadata": {"effective_timerange": body.get("timerange")},
            },
        )

    def _create(self, body: dict[str, Any], query: dict[str, str]) -> None:
        definition = self._definition(body)
        title = str(definition.get("title") or "")
        if query.get("schedule") != "true":
            self._answer(400, {"message": "A create schedules the definition."})
            return
        if "Refused" in title:
            self._answer(
                400,
                {
                    "message": "Validation failed",
                    "errors": {"config.query": ["Query is not valid"]},
                    "type": "ApiError",
                },
            )
            return
        if "Unconfirmed" in title:
            # A proxy's page with 200: the definition may exist, with an id
            # opentide does not learn.
            self._answer(
                200,
                None,
                text="<html><head><title>Saved</title></head><body>ok</body></html>",
            )
            return
        definition_id = IDS[len(DEFINITIONS_HELD) % len(IDS)]
        DEFINITIONS_HELD[definition_id] = definition
        self._answer(201, {"id": definition_id, **definition})

    def do_PUT(self) -> None:
        if not self._authorised():
            return
        parts = urlsplit(self.path)
        definition_id = parts.path[len(DEFINITIONS) :].strip("/")
        body = self._body()
        if not parts.path.startswith(f"{DEFINITIONS}/") or not definition_id:
            self._answer(404, {"message": "Not found."})
            return
        if definition_id.endswith("f0ff"):
            self._answer(400, {"message": "Immutable entity cannot be modified"})
            return
        if definition_id not in DEFINITIONS_HELD:
            self._answer(404, {"message": "Event definition not found"})
            return
        DEFINITIONS_HELD[definition_id] = body
        self._answer(200, {"id": definition_id, **body})

    def do_DELETE(self) -> None:
        if not self._authorised():
            return
        parts = urlsplit(self.path)
        definition_id = parts.path[len(DEFINITIONS) :].strip("/")
        if not parts.path.startswith(f"{DEFINITIONS}/") or not definition_id:
            self._answer(404, {"message": "Not found."})
            return
        if definition_id.endswith("inuse"):
            self._answer(
                409,
                {"message": "The event definition is in use by a notification", "type": "ApiError"},
            )
            return
        DEFINITIONS_HELD.pop(definition_id, None)
        self._answer(204, None)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
