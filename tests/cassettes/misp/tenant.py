"""A stand-in MISP instance: the REST API ``opentide share`` speaks (UC-4.4b, #834).

``cargo xtask cassettes record golden/share-*`` starts it on a free loopback port
(printed on the first line of stdout) and routes ``misp.invalid`` to it. It holds:

- the ``opentide`` object template (version 5) and one organisation, the key's;
- the ``mitre-attack-pattern`` cluster of T1059 and the ``threat-actor`` cluster of
  G0006 (found by its ATT&CK reference);
- an event per rule the fixture's ledger says was shared (``…0012``, published, with
  an object of its own beside opentide's; ``…0013``, published), and another
  organisation's event that holds the threat;
- events added from ``events/add`` get ids from 100 and UUIDs ``e1000000-…``.

Every path under ``/locked/`` answers 403, as a MISP whose key was revoked does; a
request without the key ``MISP_API_KEY`` names answers 401. Standard library only;
deterministic answers.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

ORG = "11111111-1111-4111-8111-111111111111"
FOREIGN_ORG = "99999999-9999-4999-8999-999999999999"
TEMPLATE = "892fd46a-f69e-455c-8c4f-843a4b8f4295"
RELATIONS = ["name", "uuid", "version", "opentide-type", "schema", "opentide-object"]


def _opentide_object(uuid: str) -> dict[str, Any]:
    return {
        "id": "1",
        "name": "opentide",
        "template_uuid": TEMPLATE,
        "Attribute": [{"object_relation": "uuid", "value": uuid, "type": "text"}],
    }


EVENTS: dict[str, dict[str, Any]] = {
    "7": {
        "id": "7",
        "uuid": "e0000000-0000-4000-8048-000000000012",
        "Orgc": {"uuid": ORG},
        "published": True,
        "Attribute": [],
        "Object": [
            {"id": "2", "name": "domain-ip", "Attribute": [{"value": "example.org"}]},
            _opentide_object("00000000-0000-4000-8048-000000000012"),
        ],
    },
    "8": {
        "id": "8",
        "uuid": "e0000000-0000-4000-8048-000000000013",
        "Orgc": {"uuid": ORG},
        "published": True,
        "Attribute": [],
        "Object": [_opentide_object("00000000-0000-4000-8048-000000000013")],
    },
    "9": {
        "id": "9",
        "uuid": "e0000000-0000-4000-8048-000000000099",
        "Orgc": {"uuid": FOREIGN_ORG},
        "published": True,
        "Attribute": [],
        "Object": [_opentide_object("00000000-0000-4000-8048-000000000001")],
    },
}

CLUSTERS = {
    "mitre-attack-pattern": [
        {
            "GalaxyCluster": {
                "uuid": "7385dfaf-6886-4229-9ecd-6fd678040830",
                "value": "Command and Scripting Interpreter - T1059",
                "meta": {"external_id": ["T1059"]},
            },
            "Galaxy": {"type": "mitre-attack-pattern"},
        }
    ],
    "threat-actor": [
        {
            "GalaxyCluster": {
                "uuid": "6d2b1b4d-3d3b-4c3a-9d1c-2f5d1b0a6c01",
                "value": "APT1",
                "meta": {
                    "synonyms": ["Comment Crew"],
                    "refs": ["https://attack.mitre.org/groups/G0006/"],
                },
            },
            "Galaxy": {"type": "threat-actor"},
        }
    ],
}


def _uuids(event: dict[str, Any]) -> list[str]:
    return [
        attribute["value"]
        for obj in event.get("Object", [])
        for attribute in obj.get("Attribute", [])
        if attribute.get("object_relation") == "uuid"
    ]


class Handler(BaseHTTPRequestHandler):
    server_version = "misp-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "misp-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read(self) -> Any:
        data = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        return json.loads(data) if data else None

    def _route(self) -> str | None:
        path = urlsplit(self.path).path
        if path.startswith("/locked/"):
            self._json(403, {"name": "Authentication failed.", "message": "Forbidden"})
            return None
        if self.headers.get("Authorization") != os.environ["MISP_API_KEY"]:
            self._json(401, {"name": "Authentication failed.", "message": "Unauthorized"})
            return None
        return path

    def do_GET(self) -> None:
        path = self._route()
        if path is None:
            return
        if path == "/servers/getVersion":
            self._json(200, {"version": "2.5.17"})
        elif path == "/users/view/me":
            self._json(200, {"User": {"id": "1"}, "Organisation": {"uuid": ORG}})
        elif path == f"/objectTemplates/view/{TEMPLATE}":
            elements = [{"object_relation": relation} for relation in RELATIONS]
            elements[3]["values_list"] = ["threat", "objective", "rule"]
            self._json(
                200,
                {"ObjectTemplate": {"version": "5", "ObjectTemplateElement": elements}},
            )
        elif path.startswith("/events/view/"):
            event = EVENTS.get(path.removeprefix("/events/view/"))
            if event is None:
                self._json(404, {"name": "Invalid event", "message": "Invalid event"})
            else:
                self._json(200, {"Event": event})
        else:
            self._json(404, {"name": "Not Found", "message": path})

    def do_POST(self) -> None:
        path = self._route()
        if path is None:
            return
        body = self._read() or {}
        if path == "/galaxy_clusters/restSearch":
            self._json(200, CLUSTERS.get(body.get("galaxy"), []))
        elif path == "/events/restSearch":
            found = [
                {"Event": {"id": event["id"], "uuid": event["uuid"]}}
                for event in EVENTS.values()
                if body.get("value") in _uuids(event)
            ]
            self._json(200, {"response": found})
        elif path == "/events/add":
            number = str(100 + sum(1 for key in EVENTS if int(key) >= 100))
            event = dict(body["Event"])
            event.update(
                id=number,
                uuid=f"e1000000-0000-4000-8048-{int(number):012d}",
                Orgc={"uuid": ORG},
                published=False,
            )
            EVENTS[number] = event
            self._json(200, {"Event": event})
        elif path.startswith("/events/edit/"):
            number = path.removeprefix("/events/edit/")
            if number not in EVENTS:
                self._json(404, {"name": "Invalid event", "message": "Invalid event"})
                return
            event = dict(body["Event"])
            event.update(id=number, Orgc={"uuid": ORG}, published=False)
            EVENTS[number] = event
            self._json(200, {"Event": event})
        elif path.startswith(("/events/publish/", "/events/unpublish/")):
            number = path.rsplit("/", 1)[1]
            EVENTS[number]["published"] = path.startswith("/events/publish/")
            self._json(200, {"saved": True, "success": True, "id": number})
        else:
            self._json(404, {"name": "Not Found", "message": path})

    def do_DELETE(self) -> None:
        path = self._route()
        if path is None:
            return
        number = path.removeprefix("/events/")
        if EVENTS.pop(number, None) is None:
            self._json(404, {"name": "Invalid event", "message": "Invalid event"})
        else:
            self._json(200, {"saved": True, "success": True, "id": number})


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
