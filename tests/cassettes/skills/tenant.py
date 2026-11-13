"""A stand-in opentidehq/skills repository for the recorded-HTTP harness (UC-4.4d, #834).

``cargo xtask cassettes record skills/install`` (and ``skills/broken``) starts it
on a free loopback port (printed on the first line of stdout) and routes
``raw.githubusercontent.com`` and ``api.github.com`` to it, so the oracle's
``setup skills --install`` reads a small catalogue, the repository's file list
from the trees API and each file of a skill, as it reads the real repository.
Standard library only; deterministic answers.

- ``sample-skill`` ships ``SKILL.md`` and ``references/notes.md``.
- ``broken-skill`` lists ``references/missing.md``, which answers 404: the
  download that fails.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

SOURCE = "opentidehq/skills"

MANIFEST = {
    "version": 1,
    "source": SOURCE,
    "ref": "main",
    "skills": [
        {
            "slug": "sample-skill",
            "name": "Sample skill",
            "description": "A skill with a reference file, for the install cassettes.",
        },
        {
            "slug": "broken-skill",
            "name": "Broken skill",
            "description": "A skill one of whose files cannot be downloaded.",
        },
    ],
}

FILES: dict[str, bytes] = {
    "manifest.json": json.dumps(MANIFEST, indent=2).encode() + b"\n",
    "README.md": b"# skills\n",
    "skills/sample-skill/SKILL.md": (
        b"---\nname: sample-skill\ndescription: A skill with a reference file.\n---\n\n"
        b"# Sample skill\n\nRead [the notes](references/notes.md).\n"
    ),
    "skills/sample-skill/references/notes.md": b"# Notes\n\nCaf\xc3\xa9 \xe2\x80\x94 UTF-8 kept.\n",
    "skills/broken-skill/SKILL.md": b"---\nname: broken-skill\n---\n\n# Broken skill\n",
}

#: Listed in the tree, never served.
MISSING = ("skills/broken-skill/references/missing.md",)


def _tree() -> dict[str, Any]:
    blobs = sorted([*FILES, *MISSING])
    folders = sorted({path.rsplit("/", 1)[0] for path in blobs if "/" in path})
    entries = [{"path": folder, "type": "tree"} for folder in folders]
    entries += [{"path": path, "type": "blob"} for path in blobs]
    return {"sha": "0" * 40, "tree": entries, "truncated": False}


class Handler(BaseHTTPRequestHandler):
    """raw.githubusercontent.com's files and api.github.com's trees API."""

    server_version = "skills-tenant"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def version_string(self) -> str:
        return "skills-tenant"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _answer(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        if parts.path == f"/repos/{SOURCE}/git/trees/main" and parts.query == "recursive=1":
            body = json.dumps(_tree()).encode()
            self._answer(200, body, "application/json; charset=utf-8")
            return
        prefix = f"/{SOURCE}/main/"
        name = parts.path.removeprefix(prefix) if parts.path.startswith(prefix) else None
        if name is not None and name in FILES:
            self._answer(200, FILES[name], "text/plain; charset=utf-8")
            return
        self._answer(404, b"404: Not Found", "text/plain; charset=utf-8")


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sys.stdout.write(f"{server.server_address[1]}\n")
    sys.stdout.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
