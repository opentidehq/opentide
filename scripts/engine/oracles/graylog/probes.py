#!/usr/bin/env python3
"""Record live Graylog verdicts for crates/testdata/oracles/graylog/*.lucene.

Each probe is sent to `POST /api/search/validate` on every server named in
OPENTIDE_GRAYLOG_URLS (comma-separated base URLs, e.g.
`http://127.0.0.1:9000,http://127.0.0.1:9001`), with HTTP Basic
OPENTIDE_GRAYLOG_USER / OPENTIDE_GRAYLOG_PASSWORD (a user name and password,
or an access token and `token`). The verdict is Graylog's `status`: `OK`,
`WARN` (WARNING: an unknown field, a lower-case operator), or `ERR` (ERROR:
Graylog refuses the query, and opentide deploy saves nothing).

The columns of crates/testdata/oracles/graylog/expected.tsv are the servers'
`major.minor` versions (`GET /api/system`). Without `--write`, the run
compares the live verdicts with the file and exits 1 on a difference.
`crates/opentide-lucene/tests/graylog_verdicts.rs` holds the engine to the
file without a server. Standard library only.

Usage:
    OPENTIDE_GRAYLOG_URLS=... OPENTIDE_GRAYLOG_USER=... OPENTIDE_GRAYLOG_PASSWORD=... \\
        python3 -I scripts/engine/oracles/graylog/probes.py [--write]
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
PROBES = ROOT / "testdata" / "oracles" / "graylog"
EXPECTED = PROBES / "expected.tsv"
STATUS = {"OK": "OK", "WARNING": "WARN", "ERROR": "ERR"}


def request(url: str, path: str, auth: str, body: dict | None = None) -> dict:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        url.rstrip("/") + path,
        data=data,
        method="GET" if body is None else "POST",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-By": "opentide",
            "Authorization": f"Basic {auth}",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write", action="store_true", help="rewrite expected.tsv")
    args = parser.parse_args()
    urls = [u for u in os.environ.get("OPENTIDE_GRAYLOG_URLS", "").split(",") if u]
    if not urls:
        print("OPENTIDE_GRAYLOG_URLS is not set: nothing to run", file=sys.stderr)
        return 0
    user = os.environ.get("OPENTIDE_GRAYLOG_USER", "")
    password = os.environ.get("OPENTIDE_GRAYLOG_PASSWORD", "")
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    versions = []
    for url in urls:
        version = request(url, "/api/system", auth)["version"]
        versions.append(".".join(version.split("+")[0].split(".")[:2]))
    probes = sorted(PROBES.glob("*.lucene"))
    lines = ["probe\t" + "\t".join(versions)]
    for probe in probes:
        query = probe.read_text(encoding="utf-8")
        body = {"query": query, "timerange": {"type": "relative", "range": 300}}
        cells = [STATUS[request(url, "/api/search/validate", auth, body)["status"]] for url in urls]
        lines.append(f"{probe.name}\t" + "\t".join(cells))
    rendered = "\n".join(lines) + "\n"
    if args.write:
        EXPECTED.write_text(rendered, encoding="utf-8")
        print(f"wrote {EXPECTED.relative_to(ROOT)} ({len(probes)} probes)")
        return 0
    current = EXPECTED.read_text(encoding="utf-8") if EXPECTED.exists() else ""
    if current != rendered:
        print("live verdicts differ from expected.tsv:", file=sys.stderr)
        old = set(current.splitlines())
        for line in rendered.splitlines():
            if line not in old:
                print(f"  {line}", file=sys.stderr)
        return 1
    print(f"{len(probes)} probes agree with expected.tsv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
