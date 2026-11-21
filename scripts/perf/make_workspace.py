#!/usr/bin/env python3
"""Materialise the editor-latency workspaces from tests/fixtures/tide_corpus.

small: the corpus as the CLI E2E suite lays it out (.opentide/configurations, objects/*).
large: the same, plus the corpus's detection rules copied up to --objects files in total
       (fresh UUIDs and names per copy), like the QA run's 1,000+ object workspace.

    make_workspace.py DEST --objects N      # N = 0: the small workspace
"""

from __future__ import annotations

import argparse
import re
import shutil
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests/fixtures/tide_corpus/current"

LAYOUT = {
    "objects/threats": "Objects/Threat Vectors",
    "objects/objectives": "Objects/Detection Objectives",
    "objects/rules": "Objects/Detection Rules",
}
UUID_LINE = re.compile(r"^(  uuid: )[0-9a-f-]{36}$", re.M)
NAME_LINE = re.compile(r"^name: (.*)$", re.M)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dest", type=Path)
    parser.add_argument("--objects", type=int, default=0, help="total object files (0 = the corpus as is)")
    args = parser.parse_args()
    dest: Path = args.dest
    if dest.exists():
        shutil.rmtree(dest)
    (dest / ".opentide").mkdir(parents=True)
    shutil.copytree(CORPUS / "Configurations", dest / ".opentide/configurations")
    for rel, src in LAYOUT.items():
        shutil.copytree(CORPUS / src, dest / rel)
    rules = sorted((dest / "objects/rules").glob("*.yaml"))
    have = sum(1 for _ in (dest / "objects").rglob("*.yaml"))
    n = 0
    while have < args.objects:
        for rule in rules:
            if have >= args.objects:
                break
            n += 1
            text = rule.read_text(encoding="utf-8")
            new_uuid = uuid.UUID(int=(0x0000_0000_0000_4000_8000_0000_0000_0000 | (n + 1000)))
            text = UUID_LINE.sub(lambda m: m.group(1) + str(new_uuid), text, count=1)
            text = NAME_LINE.sub(lambda m: f"name: {m.group(1)} copy {n}", text, count=1)
            (dest / "objects/rules" / f"copy-{n:05d}-{rule.name}").write_text(text, encoding="utf-8")
            have += 1
    print(f"{dest}: {have} object files")


if __name__ == "__main__":
    main()
