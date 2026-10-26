#!/usr/bin/env python3
"""Generate catalogs/ecs/fields.json from an elastic/ecs checkout.

Reads generated/ecs/ecs_flat.yml (Elastic Common Schema, Apache-2.0) and
writes one row per field: name, Elasticsearch type, ECS level, whether the
field holds an array, the short description, an example, and the allowed
values with the first sentence of each value's description. Multi-fields
such as `process.command_line.text` get their own rows.

ECS is Apache-2.0, so its short descriptions are kept, with attribution in
catalogs/ecs/NOTICE.

The ES|QL, EQL, kuery, and Lucene engines never treat this list as closed:
elastic-1.0 says field names MUST NOT be checked against one. It feeds
completion, hover, and hints where a field's type is known.

Usage:
    python scripts/sync_ecs_fields.py --ecs ../ecs
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path

import yaml


def first_sentence(text: str) -> str:
    text = " ".join((text or "").split())
    match = re.match(r"(.+?[.!?])(\s|$)", text)
    return match.group(1) if match else text


def rows(flat: dict) -> list[dict]:
    out = []
    for name, field in sorted(flat.items()):
        row = {
            "name": name,
            "type": field.get("type", ""),
            "level": field.get("level", ""),
            "short": " ".join((field.get("short") or "").split()),
        }
        if "array" in (field.get("normalize") or []):
            row["array"] = True
        example = field.get("example")
        if example not in (None, ""):
            row["example"] = str(example)
        allowed = field.get("allowed_values") or []
        if allowed:
            row["allowed"] = [
                {"name": v["name"], "short": first_sentence(v.get("description", ""))}
                for v in allowed
            ]
        out.append(row)
        for multi in field.get("multi_fields") or []:
            out.append(
                {
                    "name": multi["flat_name"],
                    "type": multi.get("type", ""),
                    "level": field.get("level", ""),
                    "short": f"`{multi.get('type', '')}` multi-field of `{name}`.",
                }
            )
    out.sort(key=lambda r: r["name"])
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecs", type=Path, required=True)
    parser.add_argument(
        "--out", type=Path, default=Path(__file__).resolve().parent.parent / "catalogs/ecs"
    )
    args = parser.parse_args()
    ecs = args.ecs.resolve()
    commit = subprocess.run(
        ["git", "-C", str(ecs), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    tag = subprocess.run(
        ["git", "-C", str(ecs), "describe", "--tags", "--exact-match"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    flat = yaml.safe_load((ecs / "generated/ecs/ecs_flat.yml").read_text())
    fields = rows(flat)
    args.out.mkdir(parents=True, exist_ok=True)
    doc = {"source": f"elastic/ecs@{commit}", "tag": tag, "fields": fields}
    (args.out / "fields.json").write_text(
        json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n"
    )
    print(f"elastic/ecs@{commit} ({tag or 'untagged'}): {len(fields)} fields")


if __name__ == "__main__":
    main()
