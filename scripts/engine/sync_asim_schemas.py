#!/usr/bin/env python3
"""Generate catalogs/kql/asim/asim.json from an Azure/Azure-Sentinel checkout.

Microsoft Sentinel's Advanced Security Information Model (ASIM) normalizes
sources to schemas (Network Session, DNS, Authentication, ...). Two files in
Azure-Sentinel (MIT) describe it in machine-readable form:

- ASIM/dev/ASimTester/ASimTester.csv: every schema field with its type and
  class (Mandatory, Recommended, Optional, Conditional, Alias). Rows of the
  `Common` schema are the common fields every schema has.
- Parsers/ASim*/Parsers/*.yaml: every ASIM parser: its workspace name
  (`ASimNetworkSession`, `imNetworkSession`, `vimNetworkSessionAzureFirewall`),
  its built-in name (`_ASim_NetworkSession`, `_Im_NetworkSession`,
  `_Im_NetworkSession_AzureFirewall`), the schema it normalizes to, its
  filtering parameters (`starttime`, `srcipaddr_has_any_prefix`, ...) and
  the source parsers a unifying parser calls.

The catalog keeps the facts: names, types, classes, parameters with their
type and default, and each schema's documentation link from its parser.

Usage (a sparse checkout is enough):
    git clone --depth 1 --filter=blob:none --sparse https://github.com/Azure/Azure-Sentinel.git
    git -C Azure-Sentinel sparse-checkout set --no-cone \\
        /ASIM/dev/ASimTester/ '/Parsers/ASim*/' /LICENSE
    python scripts/sync_asim_schemas.py --sentinel Azure-Sentinel
    python scripts/sync_asim_schemas.py --sentinel Azure-Sentinel --check
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "catalogs/kql/asim/asim.json"
TESTER = Path("ASIM/dev/ASimTester/ASimTester.csv")
TYPES = {
    "string": "string",
    "datetime": "datetime",
    "int": "int",
    "long": "long",
    "real": "real",
    "double": "real",
    "bool": "bool",
    "boolean": "bool",
    "dynamic": "dynamic",
    "guid": "guid",
    "timespan": "timespan",
}
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def kusto_type(raw: str, where: str) -> str:
    kind = raw.strip().lower()
    if kind not in TYPES:
        raise SystemExit(f"{where}: unknown type {raw!r}")
    return TYPES[kind]


def read_schemas(sentinel: Path) -> dict[str, dict]:
    rows: dict[str, dict[str, list[str]]] = {}
    common: dict[str, list[str]] = {}
    with (sentinel / TESTER).open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            column = row["ColumnName"].strip()
            schema = row["Schema"].strip()
            if not NAME.fullmatch(column) or not schema:
                continue
            entry = [column, kusto_type(row["ColumnType"], f"{schema}.{column}"), row["Class"].strip()]
            target = common if schema == "Common" else rows.setdefault(schema, {})
            target[column] = entry
    schemas = {}
    for schema, columns in rows.items():
        merged = {**common, **columns}
        schemas[schema] = {"columns": sorted(merged.values(), key=lambda c: c[0].lower())}
    return schemas


def read_parsers(sentinel: Path, schemas: dict[str, dict]) -> list[dict]:
    parsers: dict[str, dict] = {}

    def add(name: str, schema: str, params: list[dict], unifying: bool) -> None:
        name = name.strip()
        if not NAME.fullmatch(name):
            return
        current = parsers.get(name)
        if current is None or (params and not current["params"]):
            parsers[name] = {
                "name": name,
                "schema": schema,
                "params": params,
                **({"unifying": True} if unifying else {}),
            }

    for path in sorted(sentinel.glob("Parsers/ASim*/Parsers/*.yaml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
        if not isinstance(doc, dict):
            continue
        schema = str((doc.get("Normalization") or {}).get("Schema") or "").strip()
        if schema not in schemas:
            continue
        for ref in doc.get("References") or []:
            link = str(ref.get("Link") or "")
            if re.search(r"aka\.ms/ASim\w+Doc$", link):
                schemas[schema].setdefault("citation", link)
        params = []
        for param in doc.get("ParserParams") or []:
            if not isinstance(param, dict) or not NAME.fullmatch(str(param.get("Name", ""))):
                continue
            item = {"name": str(param["Name"]), "type": kusto_type(str(param.get("Type", "")), str(path))}
            if param.get("Default") is not None:
                item["default"] = str(param["Default"])
            params.append(item)
        callees = [str(p).strip() for p in doc.get("Parsers") or []]
        unifying = bool(callees)
        for key in ("ParserName", "EquivalentBuiltInParser"):
            if doc.get(key):
                add(str(doc[key]), schema, params, unifying)
        # A unifying parser names the source parsers it calls.
        for callee in callees:
            add(callee, schema, [], False)
    return sorted(parsers.values(), key=lambda p: p["name"].lower())


def generate(sentinel: Path) -> dict:
    commit = subprocess.run(
        ["git", "-C", str(sentinel), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    schemas = read_schemas(sentinel)
    parsers = read_parsers(sentinel, schemas)
    return {
        "source": "Azure/Azure-Sentinel ASIM/dev/ASimTester/ASimTester.csv and Parsers/ASim*/Parsers",
        "commit": commit,
        "license": "MIT",
        "generator": "scripts/sync_asim_schemas.py",
        "schemas": dict(sorted(schemas.items())),
        "parsers": parsers,
    }


def dump(payload: dict) -> str:
    head = {k: v for k, v in payload.items() if k not in ("schemas", "parsers")}
    lines = ["{"]
    for key, value in head.items():
        lines.append(f"  {json.dumps(key)}: {json.dumps(value, ensure_ascii=False)},")
    lines.append('  "schemas": {')
    lines.append(
        ",\n".join(
            f"    {json.dumps(name)}: {json.dumps(schema, separators=(',', ':'))}"
            for name, schema in payload["schemas"].items()
        )
    )
    lines.append("  },")
    lines.append('  "parsers": [')
    lines.append(
        ",\n".join(
            "    " + json.dumps(p, ensure_ascii=False, separators=(",", ":")) for p in payload["parsers"]
        )
    )
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--sentinel", type=Path, required=True, help="Azure-Sentinel checkout")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--check", action="store_true", help="fail if the catalog is stale")
    args = parser.parse_args()
    text = dump(generate(args.sentinel.resolve()))
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} is stale; rerun without --check", file=sys.stderr)
            return 1
        return 0
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8")
    payload = json.loads(text)
    print(f"wrote {args.out}: {len(payload['schemas'])} schemas, {len(payload['parsers'])} parsers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
