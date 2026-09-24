#!/usr/bin/env python3
"""Print Pydantic object issues for a Tide workspace as JSON.

Each record is `{file, code, field_path, severity}`. Query diagnostics are not
included. Numeric list indexes are stripped so they match LSP field paths.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml
from opentide.models.objective import DetectionObjective
from opentide.models.rule import DetectionRule
from opentide.models.threat import ThreatVector
from opentide.validation.deprecated_fields import walk_deprecated_fields
from opentide.validation.errors import issues_from_pydantic
from pydantic import ValidationError

MODELS = {
    "rule": DetectionRule,
    "objective": DetectionObjective,
    "threat": ThreatVector,
}


def family(payload: dict) -> str:
    meta = payload.get("metadata") or payload.get("meta") or {}
    schema = meta.get("schema") or ""
    return schema.split("::", 1)[0]


def issues_for(path: Path) -> list[dict]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return []
    kind = family(payload)
    model = MODELS.get(kind)
    rows: list[dict] = []
    if model is not None:
        try:
            model.model_validate(payload)
        except ValidationError as exc:
            for issue in issues_from_pydantic(exc, object_type=kind, file_path=path):
                rows.append(
                    {
                        "file": path.name,
                        "code": issue.code,
                        "field_path": [part for part in issue.field_path if not part.isdigit()],
                        "severity": issue.severity,
                    }
                )
    deprecations = json.loads(
        (Path(__file__).resolve().parents[1] / "catalogs/tide/generated/deprecations.json").read_text(
            encoding="utf-8"
        )
    )
    schema: dict = {"properties": {}}
    for row in deprecations["fields"]:
        if row["schema"] != kind:
            continue
        node = schema
        parts = row["path"].split(".")
        for part in parts[:-1]:
            node = node.setdefault("properties", {}).setdefault(part, {"properties": {}})
        node.setdefault("properties", {})[parts[-1]] = {"tide.meta.deprecation": row["message"]}
    for issue in walk_deprecated_fields(payload, schema, object_type=kind):
        rows.append(
            {
                "file": path.name,
                "code": issue.code,
                "field_path": list(issue.field_path),
                "severity": issue.severity,
            }
        )
    return rows


def main() -> None:
    root = Path(sys.argv[1])
    found: list[dict] = []
    for path in sorted(root.rglob("*.yaml")):
        found.extend(issues_for(path))
    json.dump(found, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
