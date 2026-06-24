"""Export object version snapshot to ``.opentide/exports/revisions.export.json``."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from opentide.core.registry import OpenTide


def build_revisions_export() -> dict[str, Any]:
    """Snapshot current object metadata versions (git remains source of history)."""
    OpenTide.initialise()
    export: dict[str, Any] = {}
    object_names = OpenTide.Configurations.Documentation.object_names
    for object_type in OpenTide.Configurations.Global.objects:
        for uuid, body in OpenTide.Models.Index.get(object_type, {}).items():
            metadata = body.get("metadata") or {}
            version = str(metadata.get("version", ""))
            if not version:
                continue
            entry = export.setdefault(
                uuid,
                {
                    "name": body.get("name", ""),
                    "object": object_names.get(object_type, object_type),
                    "description": _description(body, object_type),
                    "versions": {},
                },
            )
            entry["versions"][version] = {
                "schema": metadata.get("schema"),
                "modified": metadata.get("modified"),
                "created": metadata.get("created"),
                "author": metadata.get("author"),
            }
    return export


def _description(body: dict[str, Any], object_type: str) -> str:
    if object_type == "rule":
        return str(body.get("description", ""))
    if object_type == "threat":
        return str(body.get("threat", {}).get("description", ""))
    if object_type == "objective":
        return str(body.get("objective", {}).get("description", ""))
    return ""


def run() -> None:
    OpenTide.initialise()
    export_name = OpenTide.Configurations.Global.exports.revisions
    export_path = Path(OpenTide.Configurations.Global.Paths.Tide.exports) / export_name
    export_path.parent.mkdir(parents=True, exist_ok=True)
    payload = build_revisions_export()
    export_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
