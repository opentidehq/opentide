"""Print each workspace's registry index as the oracle builds it.

`cargo xtask registry diff --against python` runs it with the oracle's
interpreter (tests/corpora/oracle.in, beside the oracle executable):

    <oracle python> -I xtask/oracle/registry_export.py WORKSPACE...

For each workspace it runs the registry's own object loading
(`RegistryBuilder._load_objects`, after `resolve_configurations` and
`resolve_workspace_paths`, as `RegistryBuilder.build` does) and prints the
index in the shape `opentide_workspace::Index::to_json` writes: objects by
family, bodies, file paths and names, signals, load errors, duplicates,
nested files, the references `validation/checks/cross_object.py` follows,
and `compute_chains`. Paths are relative to the workspace. A workspace whose
configuration stops the build prints the error's code.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import sys
from pathlib import Path
from typing import Any


def plain(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf")
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat().replace("+00:00", "Z")
    return value


def relative(path: str | Path, root: Path) -> str:
    candidate = Path(path)
    try:
        return candidate.relative_to(root).as_posix()
    except ValueError:
        return str(candidate)


def block(body: dict[str, Any], key: str) -> dict[str, Any]:
    value = body.get(key)
    return value if isinstance(value, dict) else {}


def references(objects: dict[str, dict[str, Any]]) -> list[list[str]]:
    found: list[list[str]] = []
    for family, members in objects.items():
        for uuid, body in members.items():
            if family == "rule":
                parent = body.get("detection_model")
                if parent and isinstance(parent, str | int):
                    found.append([str(uuid), "detection_model", str(parent)])
            elif family == "objective":
                for threat in block(body, "objective").get("threats") or []:
                    found.append([str(uuid), "threat", str(threat)])
                signals = block(body, "objective").get("signals") or []
                for signal in signals if isinstance(signals, list) else []:
                    if isinstance(signal, dict) and signal.get("uuid"):
                        found.append([str(uuid), "signal", str(signal["uuid"])])
            elif family == "threat":
                for link in block(body, "threat").get("chaining") or []:
                    if isinstance(link, dict) and link.get("vector"):
                        found.append([str(uuid), "chaining", str(link["vector"])])
    return found


def one(workspace: Path) -> dict[str, Any]:
    os.chdir(workspace)
    os.environ["OPENTIDE_REPO_ROOT"] = str(workspace)
    from opentide.core import root

    root.get_repo_root.cache_clear()
    from opentide.core.chaining import compute_chains
    from opentide.core.errors import UserFileError
    from opentide.core.files import resolve_configurations
    from opentide.registry.builder import RegistryBuilder, parse_errors_reported_by_caller
    from opentide.registry.discovery import discover_workspace
    from opentide.registry.paths import resolve_workspace_paths

    base = discover_workspace()
    builder = RegistryBuilder()
    try:
        configs = resolve_configurations()
        paths = resolve_workspace_paths(configs)
    except UserFileError as exc:
        return {"error": {"code": exc.code}}
    except (ValueError, KeyError):
        return {"error": {"code": None}}
    metaschemas = configs["paths"].get("metaschemas", {})
    with parse_errors_reported_by_caller():
        objects, files = builder._load_objects(paths, metaschemas)
    families = {name: members for name, members in objects.items() if name != "signal"}
    return {
        "objects": {name: [str(uuid) for uuid in members] for name, members in families.items()},
        "bodies": {
            name: {str(uuid): plain(body) for uuid, body in members.items()}
            for name, members in families.items()
        },
        "file_paths": {str(k): relative(v, base) for k, v in builder.file_paths.items()},
        "files": {str(k): v for k, v in files.items()},
        "signals": {str(k): plain(v) for k, v in objects["signal"].items()},
        "load_errors": [
            {
                "path": relative(entry["path"], base),
                "object_type": entry.get("object_type") or "",
                "code": entry.get("code") or "yaml_parse",
                "error": entry.get("error", ""),
                "message": entry.get("message")
                or f"Could not parse object YAML: {entry.get('error', 'unknown error')}",
            }
            for entry in builder.parse_errors
        ],
        "duplicates": [
            {
                "path": relative(entry["path"], base),
                "object_type": entry["object_type"],
                "code": entry["code"],
                "message": entry["message"],
            }
            for entry in builder.duplicate_files
        ],
        "nested": [
            {
                "path": relative(entry["path"], base),
                "folder": relative(entry["folder"], base),
                "object_type": entry["object_type"],
            }
            for entry in builder.nested_object_files
        ],
        "references": references(families),
        "chaining": plain(compute_chains(objects.get("threat", {}))),
    }


def main() -> int:
    os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
    out: dict[str, Any] = {}
    for argument in sys.argv[1:]:
        workspace = Path(argument).resolve()
        try:
            out[argument] = one(workspace)
        except Exception as exc:  # noqa: BLE001 -- a crash is a result to compare
            out[argument] = {"crash": f"{type(exc).__name__}: {exc}"}
    json.dump(out, sys.stdout, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
