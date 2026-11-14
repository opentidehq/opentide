"""Write config_table.json: what the oracle reports for each case of config_cases.toml.

Run it with the oracle's interpreter (tests/corpora/oracle.in, tests/corpora/README.md):

    <oracle python> -I crates/opentide-schema/tests/oracle/config_table.py

Each case is checked the way the CLI and the language server check
configuration files (`validation/configuration.py`, `core/files.py`,
`core/lint_config.py`, `sharing/config.py`); `tests/configuration.rs` runs the
same case through `opentide_schema::configuration` and compares.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

import opentide
from opentide.core.errors import UserFileError
from opentide.core.files import deep_merge, resolve_configurations
from opentide.core.lint_config import LintConfigError, metadata_keys, parse_lint_config
from opentide.sharing.config import load_sharing
from opentide.validation.configuration import (
    bundled_layer,
    configuration_text_issues,
    workspace_configuration_issues,
)

HERE = Path(__file__).resolve().parent
#: Where the oracle's bundled configuration folder is installed.
BUNDLED = str(Path(opentide.__file__).parent / "data" / "configurations")


def plain(value: Any) -> Any:
    """A TOML value as JSON, as `merge::to_json` writes it."""
    if isinstance(value, dict):
        return {str(key): plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [plain(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return "nan" if math.isnan(value) else ("inf" if value > 0 else "-inf")
    if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
        return value.isoformat().replace("+00:00", "Z")
    return value


def issue(item: Any, root: str | None = None) -> dict[str, Any]:
    file_path = None if item.file_path is None else str(item.file_path)
    message = item.message
    if root is not None:
        message = message.replace(root, "<root>")
        if file_path is not None:
            file_path = file_path.replace(root, "<root>")
    return {
        "code": item.code,
        "severity": item.severity,
        "field_path": list(item.field_path),
        "message": message,
        "file_path": file_path,
        "context": plain(dict(item.context)),
    }


def write_files(folder: Path, files: dict[str, str]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for relative, text in files.items():
        target = folder / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")


def instance(root: Path, case: dict[str, Any]) -> Path:
    """`<root>/parent/ws`, its configurations from `files`, the parent's from `parent`."""
    workspace = root / "parent" / "ws"
    write_files(workspace / ".opentide" / "configurations", case.get("files", {}))
    if "parent" in case:
        write_files(root / "parent" / ".opentide" / "configurations", case["parent"])
    return workspace


def text_case(case: dict[str, Any]) -> Any:
    kwargs: dict[str, Any] = {}
    if "earlier" in case:
        kwargs["earlier_layers"] = [tomllib.loads(text) for text in case["earlier"]]
    if "later" in case:
        kwargs["later_layers"] = [tomllib.loads(text) for text in case["later"]]
    for key in ("status_names", "partial", "sharing_directory"):
        if key in case:
            kwargs[key] = case[key]
    return [issue(item) for item in configuration_text_issues(case["path"], case["text"], **kwargs)]


def workspace_case(case: dict[str, Any]) -> Any:
    with tempfile.TemporaryDirectory() as directory:
        root = str(Path(directory).resolve())
        workspace = instance(Path(root), case)
        try:
            configs = resolve_configurations(workspace)
        except UserFileError as exc:
            return {
                "error": {
                    "code": exc.code,
                    "path": str(exc.path).replace(root, "<root>"),
                    "message": exc.problem,
                    "line": exc.line,
                    "column": exc.column,
                }
            }
        except ValueError as exc:
            return {"error": {"code": None, "message": str(exc)}}
        return {
            "resolved": plain(configs),
            "issues": [issue(item) for item in workspace_configuration_issues(configs)],
        }


def lint_case(case: dict[str, Any]) -> Any:
    merged: dict[str, Any] = {}
    deep_merge(merged, bundled_layer("lint.toml") or tomllib.loads(_bundled("lint.toml")))
    deep_merge(merged, tomllib.loads(case["text"]))
    try:
        config = parse_lint_config(merged)
    except LintConfigError as exc:
        return {"error": str(exc)}

    def filenames(item: Any) -> dict[str, Any]:
        return {
            "style": item.style,
            "pattern": None if item.pattern is None else item.pattern.pattern,
            "pattern_key": item.pattern_key,
            "kinds": {kind: filenames(own) for kind, own in item.kinds.items()},
        }

    return {
        "checks": {
            name: {"enabled": check.enabled, "severity": check.severity}
            for name, check in config.checks.items()
        },
        "required_metadata": list(config.required_metadata),
        "filenames": filenames(config.filenames),
    }


def _bundled(name: str) -> str:
    return (Path(opentide.__file__).parent / "data" / "configurations" / name).read_text(
        encoding="utf-8"
    )


def sharing_case(case: dict[str, Any]) -> Any:
    with tempfile.TemporaryDirectory() as directory:
        root = str(Path(directory).resolve())
        workspace = instance(Path(root), case)
        loaded = load_sharing(workspace)
        out = []
        for finding in loaded.issues:
            field_path = [
                part
                for part in (finding.integration, finding.block, finding.field_name)
                if part is not None
            ]
            source = None if loaded.source is None else str(loaded.source)
            if source is not None:
                source = source.replace(BUNDLED, "<bundled>")
            out.append(
                {
                    "code": finding.code,
                    "severity": finding.severity,
                    "field_path": field_path,
                    "message": finding.message.replace(root, "<root>"),
                    "file_path": None if source is None else source.replace(root, "<root>"),
                    "context": {},
                }
            )
        return out


def main() -> int:
    os.environ.pop("OPENTIDE_TIDE_WORKSPACE", None)
    cases = tomllib.loads((HERE / "config_cases.toml").read_text(encoding="utf-8"))
    runners = {
        "text": text_case,
        "workspace": workspace_case,
        "lint": lint_case,
        "sharing": sharing_case,
    }
    table: dict[str, Any] = {
        "oracle": opentide.__version__,
        "metadata_keys": list(metadata_keys()),
        "bundled": sorted(
            path.relative_to(BUNDLED).as_posix() for path in Path(BUNDLED).rglob("*.toml")
        ),
        "cases": {},
    }
    for case in cases["case"]:
        table["cases"][case["id"]] = runners[case["kind"]](case)
    out = HERE / "config_table.json"
    out.write_text(json.dumps(table, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    sys.stderr.write(f"wrote {out} ({len(table['cases'])} cases)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
