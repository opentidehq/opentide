"""Write objects_table.json: what the oracle reports for each case of objects_cases.toml.

Run it with the oracle's interpreter (opentide 0.23.0, tests/corpora/README.md):

    <oracle python> crates/opentide-schema/tests/oracle/objects_table.py

Each case is a Tide object file and its family (`rule`, `threat`, `objective`),
written in objects_cases.toml or read from the repository: every object file
of tests/fixtures/tide_corpus and of the VS Code fixture workspace
(tests/golden/fixtures/vscode-workspace). For each one the script runs the
oracle's validate path, `parse_yaml` then `load_object_for_validation`, and
records:

- `yaml_error`: the loader refused the YAML (`yaml_parse`);
- `loader`: the loader refused the identifier (`schema_missing`, or the
  message of a `schema_validation` about `metadata.schema`): the model never ran;
- `crash`: the exception that escaped, by type;
- `errors`: every Pydantic error, as `from_node_table.py` records them (type,
  field path, message, string input, ctx, the span the CLI prints and the
  `yaml_line` it attaches);
- or `value`: `model_dump(by_alias=True, exclude_none=True, mode="json")`,
  with each platform block of `configurations` reduced to `{}` (UC-1.4) and
  `file` left out.
"""

from __future__ import annotations

import json
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

import opentide
from opentide.cli.ui.diagnostics import SourceFiles
from opentide.core.io import parse_yaml
from opentide.loading.object_loader import (
    SchemaIdentifierError,
    SchemaMissingError,
    load_object_for_validation,
)
from opentide.validation.errors import _find_line, load_yaml_with_lines

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
FAMILY_FOLDERS = {
    "Detection Rules": "rule",
    "Threat Vectors": "threat",
    "Detection Objectives": "objective",
    "rules": "rule",
    "threats": "threat",
    "objectives": "objective",
}
FILE_SOURCES = [
    "tests/fixtures/tide_corpus/current/Objects",
    "tests/golden/fixtures/vscode-workspace/objects",
]


def find_line(located: Any, field_path: list[str]) -> Any:
    if located is None:
        return None
    try:
        return _find_line(located, tuple(field_path))
    except Exception as exc:  # noqa: BLE001 -- recorded as data: the oracle's own crash
        return {"crash": type(exc).__name__}


def value_of(model: Any) -> Any:
    dumped = model.model_dump(by_alias=True, exclude_none=True, mode="json")
    dumped.pop("file", None)
    configurations = dumped.get("configurations")
    if isinstance(configurations, dict):
        dumped["configurations"] = {key: {} for key in configurations}
    return dumped


def run(family: str, text: str) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "object.yaml"
        path.write_text(text, encoding="utf-8")
        try:
            body = parse_yaml(text)
        except Exception:  # noqa: BLE001 -- any loader failure is yaml_parse
            return {"yaml_error": True}
        try:
            model = load_object_for_validation(body, family)
        except SchemaMissingError:
            return {"loader": "schema_missing"}
        except SchemaIdentifierError as exc:
            return {"loader": str(exc)}
        except ValidationError as exc:
            sources = SourceFiles()
            located = load_yaml_with_lines(path)
            errors = []
            for err in exc.errors():
                field_path = [str(part) for part in err["loc"]]
                at_key = err["msg"].startswith("Extra inputs are not permitted")
                span = sources.span(path, field_path, at_key=at_key)
                ctx = {key: str(item) for key, item in (err.get("ctx") or {}).items()}
                errors.append(
                    {
                        "type": err["type"],
                        "field_path": field_path,
                        "msg": err["msg"],
                        "input": err["input"] if isinstance(err["input"], str) else None,
                        "ctx": ctx,
                        "span": None
                        if span is None
                        else [span.line, span.column, span.end_column, span.found],
                        "yaml_line": find_line(located, field_path),
                    }
                )
            return {"errors": errors}
        except Exception as exc:  # noqa: BLE001 -- recorded as data: the oracle's own crash
            return {"crash": type(exc).__name__}
    return {"value": value_of(model)}


def file_cases() -> list[dict[str, str]]:
    cases = []
    for source in FILE_SOURCES:
        for path in sorted((ROOT / source).rglob("*.yaml")):
            family = FAMILY_FOLDERS[path.parent.name]
            relative = path.relative_to(ROOT).as_posix()
            text = path.read_text(encoding="utf-8")
            cases.append({"id": f"file:{relative}", "family": family, "yaml": text})
    return cases


def main() -> int:
    written = tomllib.loads((HERE / "objects_cases.toml").read_text(encoding="utf-8"))["case"]
    cases = [{"id": c["id"], "family": c["family"], "yaml": c["yaml"]} for c in written]
    out = []
    for case in [*cases, *file_cases()]:
        out.append({**case, **run(case["family"], case["yaml"])})
    document = {"oracle": opentide.__version__, "cases": out}
    (HERE / "objects_table.json").write_text(
        json.dumps(document, indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
