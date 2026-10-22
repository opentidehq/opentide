"""JSON Schema of each configuration TOML file, and a router keyed by file name.

Every schema is `model_json_schema()` of the file's model in
`opentide.models.configuration`; nothing else is a schema source. The router
maps a path under `.opentide/configurations/` (`deployment.toml`,
`platforms/sentinel.toml`, `sharing.toml`, ...) to its schema file, since a
TOML file is routed by its name rather than by a key inside it.

    python -m opentide.generation.configuration_schemas <output-dir>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from opentide.models.configuration import (
    GENERIC_PLATFORM_FILE,
    configuration_files,
)
from opentide.models.configuration.sharing import MISP_SCHEMA_ID

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
ROUTER_NAME = "configurations.router.json"
ROUTER_TITLE = "opentide Configuration Router"

#: How a later layer combines with an earlier one, per the configuration spec.
_MERGE_DEEP = "deep"
_MERGE_BY_NAME = "by-name"

#: Router key whose schema is shared with another key.
_SCHEMA_ALIASES = {"global.toml": "paths.toml"}


def configuration_schema_name(file_key: str) -> str:
    """Schema file name of a router key.

    `platforms/sentinel.toml` is written as `platforms.sentinel.schema.json`.
    """
    key = _SCHEMA_ALIASES.get(file_key, file_key)
    if key == GENERIC_PLATFORM_FILE:
        return "platforms.schema.json"
    return key.removesuffix(".toml").replace("/", ".") + ".schema.json"


def _strip_framework_keywords(node: Any) -> Any:
    """Drop `tide.*` keywords (template and enrichment hints) at any depth."""
    if isinstance(node, dict):
        return {
            key: _strip_framework_keywords(value)
            for key, value in node.items()
            if not (isinstance(key, str) and key.startswith("tide."))
        }
    if isinstance(node, list):
        return [_strip_framework_keywords(item) for item in node]
    return node


def generate_configuration_schema(file_key: str) -> dict[str, Any]:
    """JSON Schema of one configuration file, from its model."""
    model = configuration_files()[file_key]
    raw = _strip_framework_keywords(model.model_json_schema())
    title_key = _SCHEMA_ALIASES.get(file_key, file_key)
    if title_key == GENERIC_PLATFORM_FILE:
        title_key = "platforms/<id>.toml"
    schema: dict[str, Any] = {"$schema": JSON_SCHEMA_DIALECT}
    schema.update(raw)
    schema["title"] = title_key
    return schema


def _router_entry(file_key: str) -> dict[str, Any]:
    model = configuration_files()[file_key]
    entry: dict[str, Any] = {
        "schema": configuration_schema_name(file_key),
        "merge": _MERGE_BY_NAME if file_key == "sharing.toml" else _MERGE_DEEP,
    }
    identifier = getattr(model, "__schema_identifier__", None)
    if isinstance(identifier, str):
        entry["schema_id"] = identifier
    if file_key == "sharing.toml":
        entry["connectors"] = {"misp": MISP_SCHEMA_ID}
    return entry


def build_configuration_router() -> dict[str, Any]:
    """Map each configuration file name to its schema file."""
    return {
        "title": ROUTER_TITLE,
        "description": (
            "Maps a file under .opentide/configurations/ to the JSON Schema that "
            "validates it. A file is a partial override: required keys apply to the "
            "merge of the bundled file, the workspace file and the parent instance. "
            "platforms/*.toml matches a platform file without a dedicated entry."
        ),
        "files": {key: _router_entry(key) for key in configuration_files()},
    }


def generate_configuration_schemas() -> dict[str, dict[str, Any]]:
    """Every configuration schema and the router, keyed by output file name."""
    documents: dict[str, dict[str, Any]] = {}
    for file_key in configuration_files():
        name = configuration_schema_name(file_key)
        if name not in documents:
            documents[name] = generate_configuration_schema(file_key)
    documents[ROUTER_NAME] = build_configuration_router()
    return documents


def render_schema(document: dict[str, Any]) -> str:
    """The exact bytes written for a schema document."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def export_configuration_schemas(output_dir: Path) -> list[Path]:
    """Write every configuration schema and the router into *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, document in generate_configuration_schemas().items():
        path = output_dir / name
        path.write_text(render_schema(document), encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: python -m opentide.generation.configuration_schemas <dir>\n")
        return 2
    for path in export_configuration_schemas(Path(args[0])):
        sys.stdout.write(f"{path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
