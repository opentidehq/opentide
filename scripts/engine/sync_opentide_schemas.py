#!/usr/bin/env python3
"""Generate Tide LSP catalogs from the installed OpenTide package.

The language server is bundled into OpenTide, so object intelligence comes from
OpenTide's own JSON Schema export (``generate_schema_for_identifier``) plus
Pydantic ``json_schema_extra`` flags that the schema emitter drops
(``tide.template.multiline``, ``hide``, ``required``).

Pin: opentide==0.5.0 (see scripts/requirements-opentide.txt).

    python3 scripts/sync_opentide_schemas.py
"""

from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Any, get_args, get_origin

import opentide
from opentide.generation.pydantic_schemas import generate_schema_for_identifier
from opentide.models.base import TideModel
from opentide.models.object_types import CORE_OBJECT_TYPES
from opentide.models.schema_registry import identifiers_for_families, resolve_model
from opentide.validation.errors import _REF_LEAF_TO_TYPE
from pydantic_core import PydanticUndefined

# Vocab essays (ATT&CK, actors) dominate schema size and are not needed at
# hover time. Keep every enum value; keep short docs only for small enums.
DOC_CAP = 160
ENUM_DOC_MAX = 40

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "catalogs" / "tide" / "schemas"
GENERATED = ROOT / "catalogs" / "tide" / "generated" / "fields.json"
HIGHLIGHTS = ROOT / "highlights" / "queries" / "tide" / "highlights.scm"
EXPECTED_VERSION = "0.5.0"

REF_LEAVES = dict(_REF_LEAF_TO_TYPE)


def main() -> None:
    version = opentide.__version__
    if version != EXPECTED_VERSION:
        raise SystemExit(f"expected opentide {EXPECTED_VERSION}, found {version}")

    schemas: dict[str, dict[str, Any]] = {}
    for schema_id in identifiers_for_families(CORE_OBJECT_TYPES):
        schemas[schema_id] = generate_schema_for_identifier(schema_id)
        family = schema_id.split("::", 1)[0]
        path = SCHEMA_DIR / f"{family}.1.0.schema.json"
        path.write_text(dump_schema(schemas[schema_id]), encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)} ({path.stat().st_size} bytes)")

    (SCHEMA_DIR / "opentide.schema.json").write_text(
        dump_schema(router(list(schemas))), encoding="utf-8"
    )
    visibility = SCHEMA_DIR / "visibility.1.0.schema.json"
    if visibility.exists():
        visibility.unlink()
        print("removed visibility.1.0.schema.json (not registered in opentide 0.5.0)")

    nodes: list[dict[str, Any]] = []
    for schema_id, schema in schemas.items():
        family = schema_id.split("::", 1)[0]
        model = resolve_model(schema_id)
        extras, defaults = model_facts(model)
        nodes.extend(flatten(schema, family, extras, defaults))

    nodes.sort(key=lambda n: (n["schema"], n["path"]))
    payload = {
        "opentide": version,
        "generator": "scripts/sync_opentide_schemas.py",
        "ref_leaves": REF_LEAVES,
        "gaps": [
            "threat.chaining items are untyped maps in opentide 0.5.0, so relation and vector are not schema properties. Chaining-relation diagnostics still use catalogs/tide/vocabs/chaining_relations.toml.",
            "Root status is a free string with default STAGING. Lifecycle values are deployment configuration, not a schema enum, so they are not offered as completions.",
            "enum:[\"\"] sentinels (empty vocabulary, including detection_model) are dropped and are not completions.",
        ],
        "fields": nodes,
    }
    GENERATED.parent.mkdir(parents=True, exist_ok=True)
    GENERATED.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {GENERATED.relative_to(ROOT)} ({len(nodes)} fields)")
    write_highlights(nodes)
    print(f"updated {HIGHLIGHTS.relative_to(ROOT)}")


def dump_schema(schema: dict[str, Any]) -> str:
    """Stable JSON. Shorten vocab essays; keep enum values, titles, $defs."""
    compact = shorten_enum_docs(schema)
    return json.dumps(compact, indent=2) + "\n"


def shorten_enum_docs(node: Any) -> Any:
    if isinstance(node, dict):
        enum = node.get("enum")
        drop_docs = isinstance(enum, list) and len(enum) > ENUM_DOC_MAX
        out = {}
        for key, value in node.items():
            if key == "markdownEnumDescriptions":
                if drop_docs or not isinstance(value, list):
                    continue
                out[key] = [
                    cap_doc(short_doc(v)) if isinstance(v, str) else v for v in value
                ]
            else:
                out[key] = shorten_enum_docs(value)
        return out
    if isinstance(node, list):
        return [shorten_enum_docs(v) for v in node]
    return node


def short_doc(markdown: str) -> str:
    text = markdown.strip()
    if "---" in text:
        text = text.split("---")[-1].strip()
    return " ".join(text.split())


def cap_doc(text: str) -> str:
    if len(text) <= DOC_CAP:
        return text
    return text[: DOC_CAP - 1].rstrip() + "…"


def router(schemas: dict[str, dict[str, Any]]) -> dict[str, Any]:
    branches = []
    for schema_id in schemas:
        family = schema_id.split("::", 1)[0]
        branches.append(
            {
                "if": {
                    "properties": {
                        "metadata": {
                            "properties": {"schema": {"const": schema_id}},
                            "required": ["schema"],
                        }
                    },
                    "required": ["metadata"],
                },
                "then": {"$ref": f"./{family}.1.0.schema.json"},
            }
        )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://opentide.dev/schemas/opentide.schema.json",
        "title": "OpenTide Object Router",
        "description": f"Generated from opentide {EXPECTED_VERSION}.",
        "oneOf": branches,
    }


def model_facts(
    model: type[TideModel],
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    extras: dict[str, dict[str, Any]] = {}
    defaults: dict[str, str] = {}

    def walk(current: type[TideModel], path: str) -> None:
        for name, field in current.model_fields.items():
            key = field.alias or name
            child = f"{path}.{key}" if path else key
            extra = field.json_schema_extra
            if isinstance(extra, dict) and extra:
                extras[child] = dict(extra)
            default = field.default
            if default is not PydanticUndefined and isinstance(default, str) and default:
                defaults[child] = default
            annotation = unwrap_annotation(field.annotation)
            if is_tide_model(annotation):
                walk(annotation, child)
                continue
            origin = get_origin(annotation)
            if origin in (list, tuple):
                args = get_args(annotation)
                inner = unwrap_annotation(args[0]) if args else None
                if is_tide_model(inner):
                    walk(inner, child)

    walk(model, "")
    return extras, defaults


def unwrap_annotation(annotation: Any) -> Any:
    origin = get_origin(annotation)
    if origin in (types.UnionType,):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return unwrap_annotation(args[0])
    # typing.Union
    if str(origin) == "typing.Union" or origin is getattr(__import__("typing"), "Union", None):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return unwrap_annotation(args[0])
    return annotation


def is_tide_model(annotation: Any) -> bool:
    return isinstance(annotation, type) and issubclass(annotation, TideModel)


def flatten(
    schema: dict[str, Any],
    family: str,
    extras: dict[str, dict[str, Any]],
    defaults: dict[str, str],
) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], path: str) -> None:
        obj = node if not path else unwrap(schema, node)
        if not isinstance(obj, dict):
            return
        properties = obj.get("properties") or {}
        if not isinstance(properties, dict) or not properties:
            return
        required = set(obj.get("required") or [])
        for key, spec in properties.items():
            if not isinstance(spec, dict):
                continue
            child = f"{path}.{key}" if path else key
            extra = extras.get(child, {})
            nodes.append(
                field_node(
                    family,
                    child,
                    key,
                    spec,
                    key in required,
                    extra,
                    defaults.get(child),
                    schema,
                )
            )
            if unwrap(schema, spec) and (unwrap(schema, spec) or {}).get("properties"):
                walk(spec, child)
            items = array_items(spec)
            if isinstance(items, dict) and unwrap(schema, items) and (
                unwrap(schema, items) or {}
            ).get("properties"):
                walk(items, child)

    walk(schema, "")
    return nodes


def capture_for(path: str) -> str:
    """HighlightSpec capture. JSON Schema has no keyword/property split.

    Root keys and platform blocks directly under ``configurations`` are section
    headers. ``response.procedure`` is the response section header. Every other
    key is a property, including nested objects such as ``alert``.
    """
    if "." not in path:
        return "tide.keyword"
    parent, name = path.rsplit(".", 1)
    if parent == "configurations" or parent.endswith(".configurations"):
        return "tide.keyword"
    if name == "procedure" and (parent == "response" or parent.endswith(".response")):
        return "tide.keyword"
    return "tide.property"


def field_node(
    family: str,
    path: str,
    name: str,
    spec: dict[str, Any],
    required: bool,
    extra: dict[str, Any],
    default: str | None,
    schema: dict[str, Any],
) -> dict[str, Any]:
    values, docs, is_array = enum_of(spec)
    if values == [""]:
        values, docs = [], []
    if len(values) > ENUM_DOC_MAX:
        docs = []
    else:
        docs = [cap_doc(d) for d in docs]
    kind = type_name(spec, schema, is_array)
    const = const_of(spec)
    ref = None
    if name in REF_LEAVES and not values and kind in {"string", "array"}:
        ref = REF_LEAVES[name]
    if const and not values:
        values = [const]
        docs = [""]
    if default and values and default not in values:
        # Pydantic default can sit outside the schema enum (severity = Informational).
        default = None
    description = spec.get("description") if isinstance(spec.get("description"), str) else ""
    node: dict[str, Any] = {
        "schema": family,
        "path": path,
        "name": name,
        "title": spec.get("title") or name,
        "description": description or "",
        "type": kind,
        "required": required,
        "markdown": bool(extra.get("tide.template.multiline")),
        "hidden": bool(extra.get("tide.template.hide")),
        "capture": capture_for(path),
        "enum": values,
        "enum_docs": docs[: len(values)] + [""] * max(0, len(values) - len(docs)),
        "ref": ref,
        "const": const,
        "array": is_array or kind == "array",
    }
    if default:
        node["default"] = default
    min_items = spec.get("minItems")
    if not isinstance(min_items, int):
        for alt in spec.get("anyOf") or []:
            if isinstance(alt, dict) and isinstance(alt.get("minItems"), int):
                min_items = alt["minItems"]
                break
    if isinstance(min_items, int):
        node["min_items"] = min_items
    if not any(node["enum_docs"]):
        node["enum_docs"] = []
    return node


def enum_of(spec: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    if spec.get("type") == "array":
        items = spec.get("items") if isinstance(spec.get("items"), dict) else {}
        values = items.get("enum") if isinstance(items, dict) else None
        docs = items.get("markdownEnumDescriptions") if isinstance(items, dict) else None
        if isinstance(values, list):
            cleaned, short = clean_enum(values, docs if isinstance(docs, list) else [])
            return cleaned, short, True
        return [], [], True
    # A vocab enum glued beside anyOf applies only when the value can be one of
    # those strings. Chaining is an array of open objects; effort is an integer.
    # Those pins are not completions of the field itself.
    if isinstance(spec.get("enum"), list) and scalar_enum_applies(spec):
        cleaned, short = clean_enum(spec["enum"], spec.get("markdownEnumDescriptions") or [])
        return cleaned, short, False
    for alt in spec.get("anyOf") or []:
        if not isinstance(alt, dict):
            continue
        if alt.get("type") == "array":
            items = alt.get("items") if isinstance(alt.get("items"), dict) else {}
            values = items.get("enum") if isinstance(items, dict) else None
            docs = items.get("markdownEnumDescriptions") if isinstance(items, dict) else None
            if isinstance(values, list):
                cleaned, short = clean_enum(values, docs if isinstance(docs, list) else [])
                return cleaned, short, True
            return [], [], True
        if isinstance(alt.get("enum"), list):
            cleaned, short = clean_enum(alt["enum"], alt.get("markdownEnumDescriptions") or [])
            return cleaned, short, False
    return [], [], spec.get("type") == "array"


def yaml_scalar(value: Any) -> str | None:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value in ("", None):
        return None
    return str(value)


def scalar_enum_applies(spec: dict[str, Any]) -> bool:
    if spec.get("type") in {"array", "object", "integer", "number", "boolean"}:
        return False
    alternatives = [alt for alt in spec.get("anyOf") or [] if isinstance(alt, dict)]
    if not alternatives:
        return spec.get("type") in {None, "string"}
    if any(is_object_array(alt) for alt in alternatives):
        return False
    return any(holds_string(alt) for alt in alternatives)


def is_object_array(alt: dict[str, Any]) -> bool:
    if alt.get("type") != "array":
        return False
    items = alt.get("items") if isinstance(alt.get("items"), dict) else {}
    return (
        items.get("type") == "object"
        or "properties" in items
        or "additionalProperties" in items
    )


def holds_string(alt: dict[str, Any]) -> bool:
    if alt.get("type") == "string":
        return True
    if alt.get("type") != "array":
        return False
    items = alt.get("items") if isinstance(alt.get("items"), dict) else {}
    return items.get("type") in {None, "string"} and "properties" not in items


def clean_enum(values: list[Any], docs: list[Any]) -> tuple[list[str], list[str]]:
    pairs = list(zip(values, docs)) if len(docs) == len(values) else [(v, "") for v in values]
    cleaned: list[str] = []
    short: list[str] = []
    for value, doc in pairs:
        rendered = yaml_scalar(value)
        if rendered is None:
            continue
        cleaned.append(rendered)
        short.append(short_doc(doc) if isinstance(doc, str) else "")
    return cleaned, short


def const_of(spec: dict[str, Any]) -> str | None:
    if isinstance(spec.get("const"), str):
        return spec["const"]
    for alt in spec.get("anyOf") or []:
        if isinstance(alt, dict) and isinstance(alt.get("const"), str):
            return alt["const"]
    return None


def type_name(spec: dict[str, Any], schema: dict[str, Any], is_array: bool) -> str:
    if is_array or spec.get("type") == "array" or any(
        isinstance(alt, dict) and alt.get("type") == "array" for alt in spec.get("anyOf") or []
    ):
        return "array"
    if unwrap(schema, spec) and (unwrap(schema, spec) or {}).get("properties"):
        return "object"
    raw = spec.get("type")
    if isinstance(raw, str) and raw != "null":
        return raw
    types_found = []
    for alt in spec.get("anyOf") or []:
        if isinstance(alt, dict) and isinstance(alt.get("type"), str) and alt["type"] != "null":
            types_found.append(alt["type"])
        elif isinstance(alt, dict) and "$ref" in alt:
            types_found.append("object")
    if types_found:
        return types_found[0]
    if spec.get("format") == "date":
        return "string"
    return "any"


def unwrap(schema: dict[str, Any], node: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(node, dict):
        return None
    if "$ref" in node:
        return schema["$defs"][node["$ref"].rsplit("/", 1)[-1]]
    for alt in node.get("anyOf") or []:
        if isinstance(alt, dict) and "$ref" in alt:
            return schema["$defs"][alt["$ref"].rsplit("/", 1)[-1]]
    if node.get("properties"):
        return node
    return None


def array_items(spec: dict[str, Any]) -> dict[str, Any] | None:
    if spec.get("type") == "array" and isinstance(spec.get("items"), dict):
        return spec["items"]
    for alt in spec.get("anyOf") or []:
        if isinstance(alt, dict) and alt.get("type") == "array" and isinstance(alt.get("items"), dict):
            return alt["items"]
    return None


def write_highlights(nodes: list[dict[str, Any]]) -> None:
    keywords = sorted({n["name"] for n in nodes if n["capture"] == "tide.keyword"})
    properties = sorted({n["name"] for n in nodes if n["capture"] == "tide.property"})
    text = f"""\
; Tide YAML object highlighting. Injected KQL/SPL tokens are remapped onto
; the host document by opentide-highlight (not by this query).
; Generated key lists come from catalogs/tide/generated/fields.json
; (opentide {EXPECTED_VERSION}). Runtime highlighting is path-aware and does not
; use this query. Capture names must stay a subset of HighlightSpec.

((block_mapping_pair
  key: (_) @tide.keyword)
 (#match? @tide.keyword "^({alt(keywords)})$"))

((block_mapping_pair
  key: (_) @tide.property)
 (#match? @tide.property "^({alt(properties)})$"))

(comment) @comment
"""
    HIGHLIGHTS.write_text(text, encoding="utf-8")


def alt(names: list[str]) -> str:
    # Only regex metacharacters. `re.escape` also escapes `&` (`att&ck`).
    meta = set(".^$*+?()[]{}|\\")

    def esc(name: str) -> str:
        return "".join(f"\\{char}" if char in meta else char for char in name)

    return "|".join(esc(name) for name in names)


if __name__ == "__main__":
    main()
