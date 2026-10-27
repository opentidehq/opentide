"""The language server's Tide catalogs, generated from this workspace's schemas.

``opentide generate schemas`` writes them to ``.opentide/lsp/catalogs/generated/``:

- ``fields.json``: every field of the newest revision of each object family,
  with its title, description, type, enum values and their docs. The engine
  uses it for hover, completion and the enum checks, so they follow this
  workspace's vocabulary rather than the snapshot compiled into the engine.
- ``deprecations.json``: the fields marked deprecated (``deprecated_field``).

The shapes are the engine's own (``catalogs/tide/generated/`` in
opentidehq/language-server, whose ``scripts/sync_opentide_schemas.py`` this
module was ported from). ``opentide lsp start``, ``opentide lsp check`` and the
query checks install them (:mod:`opentide.analysis`); the bundled snapshot is
the fallback when they are missing or do not parse.
"""

from __future__ import annotations

import json
import types
import typing
from pathlib import Path
from typing import TYPE_CHECKING, Any, get_args, get_origin

from opentide.core.logging import get_logger

if TYPE_CHECKING:
    from typing import TypeGuard

    from opentide.models.base import TideModel

logger = get_logger(__name__)

#: Relative to the workspace root, as the language server reads it.
CATALOG_DIR = Path(".opentide") / "lsp" / "catalogs" / "generated"
FIELDS_FILE = "fields.json"
DEPRECATIONS_FILE = "deprecations.json"
GENERATOR = "opentide generate schemas"

# Vocabulary essays (ATT&CK, actors) dominate the catalog and are not needed at
# hover time: every enum value is kept, short docs only for small enums.
DOC_CAP = 160
ENUM_DOC_MAX = 40


def write_catalog(root: Path) -> list[Path]:
    """Write ``fields.json`` and ``deprecations.json`` under *root*; return their paths."""
    import opentide

    version = opentide.__version__
    directory = root / CATALOG_DIR
    directory.mkdir(parents=True, exist_ok=True)
    written = []
    for name, payload in (
        (FIELDS_FILE, fields_catalog(version)),
        (DEPRECATIONS_FILE, deprecations_catalog(version)),
    ):
        path = directory / name
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    logger.info("exported_lsp_catalogs", path=str(directory))
    return written


def fields_catalog(version: str) -> dict[str, Any]:
    """The ``fields.json`` document for the registered object schemas."""
    from opentide.generation.pydantic_schemas import generate_schema_for_identifier
    from opentide.models.object_types import CORE_OBJECT_TYPES
    from opentide.models.schema_registry import identifiers_for_families, resolve_model
    from opentide.validation.errors import _REF_LEAF_TO_TYPE

    schemas = {
        schema_id: generate_schema_for_identifier(schema_id)
        for schema_id in identifiers_for_families(CORE_OBJECT_TYPES)
    }
    # The catalog is keyed by family: a family with several revisions contributes
    # its newest, a superset of the older shapes.
    latest: dict[str, str] = {}
    revisions: dict[str, list[str]] = {}
    for schema_id in schemas:
        family, revision = schema_id.split("::", 1)
        revisions.setdefault(family, []).append(schema_id)
        current = latest.get(family)
        if current is None or _revision_key(revision) > _revision_key(current.split("::", 1)[1]):
            latest[family] = schema_id

    ref_leaves = dict(_REF_LEAF_TO_TYPE)
    nodes: list[dict[str, Any]] = []
    for family, schema_id in latest.items():
        extras, defaults = _model_facts(resolve_model(schema_id))
        nodes.extend(_flatten(schemas[schema_id], family, extras, defaults, ref_leaves))

    # metadata.schema offers every revision of the family, not only the newest.
    for node in nodes:
        if node["path"] == "metadata.schema":
            ids = sorted(revisions[node["schema"]], key=lambda i: _revision_key(i.split("::")[1]))
            node["enum"] = ids
            node["enum_docs"] = []
            node["const"] = ids[0] if len(ids) == 1 else None

    nodes.sort(key=lambda node: (node["schema"], node["path"]))
    return {
        "opentide": version,
        "generator": GENERATOR,
        "ref_leaves": ref_leaves,
        "fields": nodes,
    }


def deprecations_catalog(version: str) -> dict[str, Any]:
    """The ``deprecations.json`` document: root and platform fields marked deprecated."""
    from opentide.generation.pydantic_metaschema import CORE_ROOT_EXTRAS
    from opentide.models.platform import PLATFORM_CONFIG_MODELS
    from opentide.models.platform_schema import _PLATFORM_EXTRAS

    rows: list[dict[str, str]] = []
    for family, extras in CORE_ROOT_EXTRAS.items():
        for name, spec in (extras.get("property_extras") or {}).items():
            if isinstance(spec, dict) and spec.get("tide.meta.deprecation"):
                rows.append(
                    {"schema": family, "path": name, "message": str(spec["tide.meta.deprecation"])}
                )
    for platform, model in PLATFORM_CONFIG_MODELS.items():
        for name, spec in (_PLATFORM_EXTRAS.get(model, {}).get("property_extras") or {}).items():
            if isinstance(spec, dict) and spec.get("tide.meta.deprecation"):
                rows.append(
                    {
                        "schema": "rule",
                        "path": f"configurations.{platform}.{name}",
                        "message": str(spec["tide.meta.deprecation"]),
                    }
                )
    rows.sort(key=lambda row: (row["schema"], row["path"]))
    return {"opentide": version, "generator": GENERATOR, "fields": rows}


def _revision_key(revision: str) -> tuple[int, ...]:
    return tuple(int(part) for part in revision.split(".") if part.isdigit())


def _model_facts(model: type[TideModel]) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    """``json_schema_extra`` flags and string defaults by dotted path.

    The schema emitter drops ``tide.template.multiline`` and ``hide``, and a
    Pydantic default is not always in the schema.
    """
    from pydantic_core import PydanticUndefined

    from opentide.models.base import TideModel

    extras: dict[str, dict[str, Any]] = {}
    defaults: dict[str, str] = {}

    def is_tide_model(annotation: object) -> TypeGuard[type[TideModel]]:
        return isinstance(annotation, type) and issubclass(annotation, TideModel)

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
            annotation = _unwrap_optional(field.annotation)
            if is_tide_model(annotation):
                walk(annotation, child)
                continue
            if get_origin(annotation) in (list, tuple):
                args = get_args(annotation)
                inner = _unwrap_optional(args[0]) if args else None
                if is_tide_model(inner):
                    walk(inner, child)

    walk(model, "")
    return extras, defaults


def _unwrap_optional(annotation: Any) -> Any:
    if get_origin(annotation) in (types.UnionType, typing.Union):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return _unwrap_optional(args[0])
    return annotation


def _flatten(
    schema: dict[str, Any],
    family: str,
    extras: dict[str, dict[str, Any]],
    defaults: dict[str, str],
    ref_leaves: dict[str, str],
) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []

    def walk(node: dict[str, Any], path: str) -> None:
        obj = node if not path else _unwrap(schema, node)
        if not isinstance(obj, dict):
            return
        properties = obj.get("properties") or {}
        if not isinstance(properties, dict):
            return
        required = set(obj.get("required") or [])
        for key, spec in properties.items():
            if not isinstance(spec, dict):
                continue
            child = f"{path}.{key}" if path else key
            nodes.append(
                _field_node(
                    family,
                    child,
                    key,
                    spec,
                    required=key in required,
                    extra=extras.get(child, {}),
                    default=defaults.get(child),
                    schema=schema,
                    ref_leaves=ref_leaves,
                )
            )
            if (_unwrap(schema, spec) or {}).get("properties"):
                walk(spec, child)
            items = _array_items(spec)
            if isinstance(items, dict) and (_unwrap(schema, items) or {}).get("properties"):
                walk(items, child)

    walk(schema, "")
    return nodes


def _field_node(
    family: str,
    path: str,
    name: str,
    spec: dict[str, Any],
    *,
    required: bool,
    extra: dict[str, Any],
    default: str | None,
    schema: dict[str, Any],
    ref_leaves: dict[str, str],
) -> dict[str, Any]:
    values, docs, is_array = _enum_of(spec)
    if values == [""]:
        values, docs = [], []
    docs = [] if len(values) > ENUM_DOC_MAX else [_cap_doc(doc) for doc in docs]
    kind = _type_name(spec, schema, is_array)
    const = _const_of(spec)
    ref = ref_leaves.get(name) if not values and kind in {"string", "array"} else None
    if const and not values:
        values, docs = [const], [""]
    if default and values and default not in values:
        # A Pydantic default can sit outside the schema enum.
        default = None
    description = spec.get("description")
    node: dict[str, Any] = {
        "schema": family,
        "path": path,
        "name": name,
        "title": spec.get("title") or name,
        "description": description if isinstance(description, str) else "",
        "type": kind,
        "required": required,
        "markdown": bool(extra.get("tide.template.multiline")),
        "hidden": bool(extra.get("tide.template.hide")),
        # Every key takes one capture, so nesting never recolours a key.
        "capture": "tide.property",
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
        min_items = next(
            (
                alt["minItems"]
                for alt in spec.get("anyOf") or []
                if isinstance(alt, dict) and isinstance(alt.get("minItems"), int)
            ),
            None,
        )
    if isinstance(min_items, int):
        node["min_items"] = min_items
    if not any(node["enum_docs"]):
        node["enum_docs"] = []
    return node


def _enum_of(spec: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    if spec.get("type") == "array":
        return _array_enum(spec)
    # A vocabulary enum beside anyOf applies only when the value can be one of
    # those strings: chaining is an array of open objects, effort an integer.
    if isinstance(spec.get("enum"), list) and _scalar_enum_applies(spec):
        values, docs = _clean_enum(spec["enum"], spec.get("markdownEnumDescriptions") or [])
        return values, docs, False
    for alt in spec.get("anyOf") or []:
        if not isinstance(alt, dict):
            continue
        if alt.get("type") == "array":
            return _array_enum(alt)
        if isinstance(alt.get("enum"), list):
            values, docs = _clean_enum(alt["enum"], alt.get("markdownEnumDescriptions") or [])
            return values, docs, False
    return [], [], spec.get("type") == "array"


def _array_enum(spec: dict[str, Any]) -> tuple[list[str], list[str], bool]:
    items = _items(spec)
    values = items.get("enum")
    docs = items.get("markdownEnumDescriptions")
    if isinstance(values, list):
        cleaned, short = _clean_enum(values, docs if isinstance(docs, list) else [])
        return cleaned, short, True
    return [], [], True


def _items(spec: dict[str, Any]) -> dict[str, Any]:
    """An array schema's ``items``, or an empty mapping."""
    items = spec.get("items")
    return items if isinstance(items, dict) else {}


def _scalar_enum_applies(spec: dict[str, Any]) -> bool:
    if spec.get("type") in {"array", "object", "integer", "number", "boolean"}:
        return False
    alternatives = [alt for alt in spec.get("anyOf") or [] if isinstance(alt, dict)]
    if not alternatives:
        return spec.get("type") in {None, "string"}
    if any(_is_object_array(alt) for alt in alternatives):
        return False
    return any(_holds_string(alt) for alt in alternatives)


def _is_object_array(alt: dict[str, Any]) -> bool:
    if alt.get("type") != "array":
        return False
    items = _items(alt)
    return items.get("type") == "object" or "properties" in items or "additionalProperties" in items


def _holds_string(alt: dict[str, Any]) -> bool:
    if alt.get("type") == "string":
        return True
    if alt.get("type") != "array":
        return False
    items = _items(alt)
    return items.get("type") in {None, "string"} and "properties" not in items


def _yaml_scalar(value: Any) -> str | None:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value in ("", None):
        return None
    return str(value)


def _clean_enum(values: list[Any], docs: list[Any]) -> tuple[list[str], list[str]]:
    pairs = list(zip(values, docs, strict=True)) if len(docs) == len(values) else []
    pairs = pairs or [(value, "") for value in values]
    cleaned: list[str] = []
    short: list[str] = []
    for value, doc in pairs:
        rendered = _yaml_scalar(value)
        if rendered is None:
            continue
        cleaned.append(rendered)
        short.append(_short_doc(doc) if isinstance(doc, str) else "")
    return cleaned, short


def _short_doc(markdown: str) -> str:
    text = markdown.strip()
    if "---" in text:
        text = text.split("---")[-1].strip()
    return " ".join(text.split())


def _cap_doc(text: str) -> str:
    return text if len(text) <= DOC_CAP else text[: DOC_CAP - 1].rstrip() + "…"


def _const_of(spec: dict[str, Any]) -> str | None:
    if isinstance(spec.get("const"), str):
        return spec["const"]
    for alt in spec.get("anyOf") or []:
        if isinstance(alt, dict) and isinstance(alt.get("const"), str):
            return alt["const"]
    return None


def _type_name(spec: dict[str, Any], schema: dict[str, Any], is_array: bool) -> str:
    alternatives = [alt for alt in spec.get("anyOf") or [] if isinstance(alt, dict)]
    if (
        is_array
        or spec.get("type") == "array"
        or any(alt.get("type") == "array" for alt in alternatives)
    ):
        return "array"
    if (_unwrap(schema, spec) or {}).get("properties"):
        return "object"
    raw = spec.get("type")
    if isinstance(raw, str) and raw != "null":
        return raw
    for alt in alternatives:
        if isinstance(alt.get("type"), str) and alt["type"] != "null":
            return alt["type"]
        if "$ref" in alt:
            return "object"
    return "string" if spec.get("format") == "date" else "any"


def _unwrap(schema: dict[str, Any], node: dict[str, Any] | None) -> dict[str, Any] | None:
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


def _array_items(spec: dict[str, Any]) -> dict[str, Any] | None:
    if spec.get("type") == "array" and isinstance(spec.get("items"), dict):
        return spec["items"]
    for alt in spec.get("anyOf") or []:
        if (
            isinstance(alt, dict)
            and alt.get("type") == "array"
            and isinstance(alt.get("items"), dict)
        ):
            return alt["items"]
    return None
