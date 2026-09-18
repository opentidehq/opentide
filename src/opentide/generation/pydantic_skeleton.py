"""Render YAML object skeletons by walking Pydantic ``FieldInfo``.

Templates are line-oriented YAML. Optional fields are the same YAML as the
required render with ``#`` hugging each key (issue #223). Nested optionals
are not commented again. JSON Schema ``$ref`` / ``properties`` walking is
not used here.
"""

from __future__ import annotations

import json
import re
import types
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Union, get_args, get_origin

from pydantic.fields import FieldInfo
from pydantic_core import PydanticUndefined

from opentide.models.base import TideModel, field_json_schema_extra

_YAML_UNQUOTED = re.compile(r"^[A-Za-z0-9_./:+-]+$")
_YAML_RESERVED = frozenset({"true", "false", "null", "yes", "no", "on", "off", "y", "n", "~"})
_MULTILINE_NAMES = frozenset({"description", "query", "analysis", "sighting"})
_DATE_NAMES = frozenset({"created", "modified"})
_URI_NAMES = frozenset({"link", "url", "uri", "href"})
_MAX_DEPTH = 24


@dataclass(frozen=True)
class RenderOptions:
    """Options for a skeleton render."""

    schema_id: str | None = None
    required_only: bool = False
    comment_optionals: bool = True


def render_model_template(
    model: type[TideModel],
    *,
    schema_id: str | None = None,
    required_only: bool = False,
    indent: int = 0,
) -> str:
    """Return a YAML skeleton for *model* in declaration order.

    Uncommented keys are required ``FieldInfo`` entries (aliases honoured).
    Optional fields emit as commented blocks: the subtree is live YAML with
    ``#`` hugging each key (nested optionals are not commented again). Path
    fields and ``tide.template.hide`` are omitted. No YAML ``null`` tokens.
    """
    options = RenderOptions(schema_id=schema_id, required_only=required_only)
    lines = _render_model(model, indent=indent, options=options, depth=0)
    text = "\n".join(lines)
    if text:
        text += "\n"
    return text


def write_model_template(
    path: Path,
    model: type[TideModel],
    *,
    schema_id: str | None = None,
    indent: int = 0,
) -> None:
    """Write ``render_model_template`` output to *path*."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_model_template(model, schema_id=schema_id, indent=indent),
        encoding="utf-8",
    )


def uncomment_optional_blocks(text: str) -> str:
    """Strip a leading ``#`` after indent from each non-empty line.

    Used in tests to recover the YAML that authors get by uncommenting a
    commented optional section.
    """
    out: list[str] = []
    for raw in text.splitlines(keepends=True):
        newline = "\n" if raw.endswith("\n") else ""
        line = raw[:-1] if raw.endswith("\n") else raw
        if not line.strip():
            out.append(raw)
            continue
        indent = len(line) - len(line.lstrip(" "))
        rest = line[indent:]
        if rest.startswith("#"):
            line = line[:indent] + rest[1:]
        out.append(line + newline)
    return "".join(out)


def _render_model(
    model: type[TideModel],
    *,
    indent: int,
    options: RenderOptions,
    depth: int,
) -> list[str]:
    if depth > _MAX_DEPTH:
        return []
    identifier = getattr(model, "__schema_identifier__", None)
    if isinstance(identifier, str) and identifier:
        options = RenderOptions(
            schema_id=identifier,
            required_only=options.required_only,
            comment_optionals=options.comment_optionals,
        )
    lines: list[str] = []
    first = True
    for name, field in model.model_fields.items():
        field_lines = _render_field(name, field, indent=indent, options=options, depth=depth)
        if not field_lines:
            continue
        if _wants_spacer(field) and not first and (not lines or lines[-1] != ""):
            lines.append("")
        lines.extend(field_lines)
        first = False
    return lines


def _render_field(
    name: str,
    field: FieldInfo,
    *,
    indent: int,
    options: RenderOptions,
    depth: int,
) -> list[str]:
    extras = field_json_schema_extra(field)
    if extras.get("tide.template.hide"):
        return []
    annotation = field.annotation
    if annotation is None:
        return []
    core, _nullable = _unwrap_annotation(annotation)
    if _is_path_type(core):
        return []
    required = _field_is_required(field)
    if options.required_only and not required:
        return []

    key = _yaml_key(name, field)
    child_options = options
    comment_now = not required and options.comment_optionals
    if comment_now:
        child_options = RenderOptions(
            schema_id=options.schema_id,
            required_only=options.required_only,
            comment_optionals=False,
        )
    value_lines = _render_value(
        name,
        field,
        core,
        indent=indent,
        key=key,
        extras=extras,
        options=child_options,
        depth=depth,
    )
    if comment_now:
        value_lines = _comment_hug_keys(value_lines, indent)
    return value_lines


def _render_value(
    name: str,
    field: FieldInfo,
    core: Any,
    *,
    indent: int,
    key: str,
    extras: dict[str, Any],
    options: RenderOptions,
    depth: int,
) -> list[str]:
    origin = get_origin(core)
    pad = " " * indent

    nested = _tide_model_type(core)
    if nested is not None:
        child = _render_model(nested, indent=indent + 2, options=options, depth=depth + 1)
        return [f"{pad}{key}:"] + child

    if origin is list:
        item = get_args(core)[0] if get_args(core) else str
        return _render_list(
            name,
            field,
            item,
            indent=indent,
            key=key,
            extras=extras,
            options=options,
            depth=depth,
        )

    if origin is dict:
        args = get_args(core)
        key_type = args[0] if args else str
        val_type = args[1] if len(args) > 1 else str
        return _render_dict(
            indent=indent,
            key=key,
            key_type=key_type,
            val_type=val_type,
            options=options,
            depth=depth,
        )

    if _is_multiline(name, extras):
        return [f"{pad}{key}: |", f"{pad}  ..."]

    scalar = _scalar_placeholder(
        name,
        core,
        extras,
        options,
        default=_concrete_default(field),
        yaml_key=key,
    )
    if scalar == "":
        return [f"{pad}{key}: "]
    return [f"{pad}{key}: {scalar}"]


def _render_list(
    name: str,
    field: FieldInfo,
    item: Any,
    *,
    indent: int,
    key: str,
    extras: dict[str, Any],
    options: RenderOptions,
    depth: int,
) -> list[str]:
    pad = " " * indent
    item_core, _ = _unwrap_annotation(item)
    nested = _tide_model_type(item_core)
    header = [f"{pad}{key}:"]
    item_indent = indent + 2
    if nested is not None:
        body = _render_model(nested, indent=item_indent + 2, options=options, depth=depth + 1)
        return header + _list_item_lines(body, item_indent)
    if get_origin(item_core) is dict:
        args = get_args(item_core)
        key_type = args[0] if args else str
        val_type = args[1] if len(args) > 1 else str
        sample_key = _dict_sample_key(key_type)
        sample_val = _scalar_placeholder(
            "value", val_type, {}, options, default=_concrete_default(field)
        )
        value = f" {sample_val}" if sample_val != "" else " "
        return header + [f"{' ' * item_indent}- {sample_key}:{value}"]
    placeholder = _scalar_placeholder(
        name, item_core, extras, options, default=_concrete_default(field)
    )
    dash = f"{' ' * item_indent}-"
    if placeholder == "":
        return header + [f"{dash} "]
    return header + [f"{dash} {placeholder}"]


def _list_item_lines(body: list[str], item_indent: int) -> list[str]:
    """Attach ``- `` to the first body line; keep remaining fields aligned."""
    if not body:
        return [f"{' ' * item_indent}- "]
    first = body[0]
    lead = len(first) - len(first.lstrip(" "))
    rest = first[lead:]
    # ``  name: `` at item_indent+2 → ``  - name: `` at item_indent
    first_line = f"{' ' * item_indent}- {rest}"
    shifted = [first_line]
    for line in body[1:]:
        shifted.append(line)
    return shifted


def _render_dict(
    *,
    indent: int,
    key: str,
    key_type: Any,
    val_type: Any,
    options: RenderOptions,
    depth: int,
) -> list[str]:
    pad = " " * indent
    sample_key = _dict_sample_key(key_type)
    nested = _tide_model_type(val_type)
    header = [f"{pad}{key}:"]
    child_indent = indent + 2
    if nested is not None:
        child = _render_model(nested, indent=child_indent + 2, options=options, depth=depth + 1)
        return header + [f"{' ' * child_indent}{sample_key}:"] + child
    val_core, _ = _unwrap_annotation(val_type)
    if get_origin(val_core) is list:
        return header + [f"{' ' * child_indent}{sample_key}:", f"{' ' * (child_indent + 2)}- "]
    placeholder = _scalar_placeholder("value", val_core, {}, options)
    value = f" {placeholder}" if placeholder != "" else " "
    return header + [f"{' ' * child_indent}{sample_key}:{value}"]


def _scalar_placeholder(
    name: str,
    core: Any,
    extras: dict[str, Any],
    options: RenderOptions,
    *,
    default: Any = PydanticUndefined,
    yaml_key: str | None = None,
) -> str:
    if _is_schema_field(name, yaml_key) and options.schema_id:
        return _format_string(options.schema_id)
    if extras.get("tide.vocab") is not None:
        if default is not PydanticUndefined:
            return _format_scalar(default)
        return ""
    if default is not PydanticUndefined:
        return _format_scalar(default)
    if _is_date_field(name, extras):
        return "YYYY-MM-DD"
    if extras.get("format") == "email":
        return "author@domain.com"
    if extras.get("format") == "uri" or name in _URI_NAMES:
        return "https://"
    literals = _literal_values(core)
    if literals:
        return _format_scalar(literals[0])
    origin = get_origin(core)
    if origin is Union or origin is types.UnionType:
        picked, _ = _unwrap_annotation(core)
        return _scalar_placeholder(name, picked, extras, options, default=default)
    if core is bool or core is Literal[True] or core is Literal[False]:
        return "false"
    if core is int:
        return "3"
    if core is float:
        return "3"
    if extras.get("format") == "number":
        return "3"
    return ""


def _field_is_required(field: FieldInfo) -> bool:
    extras = field_json_schema_extra(field)
    override = extras.get("tide.template.required")
    if override is True:
        return True
    if override is False:
        return False
    return bool(field.is_required())


def _wants_spacer(field: FieldInfo) -> bool:
    return bool(field_json_schema_extra(field).get("tide.template.spacer"))


def _is_multiline(name: str, extras: dict[str, Any]) -> bool:
    if extras.get("tide.template.multiline"):
        return True
    return name in _MULTILINE_NAMES


def _is_date_field(name: str, extras: dict[str, Any]) -> bool:
    if extras.get("format") == "date":
        return True
    return name in _DATE_NAMES


def _yaml_key(name: str, field: FieldInfo) -> str:
    alias = field.serialization_alias or field.alias
    if isinstance(alias, str) and alias:
        return alias
    return name


def _is_schema_field(name: str, yaml_key: str | None) -> bool:
    return name in {"schema_id", "schema", "platform_schema"} or yaml_key == "schema"


def _concrete_default(field: FieldInfo) -> Any:
    default = field.default
    if default is PydanticUndefined or default is None:
        return PydanticUndefined
    return default


def _comment_hug_keys(lines: list[str], indent: int) -> list[str]:
    """Insert ``#`` immediately before the first non-space token on each line.

    Nested optionals must already be live YAML in *lines*; this is the only
    ``#`` for the block. Blank spacer lines become a ``#`` at the field
    indent so a commented optional block stays contiguous for editor
    uncomment.
    """
    commented: list[str] = []
    prefix = " " * indent
    for line in lines:
        if not line.strip():
            commented.append(f"{prefix}#")
            continue
        spaces = len(line) - len(line.lstrip(" "))
        rest = line[spaces:]
        if rest.startswith("#"):
            commented.append(line)
            continue
        commented.append(f"{line[:spaces]}#{rest}")
    return commented


def _unwrap_annotation(annotation: Any) -> tuple[Any, bool]:
    """Strip ``Annotated`` and ``X | None``; pick a concrete union member."""
    optional = False
    current = annotation
    for _ in range(8):
        origin = get_origin(current)
        if origin is Annotated:
            args = get_args(current)
            current = args[0] if args else current
            continue
        if origin in {Union, types.UnionType}:
            args = get_args(current)
            non_none = tuple(arg for arg in args if arg is not type(None))
            if len(non_none) < len(args):
                optional = True
            if len(non_none) == 1:
                current = non_none[0]
                continue
            current = _pick_union(non_none)
            break
        break
    return current, optional


def _pick_union(args: Sequence[Any]) -> Any:
    for arg in args:
        if get_origin(arg) is list:
            return arg
    for arg in args:
        if _tide_model_type(arg) is not None:
            return arg
    for arg in args:
        if arg is not Any:
            return arg
    return args[0] if args else str


def _tide_model_type(annotation: Any) -> type[TideModel] | None:
    origin = get_origin(annotation)
    if origin in {Union, types.UnionType, Annotated}:
        inner, _ = _unwrap_annotation(annotation)
        return _tide_model_type(inner)
    if isinstance(annotation, type):
        try:
            if issubclass(annotation, TideModel):
                return annotation
        except TypeError:
            return None
    return None


def _is_path_type(annotation: Any) -> bool:
    inner, _ = _unwrap_annotation(annotation)
    if inner is Path:
        return True
    if isinstance(inner, type):
        try:
            return issubclass(inner, Path)
        except TypeError:
            return False
    return False


def _literal_values(annotation: Any) -> tuple[Any, ...] | None:
    origin = get_origin(annotation)
    if origin is Literal:
        return get_args(annotation)
    return None


def _dict_sample_key(key_type: Any) -> str:
    core, _ = _unwrap_annotation(key_type)
    if core is int:
        return "1"
    return "key"


def _format_scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, Mapping):
        return ""
    if isinstance(value, (list, tuple)):
        return ""
    return _format_string(str(value))


def _format_string(value: str) -> str:
    if value == "":
        return ""
    if value.lower() in _YAML_RESERVED:
        return json.dumps(value)
    if re.fullmatch(r"[0-9]+", value):
        return json.dumps(value)
    if _YAML_UNQUOTED.match(value):
        return value
    return json.dumps(value)
