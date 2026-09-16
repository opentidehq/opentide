"""Shared template emission engine — YAML text generation utilities."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable, cast

import yaml

from opentide.core.files import IndentFullDumper
from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide

logger = get_logger(__name__)


def _config_index() -> dict[str, Any]:
    return cast(dict[str, Any], OpenTide.Configurations.Index)


def fetch_config_template(dot_path: str) -> str:
    config_index = OpenTide.Configurations.Index
    config_path = dot_path.split(".")
    key = config_path[0]
    while key != config_path[-1]:
        if key in config_index:
            config_index = config_index[key]
            key = config_path[config_path.index(key) + 1]
        else:
            raise ValueError(f"Key : {key} could not be found in path {dot_path}")

    try:
        return str(config_index[key]).strip()
    except Exception:
        logger.warning(
            "template_fetch_failed",
            dot_path=dot_path,
            detail="Could not the expected template",
            advice="This is non blocking, but check why the template could not be fetched",
        )
        return ""


def replace_strings_in_file(file_path: Path | str, strings: list[str], replacement: str) -> bool:
    path = Path(file_path)
    buffer: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines(keepends=True):
        for word in strings:
            if word in line:
                line = line.replace(word, replacement)
        buffer.append(line)
    path.write_text("".join(buffer), encoding="utf-8")
    return True


def remove_blanks(path: Path | str) -> bool:
    file_path = Path(path)
    clean = "".join(
        line
        for line in file_path.read_text(encoding="utf-8").splitlines(keepends=True)
        if not line.isspace()
    )
    file_path.write_text(clean, encoding="utf-8")
    return True


def get_required(
    metaschema: dict[str, Any],
    required_list: list[str],
    defs: dict[str, Any] | None = None,
) -> list[str]:
    defs = defs or {}
    for key in metaschema.keys():
        field = metaschema[key]
        if not isinstance(field, dict):
            continue
        resolved = resolve_field_schema(field, defs)
        if key in required_list:
            if resolved.get("type") == "object":
                if r := resolved.get("required"):
                    required_list.extend(r)
                    props = resolved.get("properties")
                    if props:
                        required_list.extend(get_required(props, required_list, defs))
                if fr := resolved.get("tide.template.force-required"):
                    required_list.extend(fr)
    return required_list


def _local_required(schema: dict[str, Any]) -> list[str]:
    """Return this object's required names, not an ancestor's flattened list."""
    names: list[str] = []
    required = schema.get("required")
    if isinstance(required, list):
        names.extend(str(item) for item in required)
    extra = schema.get("tide.template.force-required")
    if isinstance(extra, list):
        names.extend(str(item) for item in extra)
    return names


_OPTIONAL_KEY_COMMENT = re.compile(r"^#[A-Za-z0-9_&.-]+\s*:")


def comment_optional_subtrees(text: str) -> str:
    """Comment nested lines under a dumped ``#key:`` parent.

    Hash-prefixed keys become YAML comments. Nested live lines must also be
    commented or they attach to the previous real mapping (issue #209).
    Uncommenting the whole block restores valid structure::

        #organisation:
        #  uuid:
        #  name:
    """
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    commented_indent: int | None = None
    for line in lines:
        raw = line[:-1] if line.endswith("\n") else line
        newline = "\n" if line.endswith("\n") else ""
        if not raw.strip():
            out.append(line)
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.lstrip(" ")
        list_item = stripped.startswith("- ") or stripped.startswith("#-")
        if commented_indent is not None and indent <= commented_indent:
            if not (list_item and indent == commented_indent):
                commented_indent = None
        if commented_indent is not None and indent > commented_indent:
            if not stripped.startswith("#"):
                raw = raw[:commented_indent] + "#" + raw[commented_indent:]
            out.append(raw + newline)
            continue
        if _OPTIONAL_KEY_COMMENT.match(stripped):
            commented_indent = indent
        out.append(line)
    return "".join(out)


def _is_null_type(node: dict[str, Any]) -> bool:
    return node.get("type") == "null"


def _merge_ref_target(node: dict[str, Any], defs: dict[str, Any]) -> dict[str, Any]:
    ref = node.get("$ref")
    if not isinstance(ref, str):
        return dict(node)
    name = ref.rsplit("/", 1)[-1]
    target = defs.get(name)
    if not isinstance(target, dict):
        return dict(node)
    merged = dict(target)
    for key, value in node.items():
        if key != "$ref":
            merged[key] = value
    return merged


def resolve_field_schema(
    field: dict[str, Any], defs: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Expand ``$ref`` and Tide-nullable ``anyOf``/``oneOf`` against ``$defs``.

    Nested Tide models emit as ``{"$ref": "#/$defs/ThreatBody"}`` with no ``type``
    or ``properties``. Without this step, ``gen_template`` treats them as strings.
    """
    defs = defs or {}
    resolved = _merge_ref_target(field, defs)
    alts = resolved.get("anyOf") or resolved.get("oneOf")
    if isinstance(alts, list):
        non_null: list[dict[str, Any]] = []
        for alt in alts:
            if not isinstance(alt, dict):
                continue
            branch = _merge_ref_target(alt, defs)
            if _is_null_type(branch):
                continue
            non_null.append(branch)
        if len(non_null) == 1:
            branch = resolve_field_schema(non_null[0], defs)
            for key, value in resolved.items():
                if key not in {"anyOf", "oneOf", "$ref"} and key not in branch:
                    branch[key] = value
            resolved = branch
        elif non_null:
            preferred = next(
                (item for item in non_null if item.get("type") == "object" or "properties" in item),
                next((item for item in non_null if item.get("type") == "array"), non_null[0]),
            )
            branch = resolve_field_schema(preferred, defs)
            for key, value in resolved.items():
                if key not in {"anyOf", "oneOf", "$ref"} and key not in branch:
                    branch[key] = value
            resolved = branch

    properties = resolved.get("properties")
    if isinstance(properties, dict):
        resolved["properties"] = {
            name: resolve_field_schema(child, defs) if isinstance(child, dict) else child
            for name, child in properties.items()
        }
    items = resolved.get("items")
    if isinstance(items, dict):
        resolved["items"] = resolve_field_schema(items, defs)
    return resolved


def definition_handler(entry_point: str) -> dict[str, Any]:
    from opentide.generation.pydantic_metaschema import DEFINITION_MODELS, build_model_schema_source

    return build_model_schema_source(DEFINITION_MODELS[entry_point])


def gen_template(
    metaschema: dict[str, Any],
    required: list[str],
    defs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    defs = defs or {}
    body: dict[str, Any] = {}
    for original_key, raw in metaschema.items():
        if not isinstance(raw, dict):
            continue
        if raw.get("tide.template.hide"):
            continue
        key = original_key
        if metadef := raw.get("tide.meta.definition"):
            if key not in required:
                key = "#" + key
            if metadef is True:
                temp = definition_handler(key.replace("#", ""))
            else:
                temp = definition_handler(metadef)
            nested_defs = temp.get("$defs") if isinstance(temp.get("$defs"), dict) else defs
            properties = temp.get("properties")
            if isinstance(properties, dict):
                body[key] = gen_template(
                    properties,
                    required=_local_required(temp),
                    defs=nested_defs if isinstance(nested_defs, dict) else defs,
                )
            continue

        field = resolve_field_schema(raw, defs)
        keyword_type = field.get("type") or "string"
        if isinstance(keyword_type, list):
            keyword_type = str(keyword_type[0])
        if not field.get("type") and field.get("properties"):
            keyword_type = "object"

        if keyword_type == "object":
            if key not in required:
                if config := field.get("tide.template.config.required"):
                    if fetch_config_template(config) == "False":
                        key = "#" + key
                else:
                    key = "#" + key

            if "recomposition" in field:
                recomp_cat = field["recomposition"]
                recomp_entries: dict[str, str] = {}
                config_index = _config_index()
                for entry in config_index[recomp_cat]:
                    recomp_entry = config_index[recomp_cat][entry]
                    try:
                        if recomp_entry["tide"]["enabled"] is True:
                            recomp_entries[f"#{entry}"] = "blank"
                    except Exception:
                        if recomp_entry["platform"]["enabled"] is True:
                            recomp_entries[f"#{entry}"] = "blank"
                body[key] = recomp_entries
            else:
                if "additionalProperties" in field:
                    if not isinstance(field["additionalProperties"], bool):
                        sample = field.get("additionalProperties", {}).get("example") or "example"
                        if sample not in field.get("additionalProperties", {}).get("required", []):
                            sample = "#" + str(sample)
                        body[key] = {sample: "blank"}
                if "patternProperties" in field:
                    first_item = list(field["patternProperties"])[0]
                    sample = field["patternProperties"][first_item].get("example")
                    if sample not in field.get("patternProperties", {})[first_item].get(
                        "required", []
                    ):
                        sample = "#" + str(sample)
                    body[key] = {sample: "blank"} if sample else {}
                elif "properties" in field:
                    nested = gen_template(
                        field.get("properties", {}),
                        required=_local_required(field),
                        defs=defs,
                    )
                    body[key] = nested

        elif "items" in field and "properties" in field.get("items", {}):
            items = field["items"]
            if key in required:
                sub_req = _local_required(items)
            else:
                key = "#" + key
                sub_req = []

            values = gen_template(
                items["properties"],
                required=sub_req,
                defs=defs,
            )
            if sub_req == [] and values:
                first_key = list(values)[0]
                commented_first_key = "Comment out " + first_key.replace("#", "")
                values = {commented_first_key: values.pop(first_key), **values}
            body[key] = [values]
        else:
            content = "blank"
            local_required = key in required

            if config := field.get("tide.template.config.required"):
                enabled = fetch_config_template(config)
                if enabled == "True":
                    local_required = True
                elif enabled == "False":
                    local_required = False

            if config_path := field.get("tide.template.config.default.enabled"):
                if fetch_config_template(config_path) != "False":
                    if config_path := field.get("tide.template.config.default"):
                        content = fetch_config_template(config_path)
                        if field.get("tide.template.multiline"):
                            if not content:
                                content = "..."
                            if local_required:
                                content = content.replace("\n\n", "\nforce_space")
                            else:
                                content = "\n".join(["#" + line for line in content.split("\n")])
                            content = "|\n'" + content

            if field.get("tide.template.required") is True:
                local_required = True
            if field.get("tide.template.required") is False:
                local_required = False
            elif field.get("format") == "date":
                content = "YYYY-MM-DD"
            elif field.get("format") == "number":
                content = "3"
            elif field.get("format") == "email":
                content = "author@domain.com"
            elif field.get("format") == "uri":
                content = "https://"
            elif field.get("tide.template.multiline"):
                content = "|\n'..." if local_required else "|\n'#..."
            elif "default" in field:
                content = field["default"]
            elif "const" in field:
                content = field["const"]

            if field.get("tide.template.no-space"):
                content = "no-space" + str(content)

            if keyword_type == "array":
                if not local_required:
                    key = "#" + key
                    content = "Comment out"
                body[key] = [content]
            else:
                if not local_required:
                    key = "#" + key
                body[key] = content

    return body


def make_spaces(template_path: Path | str, metaschema: dict[str, Any]) -> bool:
    path = Path(template_path)
    template = path.read_text(encoding="utf-8").splitlines(keepends=True)
    spaced: list[str] = []
    for line in template:
        key = line.split(":")[0].replace(" ", "")
        force_space = "force_space" in line
        no_space = "no-space" in line
        from opentide.generation.pydantic_metaschema import lookup_schema_extra

        spacer = lookup_schema_extra(metaschema, key.replace("#", ""), "tide.template.spacer")
        key_type = lookup_schema_extra(metaschema, key.replace("#", ""), "type")
        if key_type == "object" or spacer or force_space:
            if spacer is not False and not no_space:
                spaced.append("\n")
            if force_space:
                line = line.replace("force_space", "")
            if no_space:
                line = line.replace("no-space", "")
        spaced.append(line)
    path.write_text("".join(spaced), encoding="utf-8")
    return True


def indent_template(template_path: Path | str, identation: int) -> bool:
    path = Path(template_path)
    indented = [
        " " * identation + line
        for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
    ]
    path.write_text("".join(indented), encoding="utf-8")
    return True


def emit_template_file(
    template_path: Path,
    template_body: dict[str, Any],
    *,
    placeholders: dict[str, str] | None = None,
    spacing_properties: dict[str, Any],
    indent: int | None,
    log: Callable[..., Any] | None = None,
) -> None:
    """Write a generated template YAML file with post-processing."""
    template_path.parent.mkdir(parents=True, exist_ok=True)
    with template_path.open("w+", encoding="utf-8") as output:
        yaml.dump(template_body, output, sort_keys=False, Dumper=IndentFullDumper)

    replace_strings_in_file(template_path, ["- Comment out"], "#-")
    replace_strings_in_file(template_path, ["blank", "'"], "")
    replace_strings_in_file(template_path, ["spacer"], "    ")

    for placeholder, value in (placeholders or {}).items():
        replace_strings_in_file(template_path, [f"${placeholder}"], value)

    remove_blanks(template_path)
    template_path.write_text(
        comment_optional_subtrees(template_path.read_text(encoding="utf-8")),
        encoding="utf-8",
    )
    make_spaces(template_path, spacing_properties)
    if indent is not None:
        indent_template(template_path, indent)
