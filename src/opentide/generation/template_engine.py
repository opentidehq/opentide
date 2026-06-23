"""Shared template emission engine — YAML text generation utilities."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, cast

import yaml

from opentide.core.files import IndentFullDumper
from opentide.core.logging import log as default_log
from opentide.core.registry import OpenTide


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
        default_log(
            "WARNING",
            "Could not the expected template",
            dot_path,
            "This is non blocking, but check why the template could not be fetched",
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


def get_required(metaschema: dict[str, Any], required_list: list[str]) -> list[str]:
    for key in metaschema.keys():
        if key in required_list:
            if metaschema[key].get("type") == "object":
                if r := metaschema[key].get("required"):
                    required_list.extend(r)
                    props = metaschema[key].get("properties")
                    if props:
                        required_list.extend(get_required(props, required_list=required_list))
                if fr := metaschema[key].get("tide.template.force-required"):
                    required_list.extend(fr)
    return required_list


def definition_handler(entry_point: str) -> dict[str, Any]:
    from opentide.generation.pydantic_metaschema import DEFINITION_MODELS, build_model_schema_source

    return build_model_schema_source(DEFINITION_MODELS[entry_point])


def gen_template(metaschema: dict[str, Any], required: list[str]) -> dict[str, Any]:
    body: dict[str, Any] = {}
    for key in metaschema:
        if metaschema[key].get("tide.template.hide"):
            continue
        if metadef := metaschema[key.replace("#", "")].get("tide.meta.definition"):
            if key not in required:
                key = "#" + key
            if metadef is True:
                temp = definition_handler(key.replace("#", ""))
                definition_required = list(temp.get("required", []))
                definition_required.extend(temp.get("tide.template.force-required", []))
            else:
                temp = definition_handler(metadef)
                definition_required = list(temp.get("required", []))
                definition_required.extend(temp.get("tide.template.force-required", []))

            template = gen_template({key.replace("#", ""): temp}, required=definition_required)
            resolved = (
                template.get(key) or template.get(key.replace("#", "")) or template.get("#" + key)
            )
            if resolved is not None:
                body[key] = resolved
            continue

        keyword_type = metaschema[key].get("type") or "string"
        if isinstance(keyword_type, list):
            keyword_type = str(keyword_type[0])

        if keyword_type == "object":
            if key not in required:
                if config := metaschema[key].get("tide.template.config.required"):
                    if fetch_config_template(config) == "False":
                        key = "#" + key
                else:
                    key = "#" + key

            if "recomposition" in metaschema[key.replace("#", "")].keys():
                recomp_cat = metaschema[key.replace("#", "")]["recomposition"]
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
                field = metaschema[key.replace("#", "")]
                if "additionalProperties" in field.keys():
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
                    body[key] = gen_template(field.get("properties", {}), required=required)

        elif "items" in metaschema[key].keys() and "properties" in metaschema[key].get("items", {}):
            if key in required:
                sub_req = metaschema[key]["items"]["required"]
            else:
                key = "#" + key
                sub_req = []

            values = gen_template(
                metaschema[key.replace("#", "")]["items"]["properties"],
                required=sub_req,
            )
            if sub_req == [] and values:
                first_key = list(values)[0]
                commented_first_key = "Comment out " + first_key.replace("#", "")
                values = {commented_first_key: values.pop(first_key), **values}
            body[key] = [values]
        else:
            content = "blank"
            local_required = key in required

            if config := metaschema[key].get("tide.template.config.required"):
                enabled = fetch_config_template(config)
                if enabled == "True":
                    local_required = True
                elif enabled == "False":
                    local_required = False

            if config_path := metaschema[key].get("tide.template.config.default.enabled"):
                if fetch_config_template(config_path) != "False":
                    if config_path := metaschema[key].get("tide.template.config.default"):
                        content = fetch_config_template(config_path)
                        if metaschema[key].get("tide.template.multiline"):
                            if not content:
                                content = "..."
                            if local_required:
                                content = content.replace("\n\n", "\nforce_space")
                            else:
                                content = "\n".join(["#" + line for line in content.split("\n")])
                            content = "|\n'" + content

            if metaschema[key].get("tide.template.required") is True:
                local_required = True
            if metaschema[key].get("tide.template.required") is False:
                local_required = False
            elif metaschema[key].get("format") == "date":
                content = "YYYY-MM-DD"
            elif metaschema[key].get("format") == "number":
                content = "3"
            elif metaschema[key].get("format") == "email":
                content = "author@domain.com"
            elif metaschema[key].get("format") == "uri":
                content = "https://"
            elif metaschema[key].get("tide.template.multiline"):
                content = "|\n'..." if local_required else "|\n'#..."
            elif "default" in metaschema[key]:
                content = metaschema[key]["default"]
            elif "const" in metaschema[key]:
                content = metaschema[key]["const"]

            if metaschema[key].get("tide.template.no-space"):
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
    make_spaces(template_path, spacing_properties)
    if indent is not None:
        indent_template(template_path, indent)
