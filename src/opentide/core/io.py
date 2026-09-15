"""Shared file I/O helpers for YAML, JSON, and TOML."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from datetime import date, datetime, time
from pathlib import Path
from typing import Any

import orjson
import tomli_w
import yaml

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:
    from yaml import SafeLoader as YamlLoader

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def yaml_loader_name() -> str:
    """Return the active YAML loader class name (for benchmarks/diagnostics)."""
    return YamlLoader.__name__


def stringify_yaml_temporals(value: Any) -> Any:
    """Replace YAML timestamp objects with ISO-8601 strings.

    PyYAML's safe loaders parse unquoted ``YYYY-MM-DD`` and timestamp scalars
    into ``datetime.date`` / ``datetime.datetime``. Tide schemas declare those
    fields as strings, and ``json.dumps`` cannot serialize native date objects.
    """
    if isinstance(value, datetime):
        rendered = value.isoformat()
        if rendered.endswith("+00:00"):
            return rendered[:-6] + "Z"
        return rendered
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, dict):
        return {
            stringify_yaml_temporals(key): stringify_yaml_temporals(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [stringify_yaml_temporals(item) for item in value]
    return value


def json_timestamp_default(value: Any) -> str:
    """``json.dumps`` ``default=`` hook for leftover YAML date/time objects."""
    if isinstance(value, (date, time)):
        converted = stringify_yaml_temporals(value)
        if isinstance(converted, str):
            return converted
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def parse_yaml(text: str) -> Any:
    """Parse YAML text using the fast safe loader when available."""
    return stringify_yaml_temporals(yaml.load(text, Loader=YamlLoader))


def load_yaml(path: Path) -> Any:
    """Load YAML from *path*."""
    return parse_yaml(path.read_text(encoding="utf-8"))


def load_json(path: Path) -> Any:
    """Load JSON from *path*."""
    return orjson.loads(path.read_bytes())


def parse_json(data: bytes | str) -> Any:
    """Parse JSON bytes or text."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return orjson.loads(data)


def dump_json(
    data: Any,
    *,
    indent: bool = False,
    append_newline: bool = True,
    default: Any = None,
) -> bytes:
    """Serialize *data* as JSON bytes."""
    option = orjson.OPT_INDENT_2 if indent else 0
    if default is not None:
        payload = orjson.dumps(data, option=option, default=default)
    else:
        payload = orjson.dumps(data, option=option)
    if append_newline:
        return payload + b"\n"
    return payload


def dump_json_text(
    data: Any,
    *,
    indent: bool = False,
    append_newline: bool = True,
    default: Any = None,
) -> str:
    """Serialize *data* as a JSON string."""
    return dump_json(
        data,
        indent=indent,
        append_newline=append_newline,
        default=default,
    ).decode("utf-8")


def load_toml(path: Path) -> dict[str, Any]:
    """Load TOML from *path*."""
    return tomllib.loads(path.read_text(encoding="utf-8"))


def dump_toml(data: Mapping[str, Any]) -> str:
    """Serialize *data* as TOML text."""
    return tomli_w.dumps(dict(data))


def dump_yaml(
    path: Path,
    data: Mapping[str, Any],
    *,
    dumper: type[yaml.Dumper] | None = None,
) -> None:
    """Write *data* as YAML to *path*, creating parent directories."""
    if dumper is None:
        from opentide.core.files import IndentFullDumper

        dumper = IndentFullDumper
    write_text(path, yaml.dump(dict(data), Dumper=dumper, sort_keys=False))


def write_text(path: Path, content: str) -> None:
    """Write UTF-8 text to *path*, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
