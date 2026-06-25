"""Shared file I/O helpers for YAML, JSON, and TOML."""

from __future__ import annotations

import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import orjson
import yaml

try:
    from yaml import CSafeLoader as YamlLoader
except ImportError:
    from yaml import SafeLoader as YamlLoader

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # ty: ignore[unresolved-import]


def yaml_loader_name() -> str:
    """Return the active YAML loader class name (for benchmarks/diagnostics)."""
    return YamlLoader.__name__


def parse_yaml(text: str) -> Any:
    """Parse YAML text using the fast safe loader when available."""
    return yaml.load(text, Loader=YamlLoader)


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


def parse_toml(text: str) -> dict[str, Any]:
    """Parse TOML text."""
    return tomllib.loads(text)


def format_toml_value(value: Any) -> str:
    """Format a scalar or inline list value for TOML output."""
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        inner = ", ".join(format_toml_value(item) for item in value)
        return f"[{inner}]"
    raise TypeError(f"Unsupported TOML value type: {type(value).__name__}")


def dump_toml_table(data: Mapping[str, Any]) -> str:
    """Serialize a flat TOML table (no nested dict values)."""
    lines = [f"{key} = {format_toml_value(value)}" for key, value in data.items()]
    return "\n".join(lines)


def dump_toml(data: Mapping[str, Any]) -> str:
    """Serialize *data* as a flat TOML document."""
    if not data:
        return ""
    return dump_toml_table(data) + "\n"


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
