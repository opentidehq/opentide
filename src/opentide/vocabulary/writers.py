"""TOML serialization for vocabulary documents."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from opentide.core.io import dump_toml_table, format_toml_value

_AOT_ARRAY_FIELDS = frozenset({"entries", "keys"})


def _dump_aot_table(section: str, item: Mapping[str, Any]) -> str:
    lines = [f"[[{section}]]"]
    for key, value in item.items():
        lines.append(f"{key} = {format_toml_value(value)}")
    return "\n".join(lines)


def dump_vocab_document(document: Mapping[str, Any]) -> str:
    """Render a vocabulary document as valid TOML with array-of-tables sections."""
    payload = dict(document)
    if "keys" not in payload:
        payload["keys"] = []

    header: dict[str, Any] = {}
    array_sections: list[tuple[str, list[Mapping[str, Any]]]] = []

    for key, value in payload.items():
        if key in _AOT_ARRAY_FIELDS and isinstance(value, list):
            items: list[Mapping[str, Any]] = [item for item in value if isinstance(item, Mapping)]
            array_sections.append((key, items))
        else:
            header[key] = value

    parts = [dump_toml_table(header).rstrip()]
    for section, items in array_sections:
        for item in items:
            parts.append(_dump_aot_table(section, item))
    return "\n".join(parts) + "\n"
