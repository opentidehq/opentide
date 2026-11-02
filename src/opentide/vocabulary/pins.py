"""Read which vocabulary fields the schema pin manifests reference.

The ingest never writes pins. A shipped schema revision keeps the contracts it
pins; adopting a newer contract is a new schema revision (``threat::1.1``),
made by hand in specifications (``specs/versioning.md``, RFC 0003).
"""

from __future__ import annotations

import re
from pathlib import Path

_PIN_FAMILIES = ("threat", "objective", "rule")
_ASSIGN = re.compile(r'^[ \t]*"[^"]+"[ \t]*=[ \t]*"([^"]+)::\d+\.\d+"[ \t]*$')


def vocab_fields_in_pin_contents(contents: str) -> frozenset[str]:
    """Return vocab field names referenced as pin values (``field::M.m``)."""
    fields: set[str] = set()
    for line in contents.splitlines():
        match = _ASSIGN.match(line.rstrip("\r"))
        if match is not None:
            fields.add(match.group(1))
    return frozenset(fields)


def vocab_fields_in_pin_dir(pin_dir: Path) -> frozenset[str]:
    """Union of vocab field names referenced by family pin files in *pin_dir*."""
    if not pin_dir.is_dir():
        return frozenset()
    fields: set[str] = set()
    for family in _PIN_FAMILIES:
        path = pin_dir / f"{family}.toml"
        if path.is_file():
            fields |= vocab_fields_in_pin_contents(path.read_text(encoding="utf-8"))
    return frozenset(fields)


def vocab_fields_in_pin_directories(pin_dirs: list[Path]) -> frozenset[str]:
    """Union of vocab field names referenced across schema pin directories."""
    fields: set[str] = set()
    for pin_dir in pin_dirs:
        fields |= vocab_fields_in_pin_dir(pin_dir)
    return frozenset(fields)
