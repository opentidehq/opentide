"""Bump schema pin manifests when a vocabulary ingest opens a new minor contract."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from opentide.generation.vocabulary import parse_semver

_PIN_FAMILIES = ("threat", "objective", "rule")
_ASSIGN = re.compile(r'^((?:[ \t]*)"[^"]+"[ \t]*=[ \t]*)"([^"]+)::(\d+\.\d+)"([ \t]*)$')


@dataclass(frozen=True)
class PinChange:
    """One contract identifier replacement in a pin file."""

    path: Path
    field: str
    old_version: str
    new_version: str


def should_bump(current: str, target: str) -> bool:
    """Return whether *current* ``M.m`` should advance to *target* (same major, higher minor)."""
    old = parse_semver(current)
    new = parse_semver(target)
    if new[0] != old[0]:
        return False
    return new > old


def bump_pin_contents(
    text: str, field_versions: Mapping[str, str]
) -> tuple[str, list[tuple[str, str, str]]]:
    """Replace ``field::M.m`` pin values in *text* when a newer same-major minor is supplied.

    Never advances a pin to a new major. Returns the rewritten text and
    ``(field, old_version, new_version)`` triples.
    """
    changes: list[tuple[str, str, str]] = []
    lines: list[str] = []
    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        core = line[:-1] if line.endswith("\n") else line
        if core.endswith("\r"):
            core = core[:-1]
            if newline:
                newline = "\r\n"
        match = _ASSIGN.match(core)
        if match is None:
            lines.append(line)
            continue
        prefix, field, version, trailing = match.groups()
        target = field_versions.get(field)
        if not target or not should_bump(version, target):
            lines.append(line)
            continue
        changes.append((field, version, target))
        lines.append(f'{prefix}"{field}::{target}"{trailing or ""}{newline}')
    return "".join(lines), changes


def bump_pin_file(path: Path, field_versions: Mapping[str, str]) -> list[PinChange]:
    """Apply pin bumps to one TOML file. No-op when the file is missing or unchanged."""
    if not path.is_file() or not field_versions:
        return []
    original = path.read_text(encoding="utf-8")
    rewritten, raw_changes = bump_pin_contents(original, field_versions)
    if rewritten == original:
        return []
    path.write_text(rewritten, encoding="utf-8")
    return [
        PinChange(path=path, field=field, old_version=old, new_version=new)
        for field, old, new in raw_changes
    ]


def bump_pin_dir(directory: Path, field_versions: Mapping[str, str]) -> list[PinChange]:
    """Bump every family pin file under *directory* (``threat.toml``, …)."""
    changes: list[PinChange] = []
    for family in _PIN_FAMILIES:
        changes.extend(bump_pin_file(directory / f"{family}.toml", field_versions))
    return changes
