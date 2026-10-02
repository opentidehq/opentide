"""Current-state ledger at ``.opentide/states/sharing.jsonl``.

The file is one JSON object per line. It records what was shared, not a
history of attempts. A skip or a failure must not call :meth:`ShareLedger.put`
or :meth:`ShareLedger.discard`. Secrets do not belong in a line.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from opentide.registry.discovery import discover_workspace

_IDENTITY = ("object_uuid", "integration", "target")


def ledger_path(workspace: Path | None = None) -> Path:
    """Path of the sharing ledger for *workspace*."""
    root = workspace or discover_workspace()
    return root / ".opentide" / "states" / "sharing.jsonl"


class ShareLedger:
    """In-memory view of the ledger. :meth:`save` rewrites the file."""

    def __init__(self, path: Path, entries: list[dict[str, Any] | str] | None = None) -> None:
        self.path = path
        self._entries: list[dict[str, Any] | str] = list(entries or [])

    @classmethod
    def load(cls, path: Path | None = None, *, workspace: Path | None = None) -> ShareLedger:
        """Read the ledger. A missing or empty file is an empty ledger."""
        target = path or ledger_path(workspace)
        if not target.is_file():
            return cls(target)
        text = target.read_text(encoding="utf-8")
        if text.strip() == "":
            return cls(target)
        parsed: list[dict[str, Any] | str] = []
        for line in text.splitlines():
            if not line.strip():
                continue
            parsed.append(_parse_line(line))
        return cls(target, _collapse(parsed))

    def records(self) -> tuple[dict[str, Any], ...]:
        """Identity lines, last duplicate kept, opaque lines omitted."""
        found: list[dict[str, Any]] = []
        for entry in self._entries:
            if isinstance(entry, dict) and _triple(entry) is not None:
                found.append(dict(entry))
        return tuple(found)

    def get(self, object_uuid: str, integration: str, target: str) -> dict[str, Any] | None:
        """Return the last line for the triple, including an unknown ``state``."""
        found: dict[str, Any] | None = None
        wanted = (object_uuid, integration, target)
        for entry in self._entries:
            if isinstance(entry, dict) and _triple(entry) == wanted:
                found = entry
        return None if found is None else dict(found)

    def put(self, record: Mapping[str, Any]) -> None:
        """Replace every line for this triple with *record*."""
        triple = _require_triple(record)
        self._entries = [
            entry
            for entry in self._entries
            if not (isinstance(entry, dict) and _triple(entry) == triple)
        ]
        self._entries.append(dict(record))

    def discard(self, object_uuid: str, integration: str, target: str) -> bool:
        """Remove the triple. Returns whether a line was present."""
        wanted = (object_uuid, integration, target)
        kept: list[dict[str, Any] | str] = []
        removed = False
        for entry in self._entries:
            if isinstance(entry, dict) and _triple(entry) == wanted:
                removed = True
                continue
            kept.append(entry)
        self._entries = kept
        return removed

    def save(self) -> None:
        """Rewrite the file, collapsing duplicate triples to their last line."""
        self._entries = _collapse(self._entries)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = "".join(_render(entry) for entry in self._entries)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, self.path)

    def __len__(self) -> int:
        return sum(1 for entry in self._entries if isinstance(entry, dict) and _triple(entry))


def _parse_line(line: str) -> dict[str, Any] | str:
    try:
        loaded = json.loads(line)
    except json.JSONDecodeError:
        return line
    if isinstance(loaded, dict):
        return loaded
    return line


def _triple(entry: Mapping[str, Any]) -> tuple[str, str, str] | None:
    values: list[str] = []
    for key in _IDENTITY:
        value = entry.get(key)
        if not isinstance(value, str) or not value:
            return None
        values.append(value)
    return values[0], values[1], values[2]


def _require_triple(record: Mapping[str, Any]) -> tuple[str, str, str]:
    triple = _triple(record)
    if triple is None:
        raise ValueError("A ledger line needs object_uuid, integration, and target.")
    return triple


def _collapse(entries: list[dict[str, Any] | str]) -> list[dict[str, Any] | str]:
    """Keep the last JSON line for each triple. Opaque lines stay where they are."""
    last_index: dict[tuple[str, str, str], int] = {}
    for index, entry in enumerate(entries):
        if isinstance(entry, dict):
            triple = _triple(entry)
            if triple is not None:
                last_index[triple] = index
    collapsed: list[dict[str, Any] | str] = []
    for index, entry in enumerate(entries):
        if isinstance(entry, dict):
            triple = _triple(entry)
            if triple is not None and last_index[triple] != index:
                continue
        collapsed.append(entry)
    return collapsed


def _render(entry: dict[str, Any] | str) -> str:
    if isinstance(entry, str):
        return entry if entry.endswith("\n") else f"{entry}\n"
    return json.dumps(entry, ensure_ascii=False, separators=(",", ":")) + "\n"
