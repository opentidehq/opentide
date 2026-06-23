"""Validation scope resolution (full registry vs narrow targets)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class ValidationScope:
    """Defines which objects are validated (preflight always uses the full index)."""

    mode: Literal["full", "narrow"]
    targets: frozenset[str] = frozenset()
    object_types: frozenset[str] = frozenset()

    @classmethod
    def full(cls) -> ValidationScope:
        return cls(mode="full")

    @classmethod
    def narrow(
        cls,
        *,
        files: frozenset[str] | None = None,
        uuids: frozenset[str] | None = None,
        types: frozenset[str] | None = None,
    ) -> ValidationScope:
        targets: set[str] = set()
        if files:
            targets.update(files)
        if uuids:
            targets.update(uuids)
        return cls(
            mode="narrow",
            targets=frozenset(targets),
            object_types=frozenset(types or ()),
        )

    def includes_object(
        self,
        uuid: str,
        object_type: str,
        *,
        file_name: str | None = None,
    ) -> bool:
        if self.mode == "full":
            return True
        if self.object_types and object_type not in self.object_types:
            return False
        if not self.targets:
            return bool(self.object_types)
        if uuid in self.targets:
            return True
        return bool(file_name and file_name in self.targets)
