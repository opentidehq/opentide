"""Runtime enum registry for vocabulary-backed schema fields."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EnumEntry:
    """Resolved enum values and parallel markdown descriptions."""

    values: list[str] = field(default_factory=list)
    descriptions: list[str] = field(default_factory=list)

    def validate_lengths(self) -> None:
        if self.descriptions and len(self.values) != len(self.descriptions):
            raise ValueError("enum values and descriptions must have equal length")


class EnumRegistry:
    """In-memory registry replacing import-time EnumResolver lookups."""

    def __init__(self) -> None:
        self._entries: dict[str, EnumEntry] = {}

    def register(
        self, vocab: str, values: list[str], descriptions: list[str] | None = None
    ) -> None:
        entry = EnumEntry(values=list(values), descriptions=list(descriptions or values))
        entry.validate_lengths()
        self._entries[vocab] = entry

    def resolve(self, vocab: str) -> tuple[list[str], list[str]]:
        entry = self._entries.get(vocab)
        if entry is None:
            return ([""], [""])
        return (list(entry.values), list(entry.descriptions))

    def clear(self) -> None:
        self._entries.clear()

    def vocabularies(self) -> frozenset[str]:
        return frozenset(self._entries)
