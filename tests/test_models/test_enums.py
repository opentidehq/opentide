"""EnumRegistry behaviour."""

from __future__ import annotations

import pytest

from opentide.models.enums import EnumEntry, EnumRegistry


def test_enum_entry_validate_lengths_ok() -> None:
    EnumEntry(values=["a"], descriptions=["A"]).validate_lengths()


def test_enum_entry_validate_lengths_mismatch() -> None:
    with pytest.raises(ValueError):
        EnumEntry(values=["a"], descriptions=["A", "B"]).validate_lengths()


def test_enum_registry_register_and_resolve() -> None:
    registry = EnumRegistry()
    registry.register("severity", ["High", "Low"], ["High severity", "Low severity"])
    values, descriptions = registry.resolve("severity")
    assert values == ["High", "Low"]
    assert descriptions == ["High severity", "Low severity"]


def test_enum_registry_resolve_missing() -> None:
    registry = EnumRegistry()
    assert registry.resolve("missing") == ([""], [""])


def test_enum_registry_clear_and_vocabularies() -> None:
    registry = EnumRegistry()
    registry.register("impact", ["A"], ["A"])
    assert registry.vocabularies() == frozenset({"impact"})
    registry.clear()
    assert registry.vocabularies() == frozenset()
