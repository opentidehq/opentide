"""Extended tests for RuntimeEnumResolver and vocab enum building."""

from __future__ import annotations

from opentide.generation.vocabulary import VocabularyDefinition, VocabularyEntry, VocabularyMetadata
from opentide.validation.vocab_resolver import RuntimeEnumResolver, _stages_key


def _severity_vocab() -> VocabularyDefinition:
    meta = VocabularyMetadata(name="Severity", field="severity", key="name")
    entries = {
        "High": VocabularyEntry(name="High", description="High severity"),
        "Low": VocabularyEntry(name="Low", description="Low severity"),
    }
    return VocabularyDefinition(metadata=meta, entries=entries)


def _staged_vocab() -> VocabularyDefinition:
    meta = VocabularyMetadata(
        name="Surface",
        field="surface",
        key="name",
        stages=[{"id": "OS", "name": "Operating System", "description": "OS surface"}],
    )
    entries = {
        "Windows::Desktop": VocabularyEntry(
            name="Windows Desktop",
            description="Desktop OS",
            stages=("OS",),
        )
    }
    return VocabularyDefinition(metadata=meta, entries=entries)


def test_stages_key_normalisation() -> None:
    assert _stages_key(None) == ()
    assert _stages_key("OS") == ("OS",)
    assert _stages_key(["OS", "Network"]) == ("OS", "Network")


def test_runtime_enum_resolver_caches_results() -> None:
    resolver = RuntimeEnumResolver({"severity": _severity_vocab()})
    first = resolver.resolve("severity")
    second = resolver.resolve("severity")
    assert first is second


def test_runtime_enum_resolver_enum_values_excludes_empty() -> None:
    resolver = RuntimeEnumResolver({})
    values = resolver.enum_values("missing")
    assert values == frozenset()


def test_runtime_enum_resolver_is_valid_with_stage_prefix() -> None:
    resolver = RuntimeEnumResolver({"surface": _staged_vocab()}, object_types=("surface",))
    assert resolver.is_valid("OS::Windows::Desktop", "surface", scoped=True)


def test_runtime_enum_resolver_suggest_returns_none_for_empty_vocab() -> None:
    resolver = RuntimeEnumResolver({})
    assert resolver.suggest("anything", "missing") is None


def test_runtime_enum_resolver_with_extensions() -> None:
    meta = VocabularyMetadata(name="Status", field="status", key="name")
    vocab = VocabularyDefinition(metadata=meta, entries={})
    resolver = RuntimeEnumResolver(
        {"status": vocab},
        extensions={"status": [{"name": "STAGING", "description": "Staging status"}]},
    )
    assert resolver.is_valid("STAGING", "status")
