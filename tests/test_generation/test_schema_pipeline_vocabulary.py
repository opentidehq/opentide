"""Schema pipeline vocabulary resolver coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.generation import schema_pipeline as sp
from opentide.generation.vocabulary import VocabularyDefinition, VocabularyEntry, VocabularyMetadata


def _severity_vocab() -> VocabularyDefinition:
    return VocabularyDefinition(
        metadata=VocabularyMetadata(name="Severity", field="severity", key="name"),
        entries={
            "High": VocabularyEntry(name="High", description="High severity"),
            "Low": VocabularyEntry(name="Low", description="Low severity"),
        },
    )


def test_vocabulary_resolver_emits_enum_values() -> None:
    with (
        patch.object(sp, "_runtime_ready", True),
        patch.object(sp, "VOCAB_INDEX", {"severity": _severity_vocab()}),
        patch.object(sp, "OBJECT_TYPES", []),
    ):
        enum, descriptions = sp.VocabularyResolver.Vocabulary("severity").resolve()
    assert "High" in enum
    assert "Low" in enum
    assert len(descriptions) == len(enum)


def test_vocabulary_resolver_visibility_format_asset() -> None:
    asset = MagicMock()
    asset.name = "Server"
    asset.criticality = "high"
    asset.description = "Production server"
    asset.custom_details = {"zone": "dmz"}
    formatted = sp.VocabularyResolver._format_asset("Server", {"Server": asset})
    assert "Server" in formatted
    assert "dmz" in formatted


def test_vocabulary_resolver_visibility_missing_asset() -> None:
    formatted = sp.VocabularyResolver._format_asset("Missing", {})
    assert "Warning" in formatted


#: The module globals ``_refresh_runtime_context()`` rebinds.
_RUNTIME_GLOBALS = (
    "_runtime_ready",
    "GLOBAL_CONFIG",
    "VOCAB_INDEX",
    "CONFIG_INDEX",
    "JSON_SCHEMA_FOLDER",
    "ICONS",
    "OBJECT_TYPES",
)


def test_refresh_runtime_context_rebinds_globals(monkeypatch: pytest.MonkeyPatch) -> None:
    # Bound to the mock, they outlived this test: a later schema generation in
    # the same worker read CONFIG_INDEX without "systems" (KeyError).
    for name in _RUNTIME_GLOBALS:
        monkeypatch.setattr(sp, name, getattr(sp, name))
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
        mock_ot.Configurations.Global.objects = ["rule"]
        mock_ot.Vocabularies.Index = {}
        mock_ot.Configurations.Index = {"schema": {"vocabulary": {}}}
        sp._refresh_runtime_context()
    assert sp.OBJECT_TYPES == ["rule"]


def test_object_levels_render_as_authored_without_a_vocabulary_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An objective's ``priority: Critical`` is not a ``criticality`` value.

    Each objective entry was looked up in the ``criticality`` vocabulary for an
    ``icon`` none of its entries defines: ``High`` logged ``Vocab parameter not
    found``, ``Critical`` ``Vocab identifier not found``, once per schema on
    every ``opentide generate``.
    """
    from opentide.generation import framework

    events: list[tuple[str, str]] = []

    class _Recorder:
        def __getattr__(self, level: str):
            return lambda event, **_fields: events.append((level, event))

    monkeypatch.setattr(framework, "logger", _Recorder())
    kinds = {"objective-1": "objective", "threat-1": "threat", "rule-1": "rule"}
    with (
        patch.object(sp, "_runtime_ready", True),
        patch.object(sp, "VOCAB_INDEX", {}),
        patch.object(sp, "OBJECT_TYPES", ["threat", "objective", "rule"]),
        patch.object(sp, "get_type", lambda identifier, mute=False: kinds[identifier]),
    ):
        resolver = sp.VocabularyResolver.Vocabulary("objective")
        objective = resolver._dropdown("objective-1", {"name": "O", "priority": "Critical"})
        threat = resolver._dropdown("threat-1", {"name": "T", "criticality": "High"})
        rule = resolver._dropdown("rule-1", {"name": "R"})

    assert "**Priority**: Critical" in objective
    assert "Criticality" not in objective
    assert "**Criticality**: High" in threat
    assert "**Criticality**: No Criticality Assigned" in rule
    assert not [event for level, event in events if level == "warning"]


def test_runtime_resolver_labels_object_levels_by_field() -> None:
    from opentide.validation.vocab_resolver import _VocabEnumBuilder

    builder = _VocabEnumBuilder("objective", {}, object_types=["objective"], icons={})
    objective = builder._dropdown("o1", {"name": "O", "priority": "Critical"})
    signal = builder._dropdown("s1", {"name": "O::S", "severity": "Medium"})

    assert "**Priority**: Critical" in objective
    assert "**Severity**: Medium" in signal
    assert "Criticality" not in objective + signal


def test_scoped_vocabulary_skips_an_entry_without_stages() -> None:
    """An entry with no stages used to crash schema generation.

    Its stages come back as an empty tuple, which was wrapped as ``[()]`` and
    then joined to the key with ``() + "::"``.
    """
    surface = VocabularyDefinition(
        metadata=VocabularyMetadata(
            name="Surface", field="surface", key="name", stages=[{"id": "OS", "name": "OS"}]
        ),
        entries={
            "Windows": VocabularyEntry.model_validate(
                {"name": "Windows", "tide.vocab.stages": ["OS"]}
            ),
            "Unstaged": VocabularyEntry(name="Unstaged"),
        },
    )
    with (
        patch.object(sp, "_runtime_ready", True),
        patch.object(sp, "VOCAB_INDEX", {"surface": surface}),
        patch.object(sp, "OBJECT_TYPES", []),
    ):
        scoped, _ = sp.VocabularyResolver.Vocabulary("surface", scoped=True).resolve()
        unscoped, _ = sp.VocabularyResolver.Vocabulary("surface").resolve()
    assert scoped == ["OS::Windows"]
    assert unscoped == ["Windows", "Unstaged"]
