"""Schema pipeline vocabulary resolver coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

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
        patch.object(sp, "VOCAB_EXTENSIONS", {}),
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


def test_refresh_runtime_context_rebinds_globals() -> None:
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Global.objects = ["rule"]
        mock_ot.Vocabularies.Index = {}
        mock_ot.Configurations.Index = {"schema": {"vocabulary": {}}}
        sp._refresh_runtime_context()
    assert sp.OBJECT_TYPES == ["rule"]
