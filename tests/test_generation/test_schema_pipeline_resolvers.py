"""Schema pipeline visibility and configuration resolver coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide.generation import schema_pipeline as sp


def test_logsources_resolver_with_tenants() -> None:
    logsource = MagicMock()
    logsource.name = "Windows Events"
    logsource.system = "sentinel"
    logsource.description = "Endpoint logs"
    logsource.assets = []
    logsource.tenants = ["tenant-a"]
    visibility = MagicMock()
    visibility.logsources = [logsource]
    with patch.object(sp.VocabularyResolver, "_visibility", return_value=visibility):
        result = sp.VocabularyResolver.Logsources().resolve()
    assert result is not None
    enums, _descriptions = result
    assert "sentinel::tenant-a::Windows Events" in enums


def test_logsources_resolver_without_tenants() -> None:
    logsource = MagicMock()
    logsource.name = "Sysmon"
    logsource.system = "sentinel"
    logsource.description = "Sysmon events"
    logsource.assets = ["Server"]
    logsource.tenants = []
    asset = MagicMock()
    asset.name = "Server"
    asset.criticality = "high"
    asset.description = "Prod"
    asset.custom_details = {}
    visibility = MagicMock()
    visibility.logsources = [logsource]
    visibility.assets = [asset]
    with patch.object(sp.VocabularyResolver, "_visibility", return_value=visibility):
        result = sp.VocabularyResolver.Logsources().resolve()
    assert result is not None
    enums, descriptions = result
    assert enums == ["sentinel::Sysmon"]
    assert "Server" in descriptions[0]


def test_detectors_resolver() -> None:
    detector = MagicMock()
    detector.name = "EDR"
    detector.description = "Endpoint detector"
    detector.references = ["Example reference doc"]
    detector.assets = []
    visibility = MagicMock()
    visibility.detectors = [detector]
    with patch.object(sp.VocabularyResolver, "_visibility", return_value=visibility):
        result = sp.VocabularyResolver.Detectors().resolve()
    assert result is not None
    enums, descriptions = result
    assert enums == ["EDR"]
    assert "Example reference doc" in descriptions[0]


def test_statuses_resolver_reads_deployment_statuses() -> None:
    status = MagicMock()
    status.name = "STAGING"
    status.strategy.name = "PREVIEW"
    status.description = "Pre-production"
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Deployment.statuses = [status]
        enums, descriptions = sp.VocabularyResolver.Statuses().resolve()
    assert enums == ["STAGING"]
    assert "Pre-production" in descriptions[0]


def test_parameters_resolver_simple_list() -> None:
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = {"systems": {"splunk": {"indexes": ["main", "security"]}}}
        values = sp.VocabularyResolver.Parameters("systems.splunk.indexes").resolve()
    assert values == ["main", "security"]


def test_parameters_resolver_tenant_parameters() -> None:
    config = {
        "tenants": [
            {"name": " Alpha ", "parameters": {"indexes": [" idx1 ", "idx2"]}},
        ]
    }
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = config
        values = sp.VocabularyResolver.Parameters("tenants.indexes").resolve()
    assert values == ["Alpha::idx1", "Alpha::idx2"]


def test_parameters_resolver_missing_key_raises() -> None:
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = {}
        with pytest.raises(ValueError, match="could not be found"):
            sp.VocabularyResolver.Parameters("global.missing").resolve()


def test_system_tenants_resolver() -> None:
    config = {
        "systems": {
            "sentinel": {
                "tenants": [
                    {"name": "Prod", "description": "Production workspace"},
                ]
            }
        }
    }
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = config
        enums, descriptions = sp.VocabularyResolver.SystemTenants("sentinel").resolve()
    assert enums == ["Prod"]
    assert descriptions == ["Production workspace"]


def test_system_tenants_missing_system_raises() -> None:
    with patch("opentide.generation.schema_pipeline.OpenTide") as mock_ot:
        mock_ot.Configurations.Index = {"systems": {}}
        with pytest.raises(ValueError, match="Missing configuration"):
            sp.VocabularyResolver.SystemTenants("unknown").resolve()


def test_vocabulary_scoped_with_stage_filter() -> None:
    from opentide.generation.vocabulary import (
        VocabularyDefinition,
        VocabularyEntry,
        VocabularyMetadata,
    )

    vocab = VocabularyDefinition(
        metadata=VocabularyMetadata(name="Surface", field="surface", key="name"),
        entries={
            "Windows::Desktop": VocabularyEntry.model_validate(
                {
                    "name": "Windows Desktop",
                    "description": "Desktop OS",
                    "tide.vocab.stages": ["OS", "Cloud"],
                }
            ),
        },
    )
    with (
        patch.object(sp, "VOCAB_INDEX", {"surface": vocab}),
        patch.object(sp, "VOCAB_EXTENSIONS", {}),
        patch.object(sp, "OBJECT_TYPES", []),
    ):
        enum, _descriptions = sp.VocabularyResolver.Vocabulary(
            "surface", stages="OS", scoped=True
        ).resolve()
    assert "OS::Windows::Desktop" in enum
    assert "Cloud::Windows::Desktop" not in enum
