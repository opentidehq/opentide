"""Schema pipeline visibility and configuration resolver coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from opentide._models.visibility import VisibilityConfig
from opentide.generation import schema_pipeline as sp


def _visibility(*logsources: dict, assets: list | None = None) -> VisibilityConfig:
    return VisibilityConfig.model_validate({"logsources": list(logsources), "assets": assets})


def _resolve(visibility: VisibilityConfig) -> tuple[list[str], list[str]]:
    with patch.object(sp.VocabularyResolver, "_visibility", return_value=visibility):
        result = sp.VocabularyResolver.Logsources().resolve()
    assert result is not None
    return result


def test_logsources_resolver_offers_every_form_a_signal_takes() -> None:
    """``<name>``, ``<system>::<name>`` and ``<system>::<tenant>::<name>`` (#718)."""
    enums, descriptions = _resolve(
        _visibility(
            {
                "name": "SecurityEvent",
                "system": "sentinel",
                "description": "Endpoint logs",
                "tenants": ["tenant-a"],
            }
        )
    )
    assert enums == [
        "SecurityEvent",
        "sentinel::SecurityEvent",
        "sentinel::tenant-a::SecurityEvent",
    ]
    assert "**Tenants**: tenant-a" in descriptions[0]


def test_a_name_two_systems_declare_describes_both() -> None:
    """No first-wins: the bare name refers to both, and each qualified form to one."""
    enums, descriptions = _resolve(
        _visibility(
            {"name": "DeviceEvents", "system": "sentinel", "description": "Sentinel copy"},
            {"name": "DeviceEvents", "system": "defender_for_endpoint", "description": "XDR"},
        )
    )
    assert enums == [
        "DeviceEvents",
        "sentinel::DeviceEvents",
        "defender_for_endpoint::DeviceEvents",
    ]
    assert "Sentinel copy" in descriptions[0] and "XDR" in descriptions[0]
    assert "XDR" not in descriptions[1]


def test_logsources_resolver_describes_assets() -> None:
    enums, descriptions = _resolve(
        _visibility(
            {"name": "Sysmon", "system": "sentinel", "description": "Sysmon", "assets": ["Server"]},
            assets=[{"name": "Server", "criticality": "high", "description": "Prod"}],
        )
    )
    assert enums == ["Sysmon", "sentinel::Sysmon"]
    assert "Server" in descriptions[0]


def test_no_log_source_is_no_enum() -> None:
    with patch.object(sp.VocabularyResolver, "_visibility", return_value=_visibility()):
        assert sp.VocabularyResolver.Logsources().resolve() is None


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
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
        mock_ot.Configurations.Deployment.statuses = [status]
        enums, descriptions = sp.VocabularyResolver.Statuses().resolve()
    assert enums == ["STAGING"]
    assert "Pre-production" in descriptions[0]


def test_parameters_resolver_simple_list() -> None:
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
        mock_ot.Configurations.Index = {"systems": {"splunk": {"indexes": ["main", "security"]}}}
        values = sp.VocabularyResolver.Parameters("systems.splunk.indexes").resolve()
    assert values == ["main", "security"]


def test_parameters_resolver_tenant_parameters() -> None:
    config = {
        "tenants": [
            {"name": " Alpha ", "parameters": {"indexes": [" idx1 ", "idx2"]}},
        ]
    }
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
        mock_ot.Configurations.Index = config
        values = sp.VocabularyResolver.Parameters("tenants.indexes").resolve()
    assert values == ["Alpha::idx1", "Alpha::idx2"]


def test_parameters_resolver_missing_key_raises() -> None:
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
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
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
        mock_ot.Configurations.Index = config
        enums, descriptions = sp.VocabularyResolver.SystemTenants("sentinel").resolve()
    assert enums == ["Prod"]
    assert descriptions == ["Production workspace"]


def test_system_tenants_missing_system_raises() -> None:
    with patch("opentide.generation.schema_pipeline.Opentide") as mock_ot:
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
        patch.object(sp, "_runtime_ready", True),
        patch.object(sp, "VOCAB_INDEX", {"surface": vocab}),
        patch.object(sp, "OBJECT_TYPES", []),
    ):
        enum, _descriptions = sp.VocabularyResolver.Vocabulary(
            "surface", stages="OS", scoped=True
        ).resolve()
    assert "OS::Windows::Desktop" in enum
    assert "Cloud::Windows::Desktop" not in enum
