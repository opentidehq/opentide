"""Phase 4 close — platform loader, legacy patch, docs, schema gate tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from opentide.documentation.rule_export import document_detection_rule
from opentide.generation.pydantic_schemas import CORE_SCHEMA_MODELS, generate_core_model_schema
from opentide.indexing.legacy_patch import LegacyObjectPatch
from opentide.loading.platform_loader import (
    load_crowdstrike_config,
    load_defender_config,
    load_sentinel_config,
    load_sentinel_one_config,
)
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.metadata import ObjectMetadata
from opentide.models.platform import RuleConfigurations, SentinelConfig
from opentide.models.rule import DetectionRule

ROOT = Path(__file__).resolve().parents[1]
METASCHEMA_ROOT = ROOT / "src/opentide/schemas/data"


def _metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


def test_load_rule_compat_removed() -> None:
    import opentide.loading.rule_loader as module

    assert not hasattr(module, "load_rule_compat")


def test_legacy_patch_adds_schema_and_uuid() -> None:
    patch = LegacyObjectPatch(index_path=Path("/nonexistent/mapping.json"))
    model = {"name": "Legacy", "meta": {"version": 1}}
    patched = patch.tide_1_patch(model, "mdr")
    assert patched["metadata"]["schema"] == "mdr::2.0"
    assert patched["metadata"]["uuid"]


def test_sentinel_config_loader_parses_alert_and_scheduling() -> None:
    config = load_sentinel_config(
        {
            "enabled": True,
            "name": "Sentinel rule",
            "schema": "platform::sentinel::1.0",
            "status": "STAGING",
            "query": "SecurityEvent | take 1",
            "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
            "alert": {
                "title": "Alert",
                "suppression": False,
                "custom_details": [{"key": "host", "column": "Computer"}],
            },
        }
    )
    assert isinstance(config, SentinelConfig)
    assert config.alert.title == "Alert"
    assert config.scheduling.frequency == "PT1H"
    assert config.alert.custom_details is not None
    assert config.alert.custom_details[0].key == "host"


def test_defender_config_loader_parses_nested_actions() -> None:
    config = load_defender_config(
        {
            "schema": "platform::defender_for_endpoint::1.0",
            "status": "STAGING",
            "query": "DeviceProcessEvents | take 1",
            "scheduling": "1H",
            "alert": {"category": "Execution"},
            "impacted_entities": {"device": "device_id"},
            "scope": {"selection": "All"},
            "actions": {
                "devices": {"run_antivirus_scan": True},
            },
        }
    )
    assert config.actions is not None
    assert config.actions.devices is not None
    assert config.actions.devices.run_antivirus_scan is True


def test_crowdstrike_config_loader_parses_rule_id_bundle() -> None:
    config = load_crowdstrike_config(
        {
            "schema": "platform::crowdstrike::1.0",
            "status": "STAGING",
            "query": "index=main",
            "details": {"trigger": "event", "outcome": "detection"},
            "schedule": {"frequency": "1h", "lookback": "2h"},
            "rule_id::tenant-a": "abc",
        }
    )
    assert config.rule_id_bundle == {"tenant-a": "abc"}


def test_sentinel_one_config_loader_parses_correlation() -> None:
    config = load_sentinel_one_config(
        {
            "schema": "platform::sentinel_one::1.0",
            "status": "STAGING",
            "condition": {
                "type": "Correlation",
                "correlation": {
                    "entity": "host",
                    "match_in_order": True,
                    "time_window": "1h",
                    "sub_queries": [{"query": "a", "matches_required": 1}],
                },
            },
            "response": {"treat_as_threat": "Malicious", "network_quarantine": False},
        }
    )
    assert config.condition.correlation is not None
    assert config.condition.correlation.sub_queries[0].query == "a"


def test_load_rule_from_dict_typed_configurations() -> None:
    payload = {
        "name": "Rule",
        "metadata": _metadata(),
        "description": "desc",
        "configurations": {
            "sentinel": {
                "enabled": True,
                "name": "S",
                "schema": "platform::sentinel::1.0",
                "status": "STAGING",
                "query": "SecurityEvent | take 1",
                "scheduling": {"frequency": "PT1H", "lookback": "PT2H"},
                "alert": {"title": "T", "suppression": False},
            }
        },
    }
    rule = load_rule_from_dict(payload)
    assert isinstance(rule.configurations, RuleConfigurations)
    assert rule.configurations.sentinel is not None
    assert rule.configurations.sentinel.query.startswith("SecurityEvent")


def test_document_detection_rule_renders_platform_query() -> None:
    rule = DetectionRule(
        name="Doc rule",
        metadata=ObjectMetadata.model_validate(_metadata()),
        description="Rule description",
        configurations=RuleConfigurations(
            sentinel=SentinelConfig(
                enabled=True,
                name="S",
                platform_schema="platform::sentinel::1.0",
                status="STAGING",
                query="SecurityEvent | take 1",
                scheduling={"frequency": "PT1H", "lookback": "PT2H"},
                alert={"title": "T", "suppression": False},
            )
        ),
    )
    doc = document_detection_rule(rule)
    assert "# Doc rule" in doc
    assert "SecurityEvent" in doc
    assert "## Platform configurations" in doc


def test_core_schema_models_cover_primary_objects() -> None:
    assert set(CORE_SCHEMA_MODELS) == {"mdr", "dom", "tvm"}


def test_generate_core_model_schema_returns_object_schema() -> None:
    schema = generate_core_model_schema("mdr", enrich=False)
    assert schema["type"] == "object"
    assert "properties" in schema


def test_bundled_metaschema_byte_checksum_gate() -> None:
    """CI gate: bundled metaschema/template sources must remain byte-stable."""
    tracked = [
        METASCHEMA_ROOT / "MDR Meta Schema.yaml",
        METASCHEMA_ROOT / "Detection Objective.metaschema.yaml",
        METASCHEMA_ROOT / "Threat Vector.metaschema.yaml",
    ]
    baseline_path = ROOT / "tests/fixtures/generation/metaschema_checksums.json"
    checksums = {
        str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in tracked
    }
    if not baseline_path.exists():
        pytest.fail("Missing generation baseline checksum file")
    expected = json.loads(baseline_path.read_text(encoding="utf-8"))
    assert checksums == expected


def test_tide2_patching_module_removed() -> None:
    assert not (ROOT / "src/Engines/modules/patching.py").exists()


def test_pydantic_schema_pipeline_source_uses_core_models() -> None:
    source = (ROOT / "src/opentide/generation/schema_pipeline.py").read_text()
    assert "CORE_SCHEMA_MODELS" in source
    assert "generate_core_model_schema" in source


def test_legacy_object_system_loaders_removed() -> None:
    assert not (ROOT / "src/Engines/modules/loaders/object_loader.py").exists()
    assert not (ROOT / "src/Engines/modules/loaders/system_loader.py").exists()
