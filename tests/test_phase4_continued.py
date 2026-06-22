"""Phase 4 continuation — OpenTide core, platforms, validation, indexing tests."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from opentide import OpenTide
from opentide.core import index_manager as index_mod
from opentide.core.registry import OpenTideRegistry
from opentide.core.runtime import is_ci, is_debug, repo_root
from opentide.generation.schema import model_json_schema
from opentide.indexing.object_vocab import build_object_vocabularies
from opentide.models.platform import (
    PLATFORM_CONFIG_MODELS,
    RuleConfigurations,
    SentinelConfig,
    parse_platform_config,
)
from opentide.models.rule import DetectionRule
from opentide.platforms.registry import Platform, PlatformsRegistry
from opentide.validation.pipeline import validate_all_objects, validate_object, validate_raw_payload


def _metadata() -> dict[str, Any]:
    return {
        "uuid": "00000000-0000-4000-8000-000000000001",
        "schema": "rule::1.0",
        "version": 1,
        "created": "2026-01-01",
        "modified": "2026-01-02",
        "tlp": "clear",
    }


def _rule_payload() -> dict[str, Any]:
    return {
        "name": "Test rule",
        "metadata": _metadata(),
        "description": "desc",
        "status": "STAGING",
        "severity": "High",
        "techniques": ["T1059"],
        "platforms": {},
    }


def test_runtime_is_debug_vscode() -> None:
    os.environ["TERM_PROGRAM"] = "vscode"
    assert is_debug() is True
    del os.environ["TERM_PROGRAM"]


def test_runtime_is_ci() -> None:
    os.environ["CI"] = "true"
    assert is_ci() is True
    del os.environ["CI"]


def test_repo_root_is_path() -> None:
    root = repo_root()
    assert root.is_dir()
    assert (root / "pyproject.toml").is_file()


def test_index_manager_load_returns_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    index_mod.IndexManager._cache = None
    sample = {"objects": {}, "configurations": {}}
    monkeypatch.setattr(index_mod.IndexManager, "_build_index", lambda: sample)
    monkeypatch.setattr(index_mod.IndexManager, "reconcile_staging", lambda idx: idx)
    index = index_mod.IndexManager.load()
    assert isinstance(index, dict)
    assert "objects" in index


def test_index_manager_reload_clears_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    sample = {"objects": {}, "configurations": {}}
    monkeypatch.setattr(index_mod.IndexManager, "_build_index", lambda: sample)
    monkeypatch.setattr(index_mod.IndexManager, "reconcile_staging", lambda idx: idx)
    index_mod.IndexManager._cache = None
    first = index_mod.IndexManager.load()
    index_mod.IndexManager.reload()
    second = index_mod.IndexManager.load()
    assert first is second


def test_opentide_singleton_type() -> None:
    assert isinstance(OpenTide, OpenTideRegistry)


def test_opentide_initialise_and_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    OpenTide._initialised = False
    OpenTide._index = None
    index_mod.IndexManager._cache = None

    sample_index = {
        "objects": {"mdr": {}, "tvm": {}, "dom": {}},
        "files": {},
        "configurations": {"global": {"objects": []}, "systems": {}},
        "paths": {},
        "vocabs": {},
        "metaschemas": {},
        "subschemas": {},
        "definitions": {},
        "templates": {},
        "json_schemas": {},
    }
    monkeypatch.setattr(index_mod.IndexManager, "load", lambda: sample_index)
    OpenTide.initialise()
    assert OpenTide._initialised is True
    assert OpenTide.Rules == {}


def test_opentide_lookup_returns_none_for_missing() -> None:
    OpenTide._initialised = False
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}
    OpenTide._index = {"objects": {"mdr": {}, "tvm": {}, "dom": {}}, "configurations": {}}
    OpenTide._initialised = True
    assert OpenTide.lookup("missing-uuid") is None


def test_opentide_configuration_schema_sharing(monkeypatch: pytest.MonkeyPatch) -> None:
    OpenTide._index = {
        "configurations": {
            "schema": {"version": "1"},
            "sharing": {"enabled": True},
            "global": {"objects": [], "metaschemas": {}, "templates": {}, "indexes": {}},
            "systems": {},
            "documentation": {},
            "deployment": {"statuses": {}},
            "visibility": {},
        },
        "objects": {"mdr": {}, "tvm": {}, "dom": {}},
    }
    OpenTide._initialised = True
    assert OpenTide.Configuration.Schema["version"] == "1"
    assert OpenTide.Configuration.Sharing["enabled"] is True


def test_opentide_debug_ci_root_properties() -> None:
    assert isinstance(OpenTide.debug, bool)
    assert isinstance(OpenTide.ci, bool)
    assert isinstance(OpenTide.root, Path)


def test_platforms_registry_register() -> None:
    registry = PlatformsRegistry()
    deployer = MagicMock()
    platform = registry.register("sentinel", deployer=deployer, enabled=True)
    assert platform.name == "sentinel"
    assert platform.deployer is deployer
    assert platform.enabled is True


def test_platform_can_deploy_and_validate() -> None:
    platform = Platform(name="splunk", deployer=MagicMock(), validator=None)
    assert platform.can_deploy is True
    assert platform.can_validate is False


def test_parse_platform_config_sentinel() -> None:
    config = parse_platform_config("sentinel", {"enabled": True, "name": "Sentinel"})
    assert isinstance(config, SentinelConfig)
    assert config.enabled is True


def test_rule_configurations_from_platforms_dict() -> None:
    configs = RuleConfigurations.from_platforms_dict(
        {"sentinel": {"enabled": True, "name": "S"}, "crowdstrike": {"enabled": False, "name": "C"}}
    )
    assert configs.sentinel is not None
    assert configs.crowdstrike is not None


def test_platform_config_models_cover_seven_platforms() -> None:
    assert len(PLATFORM_CONFIG_MODELS) == 7


def test_validate_raw_payload_rule_ok() -> None:
    result = validate_raw_payload(_rule_payload(), "mdr")
    assert result.ok is True


def test_validate_raw_payload_unknown_type() -> None:
    result = validate_raw_payload({}, "unknown")
    assert result.ok is False


def test_validate_object_roundtrip() -> None:
    rule = DetectionRule.from_yaml_dict(_rule_payload())
    result = validate_object(rule, "mdr")
    assert result.ok is True


def test_validate_all_objects_empty() -> None:
    errors = validate_all_objects({"mdr": {}, "dom": {}, "tvm": {}})
    assert errors == {}


def test_build_object_vocabularies_mdr() -> None:
    objects = {
        "mdr": {
            "uuid-1": {
                "name": "Rule A",
                "metadata": {"tlp": "clear"},
                "description": "Detects X",
            }
        }
    }
    vocab = build_object_vocabularies(
        object_scope=["mdr"],
        models_index=objects,
        icons={"mdr": "icon"},
        object_names={"mdr": "Detection Rules"},
    )
    assert "mdr" in vocab
    assert "uuid-1" in vocab["mdr"]["entries"]
    assert vocab["mdr"]["entries"]["uuid-1"]["name"] == "Rule A"


def test_tide_schema_generator_model_json_schema() -> None:
    schema = model_json_schema(SentinelConfig)
    assert schema["type"] == "object"
    assert "properties" in schema


def test_detection_rule_validate_query_no_validator() -> None:
    rule = DetectionRule.from_yaml_dict(_rule_payload())
    registry = MagicMock()
    registry.Platforms = {"crowdstrike": MagicMock(validator=None)}
    bound = rule.bind_registry(registry)
    result = bound.validate_query("crowdstrike")
    assert result.ok is False
    assert "does not support query validation" in result.errors[0]


def test_import_opentide_open_tide() -> None:
    from opentide import OpenTide as OT

    assert OT is OpenTide
