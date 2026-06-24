"""gen_json_schema tide keyword resolution coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from opentide.generation import schema_pipeline as sp


def test_gen_json_schema_resolves_logsources_array() -> None:
    schema = {"sources": {"type": "array", "tide.config.visibility.logsources": True}}
    with patch.object(
        sp.VocabularyResolver.Logsources,
        "resolve",
        return_value=(["sentinel::logs"], ["Log source"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["sources"]["items"]["enum"] == ["sentinel::logs"]


def test_gen_json_schema_resolves_detectors_string() -> None:
    schema = {"detector": {"type": "string", "tide.config.visibility.detectors": True}}
    with patch.object(
        sp.VocabularyResolver.Detectors,
        "resolve",
        return_value=(["EDR"], ["Detector"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["detector"]["enum"] == ["EDR"]


def test_gen_json_schema_resolves_parameter_list() -> None:
    schema = {"index": {"type": "string", "tide.config.parameter-list": "systems.splunk.indexes"}}
    with patch.object(
        sp.VocabularyResolver.Parameters,
        "resolve",
        return_value=["main"],
    ):
        result = sp.gen_json_schema(schema)
    assert result["index"]["enum"] == ["main"]


def test_gen_json_schema_resolves_enabled_systems() -> None:
    schema = {"system": {"type": "array", "tide.config.systems::enabled": True}}
    with patch("opentide.generation.schema_pipeline.enabled_systems", return_value=["sentinel"]):
        result = sp.gen_json_schema(schema)
    assert result["system"]["items"]["enum"] == ["sentinel"]


def test_gen_json_schema_resolves_system_tenants() -> None:
    schema = {"tenant": {"type": "string", "tide.config.system.tenants": "sentinel"}}
    with patch.object(
        sp.VocabularyResolver.SystemTenants,
        "resolve",
        return_value=(["Prod"], ["Production"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["tenant"]["enum"] == ["Prod"]


def test_gen_json_schema_resolves_statuses() -> None:
    schema = {"status": {"type": "array", "tide.config.statuses": True}}
    with patch.object(
        sp.VocabularyResolver.Statuses,
        "resolve",
        return_value=(["STAGING"], ["Staging env"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["status"]["items"]["enum"] == ["STAGING"]


def test_gen_json_schema_resolves_tide_vocab_string() -> None:
    schema = {
        "severity": {
            "type": "string",
            "title": "Severity",
            "tide.vocab": "severity",
        }
    }
    with patch.object(
        sp.VocabularyResolver.Vocabulary,
        "resolve",
        return_value=(["High"], ["High severity"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["severity"]["enum"] == ["High"]


def test_gen_json_schema_resolves_tide_vocab_array() -> None:
    schema = {
        "tags": {
            "type": "array",
            "tide.vocab": "severity",
        }
    }
    with patch.object(
        sp.VocabularyResolver.Vocabulary,
        "resolve",
        return_value=(["Low"], ["Low severity"]),
    ):
        result = sp.gen_json_schema(schema)
    assert result["tags"]["items"]["enum"] == ["Low"]
    assert result["tags"]["uniqueItems"] is True


def test_gen_json_schema_object_additional_properties_false() -> None:
    schema = {"metadata": {"type": "object", "title": "Metadata"}}
    result = sp.gen_json_schema(schema)
    assert result["metadata"]["additionalProperties"] is False


def test_recomposition_handler_skips_disabled_platforms() -> None:
    config = {
        "platforms": {
            "sentinel": {"tide": {"enabled": False, "name": "Sentinel", "description": "Azure"}},
            "splunk": {
                "platform": {"enabled": True, "name": "Splunk", "description": "Splunk ES"},
            },
        }
    }
    with (
        patch.object(sp, "CONFIG_INDEX", config),
        patch("opentide.models.platform_schema.platform_model_for_key") as mock_model,
        patch(
            "opentide.generation.pydantic_metaschema.build_platform_schema_source",
            return_value={"properties": {}},
        ),
    ):
        mock_model.return_value = MagicMock()
        result = sp.recomposition_handler("platforms")
    assert "splunk" in result
    assert "sentinel" not in result
