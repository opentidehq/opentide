"""TideDeployment resolver coverage for Splunk and CBC."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from opentide.deployment.planning import TideDeployment, _typed_platform_config_roots
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import DetectionPlatforms
from opentide.models.system_config import SystemConfig


def test_mdr_configuration_resolver_returns_splunk_config(metadata: dict) -> None:
    rule = load_rule_from_dict(
        {
            "name": "Splunk Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {
                "splunk": {
                    "schema": "splunk::3.0",
                    "status": "STAGING",
                    "query": "index=main",
                }
            },
        }
    )
    tide = TideDeployment.__new__(TideDeployment)
    config = tide.mdr_configuration_resolver(rule, DetectionPlatforms.SPLUNK)
    assert config is not None
    assert config.query == "index=main"


def test_mdr_configuration_resolver_returns_cbc_config(metadata: dict) -> None:
    rule = load_rule_from_dict(
        {
            "name": "CBC Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {
                "carbon_black_cloud": {
                    "schema": "carbon_black_cloud::3.0",
                    "status": "STAGING",
                    "query": "process_name:cmd.exe",
                }
            },
        }
    )
    tide = TideDeployment.__new__(TideDeployment)
    config = tide.mdr_configuration_resolver(rule, DetectionPlatforms.CARBON_BLACK_CLOUD)
    assert config is not None
    assert config.query == "process_name:cmd.exe"


def test_typed_platform_config_roots_include_schema_alias() -> None:
    roots = _typed_platform_config_roots("splunk")
    assert "scheduling" in roots
    assert "schema" in roots
    assert "dispatch" not in roots


def test_modifiers_resolver_skips_flat_savedsearches_keys(metadata: dict) -> None:
    """Platform Defaults with dispatch.* must not break SplunkConfig reload."""
    rule = load_rule_from_dict(
        {
            "name": "Splunk Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {
                "splunk": {
                    "schema": "splunk::3.0",
                    "status": "STAGING",
                    "query": "index=main",
                    "scheduling": {
                        "schedule": {"frequency": "1h"},
                        "timerange": {"lookback": "2h"},
                    },
                }
            },
        }
    )
    tide = TideDeployment.__new__(TideDeployment)
    tide.system_configuration_resolver = MagicMock(
        return_value=SimpleNamespace(
            platform=SimpleNamespace(identifier="splunk"),
            modifiers=[
                SystemConfig.Modifiers(
                    name="Platform Defaults",
                    conditions=SystemConfig.Modifiers.Conditions(default=True),
                    modifications={
                        "dispatch.earliest_time": "",
                        "dispatch.latest_time": "-5m@m",
                        "allowed_actions": False,
                        "correlation_search": True,
                    },
                )
            ],
        )
    )

    modified = tide.modifiers_resolver(rule, "Primary", DetectionPlatforms.SPLUNK)
    assert modified.configurations.splunk is not None
    assert modified.configurations.splunk.correlation_search is True
    # Flat keys must not have been nested into the typed config.
    assert not hasattr(modified.configurations.splunk, "dispatch")
