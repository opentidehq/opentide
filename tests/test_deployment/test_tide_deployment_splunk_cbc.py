"""TideDeployment resolver coverage for Splunk and CBC."""

from __future__ import annotations

from opentide.deployment.planning import TideDeployment
from opentide.loading.rule_loader import load_rule_from_dict
from opentide.models.deployment_enums import DetectionPlatforms


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
