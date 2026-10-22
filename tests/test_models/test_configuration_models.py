"""Configuration models on the load path: each loader validates with the file's model."""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import patch

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

from opentide.loading.config_loader import ConfigurationsLoader
from opentide.models.configuration import (
    DeploymentConfiguration,
    MispIntegration,
    configuration_files,
)
from opentide.models.configuration.loading import ConfigurationError
from opentide.models.deployment_enums import StatusStrategy
from opentide.models.system_config import DeploymentStatus

_STATUS = {"name": "LIVE", "description": "Live", "strategy": "RELEASE"}


def _bundled(name: str) -> dict[str, Any]:
    from opentide.core.root import get_data_root

    path = get_data_root() / "configurations" / name
    return tomllib.loads(path.read_text(encoding="utf-8"))


def test_every_bundled_file_validates() -> None:
    from opentide.core.root import get_data_root

    root = get_data_root() / "configurations"
    for key, model in configuration_files().items():
        path = root / key
        if path.is_file():
            model.model_validate(_bundled(key))


# --- deployment.toml -------------------------------------------------------------------


def test_load_deployment_returns_the_model() -> None:
    loaded = ConfigurationsLoader.load_deployment(_bundled("deployment.toml"))
    assert isinstance(loaded, DeploymentConfiguration)
    assert loaded.promotion.promotion_target == "PRODUCTION"
    assert {status.strategy for status in loaded.statuses} >= {StatusStrategy.RELEASE}


def test_statuses_stay_dataclasses_with_enum_strategy() -> None:
    statuses = ConfigurationsLoader.load_statuses([_STATUS])
    assert statuses == [DeploymentStatus(name="LIVE", description="Live", strategy="RELEASE")]
    assert statuses[0].strategy is StatusStrategy.RELEASE


@pytest.mark.parametrize(
    ("document", "where"),
    [
        ({"statuses": [{**_STATUS, "strategy": "LATER"}]}, "statuses.0.strategy"),
        ({"statuses": [{**_STATUS, "colour": "red"}]}, "statuses.0.colour: unknown key"),
        ({"statuses": [_STATUS], "promotion": {"enabeld": True}}, "promotion.enabeld"),
        ({"statuses": [_STATUS], "debug": {"ssl_enabled": "yes"}}, "debug.ssl_enabled"),
        ({"statuses": [{"name": "LIVE", "strategy": "RELEASE"}]}, "statuses.0.description"),
        ({"statuses": []}, "statuses"),
    ],
)
def test_load_deployment_names_the_failing_key(document: dict[str, Any], where: str) -> None:
    with pytest.raises(ConfigurationError, match="deployment.toml is invalid") as raised:
        ConfigurationsLoader.load_deployment(document)
    assert where in str(raised.value)


def test_malformed_responder_is_skipped_not_fatal() -> None:
    loaded = ConfigurationsLoader.load_deployment(
        {
            "statuses": [_STATUS],
            "responders": [{"description": "no name"}, {"name": "SOC", "description": "x"}],
        }
    )
    assert [responder.name for responder in loaded.responders] == ["SOC"]


def test_registry_deployment_accessors_read_the_model() -> None:
    from opentide.core.registry import _DeploymentConfig

    accessor = _DeploymentConfig(
        {"configurations": {"deployment": {"statuses": [_STATUS], "debug": {}}}}  # type: ignore[arg-type]
    )
    assert [status.name for status in accessor.statuses] == ["LIVE"]
    assert accessor.debug == {"mdr_test_uuids": [], "ssl_enabled": True, "proxy_enabled": False}
    assert accessor.model.promotion.enabled is True


# --- platforms/<id>.toml ---------------------------------------------------------------


def _sentinel_tenant(**setup: object) -> dict[str, Any]:
    base: dict[str, object] = {
        "resource_group": "rg",
        "workspace_name": "ws",
        "workspace_id": "$AZURE_WORKSPACE_ID",
        "azure_tenant_id": "$AZURE_TENANT_ID",
        "azure_subscription_id": "$AZURE_SUBSCRIPTION_ID",
        "azure_client_id": "$AZURE_CLIENT_ID",
        "azure_client_secret": "$AZURE_CLIENT_SECRET",
    }
    base.update(setup)
    return {"name": "Primary", "setup": base}


def test_platform_loader_rejects_an_unknown_tenant_key() -> None:
    from opentide.platforms.config import build_system_config

    raw = {"platform": {"enabled": True}, "tenants": [_sentinel_tenant(colour="red")]}
    with pytest.raises(ConfigurationError, match="platforms/sentinel.toml is invalid") as raised:
        build_system_config("sentinel", raw)
    assert "tenants.0.setup.colour: unknown key" in str(raised.value)


def test_platform_loader_accepts_a_valid_file() -> None:
    from opentide.platforms.config import build_system_config

    built = build_system_config(
        "sentinel", {"platform": {"enabled": True}, "tenants": [_sentinel_tenant()]}
    )
    assert built.tenants[0].name == "Primary"


def test_platform_loader_keeps_its_retired_key_messages() -> None:
    from opentide.platforms.config import build_system_config

    raw = {"tenants": [{**_sentinel_tenant(), "deployment": "STAGING"}]}
    with pytest.raises(ValueError, match="was removed in 0.17.0"):
        build_system_config("sentinel", raw)


def test_platform_error_never_repeats_a_secret() -> None:
    from opentide.platforms.config import build_system_config

    secret = "Very-Secret-Value-42"
    raw = {"tenants": [_sentinel_tenant(azure_client_secret=secret, extra_secret=secret)]}
    with pytest.raises(ConfigurationError) as raised:
        build_system_config("sentinel", raw)
    assert secret not in str(raised.value)


def test_splunk_legacy_tables_are_accepted() -> None:
    from opentide.platforms.config import validate_platform_config

    validate_platform_config(
        "splunk",
        {
            "tide": {"identifier": "splunk"},
            "setup": {"url": "u"},
            "secrets": {"token": "$T"},
            "defaults": {"cron_schedule": "0 * * * *"},
            "modifiers": {},
        },
    )


# --- paths.toml, documentation.toml, visibility.toml -----------------------------------


def test_workspace_paths_reject_an_unknown_key(tmp_path) -> None:
    from opentide.registry.paths import resolve_workspace_paths

    configs = {"paths": {**_bundled("paths.toml"), "paths": {"objekts": {}}}}
    with pytest.raises(ConfigurationError, match="paths.toml is invalid: paths.objekts"):
        resolve_workspace_paths(configs, workspace=tmp_path)


def test_bundled_paths_resolve(tmp_path) -> None:
    from opentide.registry.paths import resolve_workspace_paths

    paths = resolve_workspace_paths(
        {"paths": _bundled("paths.toml"), "global": _bundled("global.toml")}, workspace=tmp_path
    )
    assert paths["rule"] == (tmp_path / "objects" / "rules").resolve()


def test_documentation_settings_reject_an_unknown_direction() -> None:
    from opentide.documentation.config import load_settings

    with patch("opentide.documentation.config.Opentide") as mock_ot:
        mock_ot.Configurations.Documentation.Index = {
            "diagrams": {"relations_direction": "sideways"}
        }
        mock_ot.Configurations.Global.Index = {"paths": {"core": {}}}
        with pytest.raises(ConfigurationError, match="diagrams.relations_direction"):
            load_settings()


def test_documentation_flavor_name_with_hyphen() -> None:
    from opentide.documentation.types import DocumentFlavor
    from opentide.models.configuration import DocumentationConfiguration

    loaded = DocumentationConfiguration.model_validate({"flavor": "azure-devops"})
    assert loaded.default_flavor() is DocumentFlavor.azure_devops


def test_visibility_unknown_asset_is_logged_not_fatal() -> None:
    with patch("opentide.loading.config_loader.logger") as logger:
        loaded = ConfigurationsLoader.load_visibility(
            {
                "assets": [{"name": "dc", "description": "d", "criticality": "high"}],
                "logsources": [
                    {"name": "l", "description": "d", "system": "splunk", "assets": ["nope"]}
                ],
                "detectors": [{"name": "edr", "description": "d", "assets": ["gone"]}],
            }
        )
    assert loaded is not None
    events = [call.args[0] for call in logger.error.call_args_list]
    assert events == ["logsource_invalid_assets", "detector_invalid_assets"]


# --- sharing.toml ----------------------------------------------------------------------


def test_misp_model_constants_match_the_sharing_package() -> None:
    from opentide.models.configuration import sharing as model
    from opentide.sharing import constants

    assert model.NAME_PATTERN == constants.NAME_PATTERN
    assert model.DEFAULT_OBJECT_TYPES == constants.DEFAULT_OBJECT_TYPES
    assert model.DEFAULT_RULE_STATUSES == constants.DEFAULT_RULE_STATUSES
    assert model.ORGANISATION_UUID_PATTERN == constants.ORGANISATION_UUID_PATTERN
    assert set(MispIntegration.model_fields) == constants.MISP_BLOCK_KEYS
    required = {name for name, field in MispIntegration.model_fields.items() if field.is_required()}
    assert required == constants.REQUIRED_MISP_KEYS
