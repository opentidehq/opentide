"""Configuration loaders for deployment and visibility settings."""

from __future__ import annotations

from typing import Sequence

from opentide.core.logging import log
from opentide.models.system_config import ConfigurationModels
from opentide.models.visibility import VisibilityConfig


class ConfigurationsLoader:
    @staticmethod
    def load_statuses(
        statuses_configuration: list[dict],
    ) -> Sequence[ConfigurationModels.Deployment.Status]:
        """Convert status configuration dicts into typed Status objects."""
        Status = ConfigurationModels.Deployment.Status
        return [Status(**status_configuration) for status_configuration in statuses_configuration]

    @staticmethod
    def load_visibility(config: dict) -> VisibilityConfig | None:
        """Load visibility configuration into a Pydantic ``VisibilityConfig``."""
        if not config:
            return None

        try:
            asset_names: set[str] = set()
            if asset_configuration := config.get("assets"):
                asset_names = {asset["name"] for asset in asset_configuration}

            for source_config in config.get("logsources", []):
                if source_assets := source_config.get("assets"):
                    invalid_assets = [
                        asset for asset in source_assets if asset not in asset_names
                    ]
                    if invalid_assets:
                        log(
                            "FAILURE",
                            f"Log source '{source_config.get('name')}' references non-existent assets",
                            f"Invalid assets: {', '.join(invalid_assets)}",
                            "These assets must be defined in the assets section",
                            "Configuration will load but may be incomplete",
                        )

            for detector_config in config.get("detectors", []):
                if detector_assets := detector_config.get("assets"):
                    invalid_assets = [
                        asset for asset in detector_assets if asset not in asset_names
                    ]
                    if invalid_assets:
                        log(
                            "FAILURE",
                            f"Detector '{detector_config.get('name')}' references non-existent assets",
                            f"Invalid assets: {', '.join(invalid_assets)}",
                            "These assets must be defined in the assets section",
                            "Configuration will load but may be incomplete",
                        )

            return VisibilityConfig.model_validate(config)
        except (KeyError, TypeError, ValueError) as exc:
            log(
                "FATAL",
                "Failed to load visibility configuration",
                f"Error details: {str(exc)}",
                "Ensure all required fields are present and properly formatted",
                "Check the schema documentation for complete requirements",
            )
            raise ValueError(f"Failed to load visibility configuration: {str(exc)}") from exc
