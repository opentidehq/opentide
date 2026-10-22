"""Configuration loaders for deployment and visibility settings."""

from __future__ import annotations

from collections.abc import Sequence

from opentide.core.logging import get_logger
from opentide.models.system_config import ConfigurationModels
from opentide.models.visibility import VisibilityConfig

logger = get_logger(__name__)


class ConfigurationsLoader:
    @staticmethod
    def load_statuses(
        statuses_configuration: list[dict],
    ) -> Sequence[ConfigurationModels.Deployment.Status]:
        """Convert status configuration dicts into typed Status objects."""
        Status = ConfigurationModels.Deployment.Status
        return [Status(**status_configuration) for status_configuration in statuses_configuration]

    @staticmethod
    def load_responders(
        responders_configuration: list[dict] | None,
    ) -> Sequence[ConfigurationModels.Deployment.Responder]:
        """Convert responder configuration dicts into typed Responder objects.

        Tolerates a malformed entry by skipping it rather than failing the
        load: an unparseable team leaves the enum shorter, whereas raising
        here would take down documentation generation for the whole
        repository.
        """
        Responder = ConfigurationModels.Deployment.Responder
        loaded: list[ConfigurationModels.Deployment.Responder] = []
        for entry in responders_configuration or []:
            if not isinstance(entry, dict) or not entry.get("name"):
                logger.warning("skipping_responder_without_name", detail=str(entry)[:120])
                continue
            loaded.append(
                Responder(name=str(entry["name"]), description=str(entry.get("description", "")))
            )
        return loaded

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
                    invalid_assets = [asset for asset in source_assets if asset not in asset_names]
                    if invalid_assets:
                        logger.error(
                            "logsource_invalid_assets",
                            logsource=source_config.get("name"),
                            invalid_assets=", ".join(invalid_assets),
                        )

            for detector_config in config.get("detectors", []):
                if detector_assets := detector_config.get("assets"):
                    invalid_assets = [
                        asset for asset in detector_assets if asset not in asset_names
                    ]
                    if invalid_assets:
                        logger.error(
                            "detector_invalid_assets",
                            detector=detector_config.get("name"),
                            invalid_assets=", ".join(invalid_assets),
                        )

            return VisibilityConfig.model_validate(config)
        except (KeyError, TypeError, ValueError) as exc:
            logger.critical(
                "visibility_config_load_failed",
                detail=str(exc),
            )
            raise ValueError(f"Failed to load visibility configuration: {str(exc)}") from exc
