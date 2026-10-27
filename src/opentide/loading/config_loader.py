"""Configuration loaders for deployment and visibility settings.

Thin adapters over `opentide.models.configuration`: each validates with the
file's Pydantic model, then hands callers the dataclasses they already use.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from opentide.core.logging import get_logger
from opentide.models.configuration.deployment import (
    DeploymentConfiguration,
    DeploymentResponder,
    DeploymentStatusEntry,
)
from opentide.models.configuration.loading import (
    ConfigurationError,
    error_locations,
    validate_configuration,
)
from opentide.models.system_config import ConfigurationModels
from opentide.models.visibility import VisibilityConfig

logger = get_logger(__name__)


class ConfigurationsLoader:
    @staticmethod
    def load_deployment(deployment_configuration: Mapping[str, Any]) -> DeploymentConfiguration:
        """Validate merged `deployment.toml` against `DeploymentConfiguration`.

        `[[responders]]` go through `load_responders`, which skips a malformed
        entry instead of failing the whole file.
        """
        document = dict(deployment_configuration)
        raw_responders = document.pop("responders", None)
        loaded = validate_configuration(
            DeploymentConfiguration, document, file_key="deployment.toml"
        )
        if raw_responders is None:
            return loaded
        responders = [
            DeploymentResponder(name=item.name, description=item.description)
            for item in ConfigurationsLoader.load_responders(raw_responders)
        ]
        return loaded.model_copy(update={"responders": responders})

    @staticmethod
    def load_statuses(
        statuses_configuration: list[dict],
    ) -> Sequence[ConfigurationModels.Deployment.Status]:
        """Convert status configuration dicts into typed Status objects."""
        loaded = ConfigurationsLoader.load_deployment({"statuses": statuses_configuration})
        return ConfigurationsLoader.statuses_from(loaded.statuses)

    @staticmethod
    def statuses_from(
        statuses: Sequence[DeploymentStatusEntry],
    ) -> Sequence[ConfigurationModels.Deployment.Status]:
        Status = ConfigurationModels.Deployment.Status
        return [
            Status(name=status.name, description=status.description, strategy=status.strategy)
            for status in statuses
        ]

    @staticmethod
    def load_responders(
        responders_configuration: list[dict] | None,
    ) -> Sequence[ConfigurationModels.Deployment.Responder]:
        """Convert responder configuration dicts into typed Responder objects.

        Tolerates a malformed entry rather than failing the load: an entry
        without a name is skipped, and an entry with a name but a stray key
        (a root-level key written below the last `[[responders]]` lands in
        it) is kept with a warning. Raising here would take down
        documentation generation for the whole repository. Only key names
        are logged, never values.
        """
        Responder = ConfigurationModels.Deployment.Responder
        if responders_configuration is None:
            return []
        if not isinstance(responders_configuration, list):
            raise ConfigurationError(
                "deployment.toml", [(("responders",), "must be [[responders]] tables")]
            )
        loaded: list[ConfigurationModels.Deployment.Responder] = []
        for index, entry in enumerate(responders_configuration):
            name = entry.get("name") if isinstance(entry, dict) else None
            if not isinstance(name, str) or not name:
                logger.warning("skipping_responder_without_name", index=index)
                continue
            try:
                responder = DeploymentResponder.model_validate(entry)
            except ValidationError as exc:
                logger.warning(
                    "responder_has_invalid_keys",
                    index=index,
                    responder=name,
                    keys=[".".join(loc) for loc, _message in error_locations(exc, entry)],
                )
                description = entry.get("description")
                responder = DeploymentResponder(
                    name=name, description=description if isinstance(description, str) else ""
                )
            loaded.append(Responder(name=responder.name, description=responder.description))
        return loaded

    @staticmethod
    def load_visibility(config: dict) -> VisibilityConfig | None:
        """Load visibility configuration into a Pydantic ``VisibilityConfig``."""
        if not config:
            return None

        try:
            visibility = validate_configuration(
                VisibilityConfig, config, file_key="visibility.toml"
            )
        except ConfigurationError as exc:
            logger.critical("visibility_config_load_failed", detail=str(exc))
            raise ConfigurationError(
                "visibility.toml", exc.errors, prefix="Failed to load visibility configuration: "
            ) from None

        events = {"logsources": "logsource_invalid_assets", "detectors": "detector_invalid_assets"}
        for table, _index, name, _position, asset in visibility.unknown_assets():
            logger.error(events[table], **{table.removesuffix("s"): name}, invalid_assets=asset)
        return visibility
