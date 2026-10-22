"""Configuration loaders for deployment and visibility settings.

Thin adapters over `opentide.models.configuration`: each validates with the
file's Pydantic model, then hands callers the dataclasses they already use.
"""

from __future__ import annotations

from typing import Sequence

from pydantic import ValidationError

from opentide.core.logging import get_logger
from opentide.models.configuration.deployment import (
    DeploymentConfiguration,
    DeploymentResponder,
    DeploymentStatusEntry,
)
from opentide.models.configuration.loading import validate_configuration
from opentide.models.system_config import ConfigurationModels
from opentide.models.visibility import VisibilityConfig

logger = get_logger(__name__)


class ConfigurationsLoader:
    @staticmethod
    def load_deployment(deployment_configuration: dict) -> DeploymentConfiguration:
        """Validate merged `deployment.toml` against `DeploymentConfiguration`.

        `[[responders]]` go through `load_responders`, which skips a malformed
        entry instead of failing the whole file.
        """
        document = dict(deployment_configuration)
        raw_responders = document.pop("responders", None)
        loaded = validate_configuration(
            DeploymentConfiguration, document, file_key="deployment.toml"
        )
        if not raw_responders:
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

        Tolerates a malformed entry by skipping it rather than failing the
        load: an unparseable team leaves the enum shorter, whereas raising
        here would take down documentation generation for the whole
        repository.
        """
        Responder = ConfigurationModels.Deployment.Responder
        loaded: list[ConfigurationModels.Deployment.Responder] = []
        for entry in responders_configuration or []:
            try:
                responder = DeploymentResponder.model_validate(entry)
            except ValidationError:
                logger.warning("skipping_responder_without_name", detail=str(entry)[:120])
                continue
            loaded.append(Responder(name=responder.name, description=responder.description))
        return loaded

    @staticmethod
    def load_visibility(config: dict) -> VisibilityConfig | None:
        """Load visibility configuration into a Pydantic ``VisibilityConfig``."""
        if not config:
            return None

        try:
            visibility = VisibilityConfig.model_validate(config)
        except (KeyError, TypeError, ValueError) as exc:
            logger.critical(
                "visibility_config_load_failed",
                detail=str(exc),
            )
            raise ValueError(f"Failed to load visibility configuration: {str(exc)}") from exc

        from opentide.validation.configuration import visibility_cross_issues

        for issue in visibility_cross_issues(visibility):
            logger.error(
                f"{issue.context['entry']}_invalid_assets",
                **{issue.context["entry"]: issue.context["name"]},
                invalid_assets=issue.context["asset"],
            )
        return visibility
