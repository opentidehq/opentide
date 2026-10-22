"""`deployment.toml`: rule statuses, promotion, debug, and responders."""

from __future__ import annotations

from pydantic import Field

from opentide.models.configuration.base import ConfigurationModel, StatusStrategyName


class DeploymentStatusEntry(ConfigurationModel):
    """One `[[statuses]]` entry: a status a rule may carry, and what deploy does with it."""

    name: str = Field(
        min_length=1,
        description="Status name a rule's status field takes, for example STAGING.",
    )
    description: str = Field(description="What a rule in this status is.")
    strategy: StatusStrategyName = Field(
        description=(
            "What opentide deploy does with a rule in this status: INERT, PREVIEW, "
            "RELEASE, DISABLEMENT, DELETION or UNIVERSAL."
        )
    )


class DeploymentResponder(ConfigurationModel):
    """One `[[responders]]` entry: an alert-handling team a rule's responders may name."""

    name: str = Field(min_length=1, description="Team name a rule's response.responders takes.")
    description: str = Field(
        default="", description="What the team does; shown in the editor next to the name."
    )


class PromotionSettings(ConfigurationModel):
    """`[promotion]`: whether deploy rewrites a promotable status, and to which status."""

    enabled: bool = Field(default=True, description="Whether status promotion is allowed.")
    promotion_target: str = Field(
        default="PRODUCTION",
        min_length=1,
        description="Status a promotable rule is rewritten to. Must name a [[statuses]] entry.",
    )


class DebugSettings(ConfigurationModel):
    """`[debug]`: settings read when opentide runs in debug mode."""

    mdr_test_uuids: list[str] = Field(
        default_factory=list, description="UUIDs of rules usable for debugging."
    )
    ssl_enabled: bool = Field(
        default=True, description="Whether TLS certificates are verified in debug mode."
    )
    proxy_enabled: bool = Field(
        default=False,
        description="Ignored. Pass the proxy URL with `opentide --proxy` instead.",
    )


class DeploymentConfiguration(ConfigurationModel):
    """Merged `deployment.toml`: the statuses a rule may carry and how deploy treats them."""

    default_responders: str = Field(
        default="",
        description=(
            "Team applied when a rule sets no response.responders. Must stay above every "
            "[[...]] block in the file."
        ),
    )
    statuses: list[DeploymentStatusEntry] = Field(
        min_length=1, description="The statuses a rule may carry."
    )
    promotion: PromotionSettings = Field(
        default_factory=PromotionSettings, description="Status promotion on deploy."
    )
    debug: DebugSettings = Field(
        default_factory=DebugSettings, description="Settings read in debug mode."
    )
    responders: list[DeploymentResponder] = Field(
        default_factory=list,
        description=(
            "Alert-handling teams. None declared leaves response.responders unconstrained."
        ),
    )

    def status_names(self) -> frozenset[str]:
        return frozenset(status.name for status in self.statuses)
