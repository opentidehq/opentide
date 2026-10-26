"""System and deployment configuration dataclasses for platform deployers."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeVar

from opentide.models.deployment_enums import (
    DEPLOYABLE_STRATEGIES,
    RunStrategies,
    StatusStrategy,
    deploys,
)
from opentide.models.rule import DetectionRule


@dataclass
class DeploymentStatus:
    name: str
    description: str
    strategy: StatusStrategy | str

    def __post_init__(self) -> None:
        if isinstance(self.strategy, str):
            self.strategy = StatusStrategy[self.strategy]


@dataclass
class DeploymentResponder:
    """One alert-handling team this instance operates.

    A configuration enum entry, not a vocabulary entry: the teams are
    per-organisation, so they are declared in ``deployment.toml`` rather
    than upstream. An empty list leaves ``response.responders``
    unconstrained -- see the note in that file.
    """

    name: str
    description: str = ""


@dataclass
class SystemConfig:
    @dataclass
    class Platform:
        enabled: bool
        identifier: str
        name: str
        subschema: str
        description: str
        flags: list[str]

    @dataclass
    class Modifiers:
        @dataclass
        class Conditions:
            status: Sequence[str] | None = None
            flags: Sequence[str] | None = None
            tenants: Sequence[str] | None = None
            default: bool | None = None

        conditions: Conditions
        modifications: Mapping[Any, str]
        name: str | None = None
        description: str | None = None

    @dataclass
    class Tenant:
        @dataclass
        class Setup:
            #: An unset ``$VAR`` stays a string until a live call refuses it
            #: (``platforms.transport.tenant_tls_verify``).
            ssl: bool | str

        @dataclass
        class Parameters:
            pass

        name: str
        description: str
        setup: Setup
        parameters: Parameters | None = None
        #: The run strategies this tenant accepts (``PREVIEW``, ``RELEASE``);
        #: every one when the platform file omits ``strategies``.
        strategies: RunStrategies = DEPLOYABLE_STRATEGIES
        #: Only the rules whose platform block lists this tenant reach it.
        manual: bool = False

        def accepts(self, rule_strategy: StatusStrategy, run: RunStrategies) -> bool:
            """Whether a run with strategies *run* deploys a *rule_strategy* rule here."""
            return any(
                deploys(rule_strategy, strategy) for strategy in run if strategy in self.strategies
            )

    platform: Platform
    tenants: Sequence[Tenant] | None
    modifiers: Sequence[Modifiers] | None = None


@dataclass
class ConfigurationModels:
    @dataclass
    class Deployment:
        Status = DeploymentStatus
        statuses = Sequence[DeploymentStatus]
        Responder = DeploymentResponder
        responders = Sequence[DeploymentResponder]

    @dataclass
    class Systems:
        @dataclass
        class Sentinel(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    resource_group: str
                    workspace_name: str
                    workspace_id: str
                    azure_tenant_id: str
                    azure_subscription_id: str
                    azure_client_id: str
                    azure_client_secret: str

                setup: Setup

        @dataclass
        class Splunk(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url: str
                    port: str | int
                    app: str
                    correlation_searches: bool = True
                    allow_skew: str | None = None
                    schedule_offset: int = 0
                    frequency_scheduling: str = "random"
                    actions_enabled: Sequence[str] | None = None
                    default_actions: Sequence[str] | None = None
                    enterprise_security: bool = False
                    token: str = ""

                setup: Setup

            tenants: Sequence[Tenant] | None = None

        @dataclass
        class CarbonBlackCloud(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url: str
                    org_key: str
                    token: str
                    watchlist: str | None = None
                    organizations: Sequence[str] | None = None

                setup: Setup

            tenants: Sequence[Tenant] | None = None

        @dataclass
        class SentinelOne(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url: str
                    account_id: int
                    api_token: str
                    site_id: int | None = None

                setup: Setup

        @dataclass
        class DefenderForEndpoint(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Parameters:
                    device_groups: Sequence[str] | None = None

                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    tenant_id: str
                    client_id: str
                    client_secret: str

                setup: Setup
                parameters: Parameters | None = None

            tenants: Sequence[Tenant] | None

        @dataclass
        class Crowdstrike(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    api: str
                    client_id: str
                    client_secret: str
                    customer_id: str

                setup: Setup

            tenants: Sequence[Tenant] | None

        @dataclass
        class HarfangLab(SystemConfig):
            @dataclass
            class Platform(SystemConfig.Platform):
                pass

            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    type: str
                    url: str
                    api_token: str
                    source_id: str

                setup: Setup

            tenants: Sequence[Tenant] | None

        @dataclass
        class Elastic(SystemConfig):
            @dataclass
            class Tenant(SystemConfig.Tenant):
                @dataclass
                class Setup(SystemConfig.Tenant.Setup):
                    url: str
                    elasticsearch_url: str
                    api_key: str
                    space: str = "default"
                    index: Sequence[str] | None = None
                    tags: Sequence[str] | None = None
                    suppression: bool = True

                setup: Setup

            tenants: Sequence[Tenant] | None = None


@dataclass
class DeploymentBatch:
    tenant: SystemConfig.Tenant
    rules: Sequence[DetectionRule]


TenantT = TypeVar("TenantT", bound=SystemConfig.Tenant)


def batch_tenant(batch: DeploymentBatch, kind: type[TenantT]) -> TenantT:
    """*batch*'s tenant as the platform's own tenant class.

    The planner builds a batch from that platform's configuration, whose
    loader instantiates *kind*; anything else is a programming error.
    """
    tenant = batch.tenant
    if not isinstance(tenant, kind):
        raise TypeError(f"expected a {kind.__qualname__} tenant, got {type(tenant).__qualname__}")
    return tenant


class TenantDeployment:
    @dataclass
    class Splunk(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Splunk.Tenant

    @dataclass
    class Sentinel(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Sentinel.Tenant

    @dataclass
    class CarbonBlackCloud(DeploymentBatch):
        tenant: ConfigurationModels.Systems.CarbonBlackCloud.Tenant

    @dataclass
    class SentinelOne(DeploymentBatch):
        tenant: ConfigurationModels.Systems.SentinelOne.Tenant

    @dataclass
    class DefenderForEndpoint(DeploymentBatch):
        tenant: ConfigurationModels.Systems.DefenderForEndpoint.Tenant

    @dataclass
    class Crowdstrike(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Crowdstrike.Tenant

    @dataclass
    class HarfangLab(DeploymentBatch):
        tenant: ConfigurationModels.Systems.HarfangLab.Tenant

    @dataclass
    class Elastic(DeploymentBatch):
        tenant: ConfigurationModels.Systems.Elastic.Tenant
