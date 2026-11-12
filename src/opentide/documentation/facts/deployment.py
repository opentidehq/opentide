"""Where a rule deploys: per platform, its status, what deploys it, and to which tenants.

A page shows what ``opentide deploy`` would do with the rule, not what the
rule's YAML merely says. For each platform block:

- the **status** and the strategy ``deployment.toml`` maps it to;
- the **runs** that act on it (``PREVIEW`` from pull requests, ``RELEASE``
  from the default branch), from :func:`~opentide.models.deployment_enums.deploys`;
- the **tenants** those runs reach, by the deploy planner's rules: a block
  that lists ``tenants`` reaches only those; otherwise every tenant that is
  not ``manual``; and only a tenant that accepts one of those runs;
- the **remote id** each tenant holds, from the rule's deployment state shard.

Reading configuration and state goes through a :class:`DeploymentEnvironment`,
so a test (or an SDK caller without a workspace) passes a
:class:`StaticEnvironment` and the rendering stays pure.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Literal, Protocol

import structlog

from opentide.documentation.facts.platforms import platform_label
from opentide.models.deployment_enums import DEPLOYABLE_STRATEGIES, StatusStrategy, deploys
from opentide.models.rule import DetectionRule

logger = structlog.get_logger("opentide.documentation.facts")


@dataclass(frozen=True)
class StatusDefinition:
    """One ``[[statuses]]`` entry of ``deployment.toml``."""

    name: str
    description: str
    strategy: StatusStrategy


@dataclass(frozen=True)
class TenantInfo:
    """A configured tenant, as far as targeting is concerned."""

    name: str
    description: str = ""
    #: The run strategies it accepts.
    strategies: tuple[StatusStrategy, ...] = DEPLOYABLE_STRATEGIES
    #: Reached only by rules whose block lists it.
    manual: bool = False


class DeploymentEnvironment(Protocol):
    """The workspace configuration and state a rule page reads."""

    def statuses(self) -> Sequence[StatusDefinition]:
        """Every configured status, in file order."""
        ...

    def platform_enabled(self, platform: str) -> bool | None:
        """Whether the workspace enables *platform*; ``None`` when unknown."""
        ...

    def tenants(self, platform: str) -> Sequence[TenantInfo] | None:
        """The configured tenants of *platform*; ``None`` when they cannot be read."""
        ...

    def remote_ids(self, rule_uuid: str) -> Mapping[str, Mapping[str, str]]:
        """``platform -> tenant -> remote id`` from the rule's deployment state."""
        ...


@dataclass(frozen=True)
class StaticEnvironment:
    """A fixed environment: tests, and rendering without a workspace."""

    status_definitions: tuple[StatusDefinition, ...] = ()
    enabled_platforms: frozenset[str] | None = None
    platform_tenants: Mapping[str, Sequence[TenantInfo]] = field(default_factory=dict)
    states: Mapping[str, Mapping[str, Mapping[str, str]]] = field(default_factory=dict)

    def statuses(self) -> Sequence[StatusDefinition]:
        return self.status_definitions

    def platform_enabled(self, platform: str) -> bool | None:
        if self.enabled_platforms is None:
            return None
        return platform in self.enabled_platforms

    def tenants(self, platform: str) -> Sequence[TenantInfo] | None:
        return self.platform_tenants.get(platform)

    def remote_ids(self, rule_uuid: str) -> Mapping[str, Mapping[str, str]]:
        return self.states.get(rule_uuid, {})


class LiveEnvironment:
    """The environment of the current workspace, read once per platform and cached."""

    def __init__(self) -> None:
        self._statuses: tuple[StatusDefinition, ...] | None = None
        self._enabled: frozenset[str] | None = None
        self._tenants: dict[str, tuple[TenantInfo, ...] | None] = {}

    def statuses(self) -> Sequence[StatusDefinition]:
        if self._statuses is None:
            self._statuses = _read_statuses()
        return self._statuses

    def platform_enabled(self, platform: str) -> bool | None:
        if self._enabled is None:
            from opentide.platforms.enabled import enabled_systems

            self._enabled = frozenset(enabled_systems())
        return platform in self._enabled

    def tenants(self, platform: str) -> Sequence[TenantInfo] | None:
        if platform not in self._tenants:
            self._tenants[platform] = _read_tenants(platform)
        return self._tenants[platform]

    def remote_ids(self, rule_uuid: str) -> Mapping[str, Mapping[str, str]]:
        from opentide.states.deployment import DeploymentState, DeploymentStateError

        try:
            return DeploymentState.load(rule_uuid).platforms
        except DeploymentStateError as exc:
            # A broken shard is deploy's error to report; the page shows no ids.
            logger.warning("docs_deployment_state_unreadable", uuid=rule_uuid, detail=str(exc))
            return {}


def _read_statuses() -> tuple[StatusDefinition, ...]:
    from opentide.core.registry import Opentide

    definitions: list[StatusDefinition] = []
    for status in Opentide.Configurations.Deployment.statuses:
        strategy = status.strategy
        if isinstance(strategy, str):
            strategy = StatusStrategy.__members__.get(strategy)
        if isinstance(strategy, StatusStrategy):
            definitions.append(
                StatusDefinition(str(status.name), str(status.description or ""), strategy)
            )
    return tuple(definitions)


def _read_tenants(platform: str) -> tuple[TenantInfo, ...] | None:
    """The targeting keys of *platform*'s ``[[tenants]]``, read without their credentials.

    Building the platform's typed configuration would resolve every ``$VAR``
    setup value, and a debug run logs an error for the missing local secrets
    module. Targeting needs only ``name``, ``description``, ``strategies`` and
    ``manual``, so they are read from the merged configuration as written.
    ``None`` when the platform has no configuration or its tenants are malformed:
    validate reports those, and the page says the tenants are unknown.
    """
    from opentide.models.deployment_enums import parse_strategies
    from opentide.platforms.config import systems_raw_index

    raw = systems_raw_index().get(platform)
    if not isinstance(raw, dict):
        return None
    entries = raw.get("tenants") or []
    if not isinstance(entries, list):
        return None
    tenants: list[TenantInfo] = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
            return None
        strategies = entry.get("strategies", list(_names(DEPLOYABLE_STRATEGIES)))
        if isinstance(strategies, str):
            strategies = [strategies]
        try:
            accepted = parse_strategies(strategies, source=f"{platform} tenant strategies:")
        except (TypeError, ValueError) as exc:
            logger.info("docs_tenants_unavailable", platform=platform, detail=str(exc))
            return None
        tenants.append(
            TenantInfo(
                name=entry["name"],
                description=str(entry.get("description") or ""),
                strategies=accepted,
                manual=entry.get("manual") is True,
            )
        )
    return tuple(tenants)


def _names(strategies: Sequence[StatusStrategy]) -> tuple[str, ...]:
    return tuple(strategy.name for strategy in strategies)


#: How the tenants of a block were chosen: the block lists them, every tenant
#: that is not manual, the platform configures none, or its file is unreadable.
TenantScope = Literal["listed", "all", "none", "unknown"]


@dataclass(frozen=True)
class TenantTarget:
    """One tenant a block reaches, and the runs that reach it."""

    name: str
    description: str = ""
    runs: tuple[StatusStrategy, ...] = ()
    remote_id: str = ""
    #: The run strategies the tenant accepts; empty when its configuration is unknown.
    accepts: tuple[StatusStrategy, ...] = ()


@dataclass(frozen=True)
class PlatformDeployment:
    """Everything a page says about one platform block's deployment."""

    platform: str
    label: str
    enabled: bool
    status: str
    #: ``None`` when ``deployment.toml`` does not define the status.
    definition: StatusDefinition | None
    #: The runs that act on the block, whatever the tenants accept.
    runs: tuple[StatusStrategy, ...]
    scope: TenantScope
    targets: tuple[TenantTarget, ...] = ()
    #: Tenants the block lists that the platform does not configure.
    unknown_tenants: tuple[str, ...] = ()
    #: Whether the workspace enables the platform; ``None`` when unknown.
    platform_enabled: bool | None = None
    #: Remote ids held for tenants the block no longer reaches.
    orphaned_ids: Mapping[str, str] = field(default_factory=dict)

    @property
    def strategy(self) -> StatusStrategy | None:
        return self.definition.strategy if self.definition else None

    @property
    def reached(self) -> tuple[TenantTarget, ...]:
        """The tenants at least one run deploys to."""
        return tuple(target for target in self.targets if target.runs)


def rule_deployments(
    rule: DetectionRule, environment: DeploymentEnvironment
) -> list[PlatformDeployment]:
    """One :class:`PlatformDeployment` per platform block, in model order."""
    if rule.configurations is None:
        return []
    definitions = {status.name: status for status in environment.statuses()}
    remote = environment.remote_ids(rule.metadata.uuid)
    deployments: list[PlatformDeployment] = []
    for platform in type(rule.configurations).model_fields:
        block = getattr(rule.configurations, platform, None)
        if block is None:
            continue
        definition = definitions.get(str(block.status))
        strategy = definition.strategy if definition else None
        runs = (
            tuple(run for run in DEPLOYABLE_STRATEGIES if deploys(strategy, run))
            if strategy
            else ()
        )
        deployments.append(
            _platform_deployment(
                platform,
                block,
                definition=definition,
                runs=runs,
                tenants=environment.tenants(platform),
                remote=remote.get(platform, {}),
                platform_enabled=environment.platform_enabled(platform),
            )
        )
    return deployments


def _platform_deployment(
    platform: str,
    block: object,
    *,
    definition: StatusDefinition | None,
    runs: tuple[StatusStrategy, ...],
    tenants: Sequence[TenantInfo] | None,
    remote: Mapping[str, str],
    platform_enabled: bool | None,
) -> PlatformDeployment:
    listed = tuple(str(name) for name in (getattr(block, "tenants", None) or ()))
    base = PlatformDeployment(
        platform=platform,
        label=platform_label(platform),
        enabled=bool(getattr(block, "enabled", False)),
        status=str(getattr(block, "status", "")),
        definition=definition,
        runs=runs,
        scope="unknown",
        platform_enabled=platform_enabled,
    )
    if tenants is None:
        targets = tuple(TenantTarget(name, remote_id=remote.get(name, "")) for name in listed)
        orphaned = {name: rid for name, rid in remote.items() if name not in listed}
        return replace(
            base,
            scope="listed" if listed else "unknown",
            targets=targets,
            orphaned_ids=orphaned,
        )

    if not tenants:
        return replace(base, scope="none", unknown_tenants=listed)
    known = {tenant.name for tenant in tenants}
    if listed:
        candidates = [tenant for tenant in tenants if tenant.name in listed]
    else:
        candidates = [tenant for tenant in tenants if not tenant.manual]
    targets = tuple(
        TenantTarget(
            name=tenant.name,
            description=tenant.description,
            runs=tuple(run for run in runs if run in tenant.strategies),
            remote_id=remote.get(tenant.name, ""),
            accepts=tuple(tenant.strategies),
        )
        for tenant in candidates
    )
    names = {target.name for target in targets}
    return replace(
        base,
        scope="listed" if listed else "all",
        targets=targets,
        unknown_tenants=tuple(name for name in listed if name not in known),
        orphaned_ids={name: rid for name, rid in remote.items() if name not in names},
    )
