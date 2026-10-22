from collections.abc import Generator, Mapping, MutableMapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Protocol, TypeVar

from opentide.core import registry
from opentide.core.logging import get_logger
from opentide.generation.framework import unroll_dot_dict
from opentide.models.deployment_enums import (
    DetectionPlatforms,
    RunStrategies,
    StatusStrategy,
)
from opentide.models.platform import PLATFORM_CONFIG_MODELS, PlatformConfigBase
from opentide.models.rule import DetectionRule
from opentide.models.system_config import DeploymentBatch, SystemConfig
from opentide.platforms.enabled import MissingTenantsError

DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

logger = get_logger(__name__)


def __getattr__(name: str) -> Any:
    """Resolve registry-backed globals on access rather than at import (#536)."""
    if name == "SYSTEMS_CONFIGS_INDEX":
        return registry.Opentide.Configurations.Systems.Index
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


_WIDE_SCOPE: ContextVar[bool] = ContextVar("opentide_wide_scope", default=False)


@contextmanager
def wide_scope() -> Generator[None]:
    """Resolve tenants for ``--wide``, which deploys rules whatever their status.

    A rule's status strategy normally decides which tenants take it. Under
    ``--wide`` it may be one no run deploys (``INERT``), so a tenant is reached
    when it accepts any of the run's strategies.
    """
    token = _WIDE_SCOPE.set(True)
    try:
        yield
    finally:
        _WIDE_SCOPE.reset(token)


def modifier_applies(
    conditions: SystemConfig.Modifiers.Conditions,
    *,
    status: str,
    tenant: str,
    flags: Sequence[str] | None,
) -> bool:
    """Whether a platform modifier applies to a rule deployed to *tenant*.

    Every condition the modifier sets must hold: ``status`` lists the rule's
    status, ``tenants`` lists the tenant, and ``flags`` shares a flag with the
    rule, so a rule without flags never meets a ``flags`` condition.
    ``default = true`` holds for every rule. A modifier that sets no
    condition applies to none.
    """
    checks: list[bool] = []
    if conditions.status:
        checks.append(status in conditions.status)
    if conditions.tenants:
        checks.append(tenant in conditions.tenants)
    if conditions.flags:
        checks.append(any(flag in conditions.flags for flag in flags or ()))
    if checks:
        return all(checks)
    return conditions.default is True


def _json_normalize(data: Any) -> Any:
    """Import pandas on first use: it is slow to import and most commands never need it."""
    import pandas as pd

    return pd.json_normalize(data)


def _typed_platform_config_roots(system_identifier: str) -> set[str]:
    """Return allowed top-level keys for a platform MDR configuration model."""
    model = PLATFORM_CONFIG_MODELS.get(system_identifier)
    if model is None:
        return set()
    roots: set[str] = set()
    for name, field in model.model_fields.items():
        roots.add(name)
        if field.alias:
            roots.add(str(field.alias))
    return roots


_Mapping = TypeVar("_Mapping", bound=MutableMapping[str, Any])


class _PlatformConfiguration(Protocol):
    """The parts of a platform's ``.opentide/configurations`` file that planning reads."""

    @property
    def platform(self) -> SystemConfig.Platform: ...

    @property
    def tenants(self) -> Sequence[SystemConfig.Tenant] | None: ...

    @property
    def modifiers(self) -> Sequence[SystemConfig.Modifiers] | None: ...


class TideDeployment:
    def __init__(
        self,
        deployment: Sequence[DetectionRule | str],
        system: DetectionPlatforms,
        strategies: RunStrategies | None,
    ) -> None:
        if not isinstance(system, DetectionPlatforms):
            raise NotImplementedError(f"System {system} is not implemented by TideDeployment")
        # Each batch's tenant is the platform's own tenant type; the batches
        # themselves are built as plain ``DeploymentBatch`` objects.
        self.rule_deployment: Sequence[DeploymentBatch] = self.deployment_resolver(
            deployment, system, strategies
        )

    def system_configuration_resolver(self, system: DetectionPlatforms) -> _PlatformConfiguration:
        match system:
            case DetectionPlatforms.SPLUNK:
                return registry.Opentide.Configurations.Systems.Splunk
            case DetectionPlatforms.CARBON_BLACK_CLOUD:
                return registry.Opentide.Configurations.Systems.CarbonBlackCloud
            case DetectionPlatforms.SENTINEL:
                return registry.Opentide.Configurations.Systems.Sentinel
            case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                return registry.Opentide.Configurations.Systems.DefenderForEndpoint
            case DetectionPlatforms.SENTINEL_ONE:
                return registry.Opentide.Configurations.Systems.SentinelOne
            case DetectionPlatforms.CROWDSTRIKE:
                return registry.Opentide.Configurations.Systems.Crowdstrike
            case DetectionPlatforms.HARFANGLAB:
                return registry.Opentide.Configurations.Systems.HarfangLab
            case DetectionPlatforms.ELASTIC:
                return registry.Opentide.Configurations.Systems.Elastic
        raise NotImplementedError(f"System {system} is not implemented by TideDeployment")

    def mdr_configuration_resolver(
        self, data: DetectionRule, system: DetectionPlatforms
    ) -> PlatformConfigBase:
        configurations = data.configurations
        mdr_config: PlatformConfigBase | None = None
        if configurations is not None:
            match system:
                case DetectionPlatforms.SENTINEL:
                    mdr_config = configurations.sentinel
                case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                    mdr_config = configurations.defender_for_endpoint
                case DetectionPlatforms.SENTINEL_ONE:
                    mdr_config = configurations.sentinel_one
                case DetectionPlatforms.CROWDSTRIKE:
                    mdr_config = configurations.crowdstrike
                case DetectionPlatforms.HARFANGLAB:
                    mdr_config = configurations.harfanglab
                case DetectionPlatforms.SPLUNK:
                    mdr_config = configurations.splunk
                case DetectionPlatforms.CARBON_BLACK_CLOUD:
                    mdr_config = configurations.carbon_black_cloud
                case DetectionPlatforms.ELASTIC:
                    mdr_config = configurations.elastic
                case _:
                    logger.critical(
                        "could_not_resolve_mdr_configuration_for_system", detail=str(system)
                    )
                    raise Exception(NotImplemented)

        if not mdr_config:
            logger.error(
                "was_not_able_to_retrieve_mdr_configuration_for_targeted_system",
                detail=(
                    f"[{data.metadata.uuid}] {data.name} - Available configurations : "
                    f"[{data.configurations!s}]"
                ),
            )
            raise Exception(NotImplemented)

        return mdr_config

    def tenants_resolver(
        self,
        data: DetectionRule,
        system: DetectionPlatforms,
        strategies: RunStrategies | None,
    ) -> Sequence[SystemConfig.Tenant]:
        """The tenants a run with *strategies* deploys *data* to on *system*.

        - A tenant takes the rule when it accepts a run strategy that deploys
          the rule's status strategy (``Tenant.accepts``): a ``PREVIEW`` run
          reaches the tenants listing ``PREVIEW``, a ``RELEASE`` run those
          listing ``RELEASE``, also for the ``DISABLEMENT`` and ``DELETION``
          rules it retires.
        - A rule whose platform block lists ``tenants`` reaches only those.
        - A ``manual`` tenant is reached only by the rules that list it.
        """
        from opentide.deployment.utils import check_status

        tenants = self.system_configuration_resolver(system).tenants
        mdr_config = self.mdr_configuration_resolver(data, system)
        mdr_tenants = mdr_config.tenants
        run = tuple(strategies or ())
        rule_strategy = check_status(str(mdr_config.status))
        wide = _WIDE_SCOPE.get()
        target_tenants: list[SystemConfig.Tenant] = []

        if not tenants:
            logger.critical(
                "missing_tenant_configuration_for_enabled_system",
                detail=str(system.name)
                + " | "
                + "Review the system configuration and ensure you have at least one tenant",
            )
            raise MissingTenantsError(system.name.lower())

        for tenant in tenants:
            fields = {
                "rule": data.name,
                "uuid": str(data.metadata.uuid),
                "tenant": tenant.name,
                "rule_strategy": rule_strategy.name,
                "tenant_strategies": [s.name for s in tenant.strategies],
                "run_strategies": [s.name for s in run],
            }
            if mdr_tenants:
                if tenant.name not in mdr_tenants:
                    logger.info("skipping_tenant", reason="not listed by the rule", **fields)
                    continue
            elif tenant.manual:
                logger.info(
                    "skipping_tenant",
                    reason="manual tenant: only rules that list it under tenants reach it",
                    **fields,
                )
                continue
            if wide:
                accepted = any(strategy in tenant.strategies for strategy in run)
            else:
                accepted = tenant.accepts(rule_strategy, run)
            if accepted:
                target_tenants.append(tenant)
                logger.info("adding_tenant", **fields)
            else:
                logger.info(
                    "skipping_tenant",
                    reason="the tenant accepts none of the run strategies that deploy this rule",
                    **fields,
                )

        return target_tenants

    def _deep_update(
        self, base_dictionary: _Mapping, updating_dictionary: Mapping[str, Any]
    ) -> _Mapping:
        """
        Performs a deep nested mapping, so can combine dictionaries
        without overriding them
        """
        for key, value in updating_dictionary.items():
            if isinstance(value, MutableMapping):
                base_dictionary[key] = self._deep_update(base_dictionary.get(key, {}), value)
            else:
                base_dictionary[key] = value
        return base_dictionary

    def modifiers_resolver(
        self, data: DetectionRule, target_tenant: str, system: DetectionPlatforms
    ) -> DetectionRule:
        """
        Dynamically modifies MDR data based on
        """

        system_configuration = self.system_configuration_resolver(system)
        modifiers = system_configuration.modifiers
        mdr_config = self.mdr_configuration_resolver(data, system)
        system_identifier = system_configuration.platform.identifier

        if not mdr_config:
            raise NotImplementedError

        raw_data = data.model_dump(by_alias=True, exclude_none=False)
        raw_mdr_config = mdr_config.model_dump(by_alias=True, exclude_none=False)

        logger.info(
            "checking_modifiers_for_system", detail=str(str(system)) + " | " + str(str(modifiers))
        )

        if modifiers:
            logger.info("found_modifiers_in_configuration_for_system", detail=str(system))
            for mod in modifiers:
                logger.info("evaluating_modifier", detail=str(mod.conditions))

                if modifier_applies(
                    mod.conditions,
                    status=mdr_config.status,
                    tenant=target_tenant,
                    flags=mdr_config.flags,
                ):
                    logger.info(
                        "condition_matching",
                        detail=str(str(mod.name or "")) + " | " + str(str(mod.description or "")),
                    )
                    typed_roots = _typed_platform_config_roots(system_identifier)
                    flatten_modifications = _json_normalize(mod.modifications).to_dict(
                        orient="records"
                    )[0]
                    for modification in flatten_modifications:
                        new_value = flatten_modifications[modification]
                        new_value = None if new_value in ["NONE", "NULL"] else new_value
                        if new_value:
                            if type(new_value) is not str:
                                pass
                            elif "::" in new_value:
                                raw_mdr_config_flatten = _json_normalize(raw_mdr_config).to_dict(
                                    orient="records"
                                )[0]
                                operator = new_value.split("::")[0]
                                value = new_value.split("::")[1]
                                logger.debug("found_mod")
                                logger.debug("debug", detail=str(raw_mdr_config_flatten))
                                if modification in raw_mdr_config_flatten:
                                    logger.debug(
                                        "debug", detail=str(raw_mdr_config_flatten[modification])
                                    )
                                    if operator == "prefix":
                                        new_value = value + (
                                            raw_mdr_config_flatten[modification] or ""
                                        )
                                    elif operator == "suffix":
                                        new_value = (
                                            raw_mdr_config_flatten[modification] or ""
                                        ) + value
                                    logger.debug("generated_new_value", detail=new_value)
                                else:
                                    new_value = value

                        updated_config = unroll_dot_dict({modification: new_value})
                        logger.info("applying_modification")
                        if not updated_config:
                            continue
                        # Flat savedsearches.conf / deploy-control keys (e.g.
                        # dispatch.latest_time, allowed_actions) are applied by
                        # platform deployers — skipping keeps TideModel extra=forbid.
                        root_key = next(iter(updated_config))
                        if typed_roots and root_key not in typed_roots:
                            logger.info(
                                "skipping_flat_platform_modifier",
                                key=modification,
                                root=root_key,
                                system=system_identifier,
                            )
                            continue
                        raw_mdr_config = self._deep_update(
                            raw_mdr_config.copy(),
                            updated_config,
                        )

        raw_data["configurations"].update({system_identifier: raw_mdr_config})
        logger.info("new_recompiled_modified_deployment", detail=str(raw_data))

        from opentide.loading.rule_loader import load_rule_from_dict

        return load_rule_from_dict(raw_data)

    def deployment_resolver(
        self,
        mdr_deployment: Sequence[DetectionRule | str],
        system: DetectionPlatforms,
        strategies: RunStrategies | None,
    ) -> Sequence[DeploymentBatch]:
        deployment: list[DeploymentBatch] = []
        tenants_data: dict[str, SystemConfig.Tenant] = {}
        tenants_mapping: dict[str, list[DetectionRule]] = {}

        for entry in mdr_deployment:
            mdr = registry.Opentide.Rules[entry] if isinstance(entry, str) else entry

            tenants = self.tenants_resolver(mdr, system, strategies)

            for tenant in tenants:
                tenants_data[tenant.name] = tenant
                tenants_mapping.setdefault(tenant.name, []).append(
                    self.modifiers_resolver(data=mdr, target_tenant=tenant.name, system=system)
                )

        for tenant in tenants_mapping:
            deployment.append(
                DeploymentBatch(tenant=tenants_data[tenant], rules=tenants_mapping[tenant])
            )

        return deployment


def __dir__() -> list[str]:
    return sorted(set(globals()) | {"SYSTEMS_CONFIGS_INDEX"})
