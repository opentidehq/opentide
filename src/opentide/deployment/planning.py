from collections.abc import MutableMapping, Sequence
from dataclasses import asdict

import pandas as pd

from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.generation.framework import unroll_dot_dict
from opentide.models.deployment_enums import (
    DeploymentStrategy,
    StatusStrategy,
)
from opentide.models.platform import PlatformConfigBase
from opentide.models.rule import DetectionRule
from opentide.models.system_config import (
    DeploymentBatch,
    SystemConfig,
    TenantDeployment,
)

SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION, StatusStrategy.DISABLEMENT)

from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.models.deployment_enums import DetectionPlatforms

logger = get_logger(__name__)


class TideDeployment:
    def __init__(self, deployment, system: DetectionPlatforms, strategy):
        match system:
            case DetectionPlatforms.SPLUNK:
                self.rule_deployment: Sequence[TenantDeployment.Splunk] = (  # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.SENTINEL:
                self.rule_deployment: Sequence[TenantDeployment.Sentinel] = (  # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.CARBON_BLACK_CLOUD:
                self.rule_deployment: Sequence[TenantDeployment.CarbonBlackCloud] = (  # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                self.rule_deployment: Sequence[TenantDeployment.DefenderForEndpoint] = (  # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.SENTINEL_ONE:
                self.rule_deployment: Sequence[TenantDeployment.SentinelOne] = (  # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.CROWDSTRIKE:
                self.rule_deployment: Sequence[TenantDeployment.Crowdstrike] = (
                    self.deployment_resolver(deployment, system, strategy)  # type:ignore
                )
            case DetectionPlatforms.HARFANGLAB:
                self.rule_deployment: Sequence[TenantDeployment.HarfangLab] = (
                    self.deployment_resolver(deployment, system, strategy)  # type:ignore
                )
            case _:
                raise NotImplementedError(f"System {system} is not implemented by TideDeployment")

    def system_configuration_resolver(self, system: DetectionPlatforms):  # type:ignore
        match system:
            # case DetectionPlatforms.SPLUNK:
            # return OpenTide.Configurations.Systems.Splunk
            # case DetectionPlatforms.CARBON_BLACK_CLOUD:
            # return OpenTide.Configurations.Systems.CarbonBlackCloud
            case DetectionPlatforms.SENTINEL:
                return OpenTide.Configurations.Systems.Sentinel
            case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                return OpenTide.Configurations.Systems.DefenderForEndpoint
            case DetectionPlatforms.SENTINEL_ONE:
                return OpenTide.Configurations.Systems.SentinelOne
            case DetectionPlatforms.CROWDSTRIKE:
                return OpenTide.Configurations.Systems.Crowdstrike
            case DetectionPlatforms.HARFANGLAB:
                return OpenTide.Configurations.Systems.HarfangLab
            # case _:
            # raise NotImplementedError
        return None

    def mdr_configuration_resolver(
        self, data: DetectionRule, system: DetectionPlatforms
    ) -> PlatformConfigBase:
        match system:
            case DetectionPlatforms.SENTINEL:
                mdr_config = data.configurations.sentinel
            case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                mdr_config = data.configurations.defender_for_endpoint
            case DetectionPlatforms.SENTINEL_ONE:
                mdr_config = data.configurations.sentinel_one
            case DetectionPlatforms.CROWDSTRIKE:
                mdr_config = data.configurations.crowdstrike
            case DetectionPlatforms.HARFANGLAB:
                mdr_config = data.configurations.harfanglab
            case _:
                logger.critical(
                    "could_not_resolve_mdr_configuration_for_system", detail=str(system)
                )
                raise Exception(NotImplemented)

        if not mdr_config:
            logger.error(
                "was_not_able_to_retrieve_mdr_configuration_for_targeted_system",
                detail=f"[{data.metadata.uuid}] {data.name} - Available configurations : [{data.configurations!s}]",
            )
            raise Exception(NotImplemented)

        return mdr_config

    def tenants_resolver(
        self,
        data: DetectionRule,
        system: DetectionPlatforms,
        deployment_strategy: DeploymentStrategy,
    ) -> Sequence[SystemConfig.Tenant]:
        """
        Returns a list of all the tenants configurations, if they are allowed to be targeted.
        - If ALWAYS, will be targeted on every deployment
        - If MANUAL, can only be targeted if defined in the MDR
        - If STAGING or PRODUCTION, can only be targeted if the current deployment plan alligns with it
        """
        tenants = self.system_configuration_resolver(system).tenants  # type: ignore
        mdr_tenants = self.mdr_configuration_resolver(data, system).tenants
        target_tenants = list()

        logger.info(
            "currently_resolving_available_tenant_deployments_for_rule",
            detail=str(data.name) + " | " + str(data.metadata.uuid),
        )

        if not tenants:
            logger.critical(
                "missing_tenant_configuration_for_enabled_system",
                detail=str(system.name)
                + " | "
                + "Review the system configuration and ensure you have at least one tenant",
            )
            raise Exception

        for tenant in tenants:
            # Resolve tenant deployments when they are specific or not in the MDR spec
            if mdr_tenants:
                logger.info(
                    "found_specific_tenants_targeted_by_rule",
                    detail=str(data.name) + " | " + str(str(mdr_tenants)),
                )

                if tenant.name in mdr_tenants:
                    if (
                        (tenant.deployment is DeploymentStrategy.MANUAL)
                        or (tenant.deployment is DeploymentStrategy.ALWAYS)
                        or (tenant.deployment is deployment_strategy)
                    ):
                        target_tenants.append(tenant)
                        logger.info(
                            "adding_tenant",
                            detail=f"Compatible with current deployment plan : {deployment_strategy!s}",
                        )
                    else:
                        logger.info(
                            "skipping_tenant",
                            detail=f"Tenant deployment plan : {tenant.deployment!s}, current deployment plan : {deployment_strategy.name}",
                        )
                else:
                    logger.info("skipping_tenant", detail=str(mdr_tenants))

            else:
                logger.info(
                    "did_not_find_tenants_specified_in_detection_rule_will_resolve_available_ones",
                    detail=data.name,
                )

                if tenant.deployment is DeploymentStrategy.MANUAL:
                    logger.info(
                        "skipping_tenant",
                        detail="You can define custom target tenants under the tenants keyword",
                    )
                    continue

                elif (tenant.deployment is deployment_strategy) or (
                    tenant.deployment is DeploymentStrategy.ALWAYS
                ):
                    target_tenants.append(tenant)
                    logger.info(
                        "adding_tenant",
                        detail=f"Compatible with current deployment plan : {deployment_strategy!s}",
                    )
                else:
                    logger.info(
                        "skipping_tenant",
                        detail=f"Tenant deployment plan : {tenant.deployment!s}, current deployment plan : {deployment_strategy.name}",
                    )

        return target_tenants

    def _deep_update(
        self, base_dictionary: MutableMapping, updating_dictionary: MutableMapping
    ) -> MutableMapping:
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
        modifiers = system_configuration.modifiers  # type: ignore
        mdr_config = self.mdr_configuration_resolver(data, system)
        system_identifier = system_configuration.platform.identifier  # type: ignore

        if not mdr_config:
            raise NotImplementedError

        raw_data = asdict(data)
        raw_mdr_config = asdict(mdr_config)

        logger.info(
            "checking_modifiers_for_system", detail=str(str(system)) + " | " + str(str(modifiers))
        )

        if modifiers:
            logger.info("found_modifiers_in_configuration_for_system", detail=str(system))
            for mod in modifiers:
                logger.info("evaluating_modifier", detail=str(mod.conditions))

                match = False

                if mod.conditions.default:
                    if mod.conditions.default is True:
                        match = True

                if mod.conditions.status:
                    if mdr_config.status in mod.conditions.status:
                        match = True
                if mod.conditions.tenants:
                    if target_tenant in mod.conditions.tenants:
                        match = True
                    else:
                        match = False
                if mod.conditions.flags and mdr_config.flags:
                    if [tag for tag in mdr_config.flags if tag in mod.conditions.flags]:
                        match = True
                    else:
                        match = False

                if match is True:
                    logger.info(
                        "condition_matching",
                        detail=str(str(mod.name or "")) + " | " + str(str(mod.description or "")),
                    )
                    flatten_modifications = pd.json_normalize(
                        mod.modifications  # type: ignore
                    ).to_dict(orient="records")[0]
                    for modification in flatten_modifications:
                        new_value = flatten_modifications[modification]
                        new_value = None if new_value in ["NONE", "NULL"] else new_value
                        if new_value:
                            if type(new_value) is not str:
                                pass
                            elif "::" in new_value:
                                raw_mdr_config_flatten = pd.json_normalize(
                                    raw_mdr_config  # type: ignore
                                ).to_dict(orient="records")[0]
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
                        if updated_config:
                            raw_mdr_config = self._deep_update(
                                raw_mdr_config.copy(),
                                updated_config,  # type: ignore
                            )

        raw_data["configurations"].update({system_identifier: raw_mdr_config})
        logger.info("new_recompiled_modified_deployment", detail=str(raw_data))

        from opentide.loading.rule_loader import load_rule_from_dict

        return load_rule_from_dict(raw_data)

    def deployment_resolver(
        self,
        mdr_deployment: Sequence[DetectionRule],
        system: DetectionPlatforms,
        deployment_strategy: DeploymentStrategy,
    ) -> Sequence[DeploymentBatch]:
        deployment = list()
        tenants_data = dict()
        tenants_mapping = dict()

        for mdr in mdr_deployment:
            if type(mdr) is str:
                mdr = OpenTide.Rules[mdr]

            tenants = self.tenants_resolver(mdr, system, deployment_strategy)

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
