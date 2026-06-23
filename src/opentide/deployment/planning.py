import pandas as pd
from opentide.generation.framework import unroll_dot_dict
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import (
    DeploymentStrategy,
    StatusStrategy,
)
from opentide.models.platform import PlatformConfigBase
from opentide.models.system_config import (
    DeploymentBatch,
    SystemConfig,
    TenantDeployment,
)
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.core.registry import OpenTide
from opentide.core.logging import log
from typing import MutableMapping, Sequence
from dataclasses import asdict




SYSTEMS_CONFIGS_INDEX = OpenTide.Configurations.Systems.Index
DEPRECATED_STATUSES = (StatusStrategy.DELETION,
                        StatusStrategy.DISABLEMENT)

from opentide.core.registry import OpenTide
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import DeploymentStrategy, DetectionPlatforms
from opentide.models.system_config import DeploymentBatch, SystemConfig, TenantDeployment
from opentide.generation.framework import unroll_dot_dict

class TideDeployment:
    def __init__(self, deployment, system: DetectionPlatforms, strategy):
        match system:
            case DetectionPlatforms.SPLUNK:
                self.rule_deployment: Sequence[TenantDeployment.Splunk] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.SENTINEL:
                self.rule_deployment: Sequence[TenantDeployment.Sentinel] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.CARBON_BLACK_CLOUD:
                self.rule_deployment: Sequence[TenantDeployment.CarbonBlackCloud] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.DEFENDER_FOR_ENDPOINT:
                self.rule_deployment: Sequence[TenantDeployment.DefenderForEndpoint] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.SENTINEL_ONE:
                self.rule_deployment: Sequence[TenantDeployment.SentinelOne] = ( # type:ignore
                    self.deployment_resolver(deployment, system, strategy)
                )
            case DetectionPlatforms.CROWDSTRIKE:
                self.rule_deployment: Sequence[TenantDeployment.Crowdstrike] = (
                    self.deployment_resolver(deployment, system, strategy) # type:ignore
                )
            case DetectionPlatforms.HARFANGLAB:
                self.rule_deployment: Sequence[TenantDeployment.HarfangLab] = (
                    self.deployment_resolver(deployment, system, strategy) # type:ignore
                )
            case _:
                raise NotImplementedError(
                    f"System {system} is not implemented by TideDeployment"
                )

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
                log(
                    "FATAL",
                    "Could not resolve mdr configuration for system",
                    str(system),
                )
                raise Exception(NotImplemented)

        if not mdr_config:
            log(
                "FAILURE",
                "Was not able to retrieve MDR configuration for targeted system",
                f"[{data.metadata.uuid}] {data.name} - Available configurations : [{data.configurations!s}]",
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
        tenants = self.system_configuration_resolver(
            system).tenants  # type: ignore
        mdr_tenants = self.mdr_configuration_resolver(data, system).tenants
        target_tenants = list()

        log(
            "ONGOING",
            "Currently resolving available tenant deployments for rule",
            data.name,
            data.metadata.uuid,
        )

        if not tenants:
            log(
                "FATAL",
                "Missing tenant configuration for enabled system",
                system.name,
                "Review the system configuration and ensure you have at least one tenant",
            )
            raise Exception

        for tenant in tenants:

            # Resolve tenant deployments when they are specific or not in the MDR spec
            if mdr_tenants:
                log(
                    "INFO",
                    "Found specific tenants targeted by rule",
                    data.name,
                    str(mdr_tenants),
                )

                if tenant.name in mdr_tenants:
                    if (
                        (tenant.deployment is DeploymentStrategy.MANUAL) or
                        (tenant.deployment is DeploymentStrategy.ALWAYS) or
                        (tenant.deployment is deployment_strategy)
                    ):
                        target_tenants.append(tenant)
                        log(
                            "SUCCESS",
                            f"Adding tenant {tenant.name} to the tenant deployment list",
                            f"Compatible with current deployment plan : {deployment_strategy!s}",
                        )
                    else:
                        log(
                            "SKIP",
                            f"Skipping tenant {tenant.name} as is not compatible with current deployment plan",
                            f"Tenant deployment plan : {tenant.deployment!s}, current deployment plan : {deployment_strategy.name}",
                        )
                else:
                    log(
                        "SKIP",
                        f"Skipping tenant {tenant.name} as is not defined by MDR tenant list",
                        str(mdr_tenants),
                    )

            else:
                log(
                    "INFO",
                    "Did not find tenants specified in detection rule, will resolve available ones",
                    data.name,
                )

                if tenant.deployment is DeploymentStrategy.MANUAL:
                    log(
                        "SKIP",
                        f"Skipping tenant {tenant.name} as can only be assigned within the MDR defined tenant",
                        "You can define custom target tenants under the tenants keyword",
                    )
                    continue

                elif (
                    (tenant.deployment is deployment_strategy) or
                    (tenant.deployment is DeploymentStrategy.ALWAYS)
                ):
                    target_tenants.append(tenant)
                    log(
                        "SUCCESS",
                        f"Adding tenant {tenant.name} to the tenant deployment list",
                        f"Compatible with current deployment plan : {deployment_strategy!s}",
                    )
                else:
                    log(
                        "SKIP",
                        f"Skipping tenant {tenant.name} as is not compatible with current deployment plan",
                        f"Tenant deployment plan : {tenant.deployment!s}, current deployment plan : {deployment_strategy.name}",
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
                base_dictionary[key] = self._deep_update(
                    base_dictionary.get(key, {}), value
                )
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

        log("ONGOING", "Checking modifiers for system",
            str(system), str(modifiers))

        if modifiers:
            log("INFO", "Found modifiers in configuration for system", str(system))
            for mod in modifiers:
                log(
                    "ONGOING",
                    f"Evaluating modifier {mod.name!s} {mod.description!s}",
                    str(mod.conditions),
                )

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
                    log(
                        "INFO",
                        "Condition Matching",
                        str(mod.name or ""),
                        str(mod.description or ""),
                    )
                    flatten_modifications = pd.json_normalize(
                        mod.modifications # type: ignore
                    ).to_dict(orient="records")[0]
                    for modification in flatten_modifications:
                        new_value = flatten_modifications[modification]
                        new_value = None if new_value in [
                            "NONE", "NULL"] else new_value
                        if new_value:
                            if type(new_value) is not str:
                                pass
                            elif "::" in new_value:
                                raw_mdr_config_flatten = pd.json_normalize(
                                    raw_mdr_config # type: ignore
                                ).to_dict(orient="records")[0]
                                operator = new_value.split("::")[0]
                                value = new_value.split("::")[1]
                                log(
                                    "DEBUG",
                                    f"Found mod {modification} with operator {operator} with value {value}",
                                )
                                log("DEBUG", str(raw_mdr_config_flatten))
                                if modification in raw_mdr_config_flatten:
                                    log(
                                        "DEBUG",
                                        str(raw_mdr_config_flatten[modification]),
                                    )
                                    if operator == "prefix":
                                        new_value = value + (
                                            raw_mdr_config_flatten[modification] or ""
                                        )
                                    elif operator == "suffix":
                                        new_value = (
                                            raw_mdr_config_flatten[modification] or ""
                                        ) + value
                                    log("DEBUG", "Generated new value", new_value)
                                else:
                                    new_value = value

                        updated_config = unroll_dot_dict(
                            {modification: new_value})
                        log(
                            "ONGOING",
                            f"Applying modification {modification} -> {new_value!s}",
                        )
                        if updated_config:
                            raw_mdr_config = self._deep_update(
                                raw_mdr_config.copy(), updated_config # type: ignore
                            )

        raw_data["configurations"].update({system_identifier: raw_mdr_config})
        log("INFO", "New recompiled modified deployment", str(raw_data))

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
                    self.modifiers_resolver(
                        data=mdr, target_tenant=tenant.name, system=system
                    )
                )

        for tenant in tenants_mapping:
            deployment.append(
                DeploymentBatch(
                    tenant=tenants_data[tenant], rules=tenants_mapping[tenant]
                )
            )

        return deployment
