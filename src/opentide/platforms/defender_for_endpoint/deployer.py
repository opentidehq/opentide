import sys
from collections.abc import Sequence
from dataclasses import dataclass

from opentide.core.debug import DebugEnvironment
from opentide.core.logging import get_logger, is_debug_enabled
from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.deployment import TideDeployment, check_status
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.defender_for_endpoint.client import (
    DefenderForEndpointService,
    SeverityMapping,
)
from opentide.platforms.defender_for_endpoint.client import DetectionRule as DefenderApiRule
from opentide.platforms.kql import compile_kql_query
from opentide.platforms.plugins import RuleDeployer

logger = get_logger(__name__)


class DefenderForEndpointDeploy(RuleDeployer):
    def deploy_mdr(self, data: DetectionRule, service: DefenderForEndpointService, tenant: str):

        def lower_first_character(string: str) -> str:
            return string[0].lower() + string[1:]

        mdr_config = data.configurations.defender_for_endpoint
        if not mdr_config:
            sys.exit(1)
        response_actions = []
        if mdr_config.actions:

            @dataclass
            class ResponseAction(DefenderApiRule.DetectionAction.ResponseAction):
                pass

            @dataclass
            class ResponseActionIsolateDevice(
                DefenderApiRule.DetectionAction.ResponseActionIsolateDevice
            ):
                pass

            @dataclass
            class ResponseActionFileActions(
                DefenderApiRule.DetectionAction.ResponseActionFileActions
            ):
                pass

            if device_actions := mdr_config.actions.devices:
                if isolation_type := device_actions.isolate_device:
                    response_actions.append(
                        ResponseActionIsolateDevice(
                            odata_type="#microsoft.graph.security.isolateDeviceResponseAction",
                            isolationType=lower_first_character(isolation_type),
                        )
                    )
                if device_actions.collect_investigation_package:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.collectInvestigationPackageResponseAction"
                        )
                    )
                if device_actions.initiate_investigation:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.initiateInvestigationResponseAction"
                        )
                    )
                if device_actions.restrict_app_execution:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.restrictAppExecutionResponseAction"
                        )
                    )
                if device_actions.run_antivirus_scan:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.runAntivirusScanResponseAction"
                        )
                    )
            if file_actions := mdr_config.actions.files:
                if file_actions.allow_block:
                    scope = []
                    identifer = file_actions.allow_block.identifier
                    if file_actions.allow_block.groups:
                        if file_actions.allow_block.groups.selection == "Specific":
                            scope = file_actions.allow_block.groups.device_groups
                    if file_actions.allow_block.action == "Allow":
                        response_actions.append(
                            ResponseActionFileActions(
                                odata_type="#microsoft.graph.security.allowFileResponseAction",
                                identifier=lower_first_character(identifer),
                                deviceGroupNames=scope,
                            )
                        )
                    elif file_actions.allow_block.action == "Block":
                        response_actions.append(
                            ResponseActionFileActions(
                                odata_type="#microsoft.graph.security.blockFileResponseAction",
                                identifier=lower_first_character(identifer),
                                deviceGroupNames=scope,
                            )
                        )
                if identifier := file_actions.quarantine_file:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.stopAndQuarantineFileResponseAction",
                            identifier=identifier,
                        )
                    )
            if user_actions := mdr_config.actions.users:
                if identifer := user_actions.mark_as_compromised:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.markUserAsCompromisedResponseAction",
                            identifier=lower_first_character(identifer),
                        )
                    )
                if identifer := user_actions.disable_user:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.disableUserResponseAction",
                            identifier=lower_first_character(identifer),
                        )
                    )
                if identifer := user_actions.force_password_reset:
                    response_actions.append(
                        ResponseAction(
                            odata_type="#microsoft.graph.security.forceUserPasswordResetResponseAction",
                            identifier=lower_first_character(identifer),
                        )
                    )
        impacted_assets = []
        if mdr_config.impacted_entities:

            @dataclass
            class ImpactedAsset(DefenderApiRule.DetectionAction.AlertTemplate.ImpactedAsset):
                pass

            if identifier := mdr_config.impacted_entities.device:
                impacted_assets.append(
                    ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedDeviceAsset",
                        identifier=lower_first_character(identifier),
                    )
                )
            if identifier := mdr_config.impacted_entities.user:
                impacted_assets.append(
                    ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedUserAsset",
                        identifier=lower_first_character(identifier),
                    )
                )
            if identifier := mdr_config.impacted_entities.mailbox:
                impacted_assets.append(
                    ImpactedAsset(
                        odata_type="#microsoft.graph.security.impactedMailboxAsset",
                        identifier=lower_first_character(identifier),
                    )
                )
        if mdr_config.alert.severity:
            severity = SeverityMapping[mdr_config.alert.severity].value
        else:
            severity = data.response.alert_severity if data.response else "Informational"
            severity = SeverityMapping[severity].value
        category = mdr_config.alert.category.replace(" ", "")
        alert_description = mdr_config.alert.description or data.description
        alert_template = DefenderApiRule.DetectionAction.AlertTemplate(
            title=mdr_config.alert.title or data.name,
            description=alert_description,
            severity=severity,
            category=category,
            mitreTechniques=[],
            impactedAssets=impacted_assets,
            recommendedActions=mdr_config.alert.recommendation or None,
        )
        scheduling = mdr_config.scheduling if mdr_config.scheduling != "NRT" else "0"
        is_enabled = (
            False if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT else True
        )
        query = compile_kql_query(mdr_config.query, mdr_config.exclusions, tenant)
        logger.info("final_compiled_query", detail=query)
        rule = DefenderApiRule(
            displayName=data.name,
            isEnabled=is_enabled,
            queryCondition=DefenderApiRule.QueryCondition(queryText=query),
            schedule=DefenderApiRule.Schedule(period=scheduling),
            detectionAction=DefenderApiRule.DetectionAction(
                alertTemplate=alert_template, responseActions=response_actions
            ),
        )
        if mdr_config.rule_id:
            rule_id = mdr_config.rule_id.get(tenant)
            logger.info(
                "retrieved_id_for_tenant",
                detail=str(str(rule_id)) + " | " + "Will perform an update",
            )
        else:
            logger.info(
                "could_not_retrieve_id_for_tenant",
                detail="Will create a new rule, and write back the ID to the file",
            )
            rule_id = None
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            if not rule_id:
                logger.critical(
                    "cannot_remove_the_rule_as_a_rule_id_could_not_be_found_in_the_file",
                    detail="You will need to manually check the target system to remove the rule",
                )
            else:
                logger.info("proceeding_with_deletion_of_rule_against_tenant", detail=str(rule_id))
                service.delete_detection_rule(rule_id)
                file_path = (
                    OpenTide.Configurations.Global.Paths.Tide.rule
                    / OpenTide.Models.files[data.metadata.uuid]
                )
                with open(file_path, encoding="utf-8") as mdr_file:
                    content = mdr_file.readlines()
                updated_content = list()
                for line in content:
                    if line.strip() != f"rule_id::{tenant}: {rule_id}":
                        updated_content.append(line)
                with open(file_path, "w", encoding="utf-8") as mdr_file:
                    logger.info("removed_id_in_mdr_file_for_tenant")
                    mdr_file.writelines(updated_content)
        elif rule_id:
            service.update_detection_rule(rule, rule_id)
        else:
            rule_id = service.create_detection_rule(rule)
            file_path = (
                OpenTide.Configurations.Global.Paths.Tide.rule
                / OpenTide.Models.files[data.metadata.uuid]
            )
            with open(file_path, encoding="utf-8") as mdr_file:
                content = mdr_file.readlines()
            updated_content = list()
            for line in content:
                if is_debug_enabled():
                    logger.debug("mdr_file_line", detail=line.rstrip())
                if line.strip() == "defender_for_endpoint:":
                    updated_content.append(line)
                    updated_content.append(f"    rule_id::{tenant}: {rule_id}\n")
                    if is_debug_enabled():
                        logger.debug("appending_rule_id_line", rule_id=str(rule_id))
                else:
                    updated_content.append(line)
            with open(file_path, "w", encoding="utf-8") as mdr_file:
                logger.info("updated_mdr_file_with_new_id_for_tenant", detail=str(rule_id))
                mdr_file.writelines(updated_content)

    def deploy(self, mdr_deployment: Sequence[DetectionRule], deployment_plan: DeploymentStrategy):
        mdr_deployment = [OpenTide.Rules[uuid] for uuid in mdr_deployment]
        deployment = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionPlatforms.DEFENDER_FOR_ENDPOINT,
            strategy=deployment_plan,
        )
        for tenant_deployment in deployment.rule_deployment:
            service = DefenderForEndpointService(tenant_deployment.tenant)
            logger.info(
                "planned_deployment",
                detail=str(tenant_deployment.tenant.name)
                + " | "
                + str(str(tenant_deployment.rules)),
            )
            for mdr in tenant_deployment.rules:
                self.deploy_mdr(data=mdr, service=service, tenant=tenant_deployment.tenant.name)


def declare():
    return DefenderForEndpointDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    DefenderForEndpointDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG
    )
