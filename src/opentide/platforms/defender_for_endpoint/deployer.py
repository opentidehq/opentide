import sys
from collections.abc import Sequence
from dataclasses import dataclass

from opentide.core.debug import DebugEnvironment
from opentide.core.logging import get_logger
from opentide.core.registry import DetectionPlatforms, Opentide
from opentide.deployment import TideDeployment, check_status
from opentide.deployment.external_ids import (
    ExternalIdAction,
    plan_external_id,
    record_created,
    record_deleted,
    report_failure,
    screen_tenant,
)
from opentide.states.deployment import DeploymentStateError
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.defender_for_endpoint.client import (
    DefenderForEndpointService,
    SeverityMapping,
)
from opentide.platforms.defender_for_endpoint.client import DetectionRule as DefenderApiRule
from opentide.platforms.kql import compile_kql_query
from opentide.platforms.plugins import RuleDeployer

logger = get_logger(__name__)

PLATFORM = "defender_for_endpoint"


class DefenderForEndpointDeploy(RuleDeployer):
    def deploy_mdr(
        self,
        data: DetectionRule,
        service: DefenderForEndpointService,
        tenant: str,
        action: ExternalIdAction | None = None,
    ):

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
        object_uuid = str(data.metadata.uuid)
        if action is None:
            try:
                action = plan_external_id(
                    object_uuid=object_uuid,
                    platform=PLATFORM,
                    tenant_name=tenant,
                    status=mdr_config.status,
                )
            except DeploymentStateError as error:
                report_failure(error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant)
                return
        if action.kind == "delete":
            logger.info("proceeding_with_deletion_of_rule_against_tenant", detail=str(action.external_id))
            service.delete_detection_rule(action.external_id)
            try:
                record_deleted(object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant)
            except DeploymentStateError as error:
                report_failure(error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant)
        elif action.kind == "update":
            logger.info(
                "retrieved_id_for_tenant",
                detail=str(action.external_id) + " | " + "Will perform an update",
            )
            service.update_detection_rule(rule, action.external_id)
        else:
            logger.info(
                "could_not_retrieve_id_for_tenant",
                detail="Will create a new rule, and record its ID in .opentide/states/deployment/",
            )
            rule_id = service.create_detection_rule(rule)
            try:
                record_created(
                    object_uuid=object_uuid,
                    platform=PLATFORM,
                    tenant_name=tenant,
                    external_id=rule_id,
                )
            except DeploymentStateError as error:
                report_failure(error, object_uuid=object_uuid, platform=PLATFORM, tenant_name=tenant)

    def deploy(self, mdr_deployment: Sequence[DetectionRule], strategies: RunStrategies):
        mdr_deployment = [Opentide.Rules[uuid] for uuid in mdr_deployment]
        deployment = TideDeployment(
            deployment=mdr_deployment,
            system=DetectionPlatforms.DEFENDER_FOR_ENDPOINT,
            strategies=strategies,
        )
        for tenant_deployment in deployment.rule_deployment:
            tenant = tenant_deployment.tenant.name
            logger.info(
                "planned_deployment",
                detail=str(tenant) + " | " + str(str(tenant_deployment.rules)),
            )
            # Every rule is planned against the deployment state before the
            # client authenticates, so a refused rule makes no HTTP call.
            planned = screen_tenant(
                list(tenant_deployment.rules),
                platform=PLATFORM,
                tenant_name=tenant,
                status_of=lambda mdr: mdr.configurations.defender_for_endpoint.status,
                strategies=strategies,
            )
            if not planned:
                continue
            service = DefenderForEndpointService(tenant_deployment.tenant)
            for mdr, action in planned:
                self.deploy_mdr(data=mdr, service=service, tenant=tenant, action=action)


def declare():
    return DefenderForEndpointDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    DefenderForEndpointDeploy().deploy(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, (StatusStrategy.PREVIEW,)
    )
