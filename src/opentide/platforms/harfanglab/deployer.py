from typing import Sequence
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.platforms.plugins import RuleDeployer
from opentide.models.rule import DetectionRule
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.deployment import TideDeployment, check_status
from opentide.models.system_config import ConfigurationModels
from opentide.models.deployment_enums import StatusStrategy
from opentide.platforms.harfanglab.client import HarfangLabService, SigmaRule, YaraRule, SigmaRuleBuilder
import structlog
logger = structlog.get_logger('opentide.platforms.harfanglab.deployer')
SEVERITY_TO_SCORE = {'Informational': 10, 'Low': 30, 'Medium': 50, 'High': 70, 'Critical': 90}
SCORE_OVERRIDE_MAP = {'Informational': 10, 'Low': 30, 'Medium': 50, 'High': 70, 'Critical': 90}
OS_TO_FILE_CONTEXT = {'Windows': 'file.pe', 'MacOS': 'file.macho', 'Linux': 'file.elf'}

class HarfangLabDeploy(RuleDeployer):
    """
    Deployer for HarfangLab EDR.
    Supports both Sigma rules (behavioral detection) and YARA rules (memory/file scanning).
    """

    def compile_sigma_deployment(self, data: DetectionRule, tenant_config: ConfigurationModels.Systems.HarfangLab.Tenant) -> SigmaRule:
        """
        Builds the Sigma Rule for deployment to HarfangLab API.
        Converts OpenTide's selection-based format to HarfangLab's Sigma format.
        """
        mdr_config = data.configurations.harfanglab
        if not mdr_config:
            logger.critical('missing_harfanglab_configuration_in_mdr', detail=data.metadata.uuid)
            raise Exception('Missing HarfangLab configuration')
        if not mdr_config.sigma:
            logger.critical('sigma_configuration_expected_but_not_found', detail=data.metadata.uuid)
            raise Exception('Missing Sigma configuration')
        sigma_config = mdr_config.sigma
        rule_name = data.name
        rule_description = data.description
        hl_status = HarfangLabService.map_maturity_to_hl_status(mdr_config.maturity)
        global_state = HarfangLabService.map_action_to_global_state(mdr_config.action)
        enabled = True
        if check_status(mdr_config.status) is StatusStrategy.DISABLEMENT:
            enabled = False
            global_state = 'disabled'
        rule_confidence = HarfangLabService.map_confidence(mdr_config.confidence)
        rule_level = HarfangLabService.map_level(data.response.alert_severity)
        selections = []
        for sel in sigma_config.selections:
            selections.append({'name': sel.name, 'field': sel.field, 'modifiers': sel.modifiers or [], 'value': sel.value})
        sigma_yaml = SigmaRuleBuilder.build_sigma_yaml(title=rule_name, description=rule_description, rule_id=data.metadata.uuid, logsource_category=sigma_config.logsource.category, logsource_product=sigma_config.logsource.product, selections=selections, condition=sigma_config.condition, level=rule_level, status=hl_status, tags=mdr_config.tags, false_positives=sigma_config.false_positives, author=data.metadata.author)
        logger.debug('compiled_sigma_rule_content', detail=f'\n{sigma_yaml}')
        block_on_agent = global_state in ['block', 'quarantine']
        quarantine_on_agent = global_state == 'quarantine'
        source_id = tenant_config.setup.source_id
        return SigmaRule(name=rule_name, content=sigma_yaml, source_id=source_id, enabled=enabled, global_state=global_state, hl_status=hl_status, block_on_agent=block_on_agent, quarantine_on_agent=quarantine_on_agent, rule_confidence_override=rule_confidence, rule_level_override=rule_level)

    def compile_yara_deployment(self, data: DetectionRule, tenant_config: ConfigurationModels.Systems.HarfangLab.Tenant) -> YaraRule:
        """
        Builds the YARA Rule for deployment to HarfangLab API.
        Converts OpenTide's YARA format to HarfangLab's YARA format.
        
        Features:
        - Automatic id field for rule identification
        - Score derived from alert_severity (can be overridden)
        - Context auto-routing based on OS (file -> file.pe/file.macho/file.elf)
        - Import statements for YARA modules
        - Rule name from MDR name (lowercased, underscored)
        """
        mdr_config = data.configurations.harfanglab
        if not mdr_config:
            logger.critical('missing_harfanglab_configuration_in_mdr', detail=data.metadata.uuid)
            raise Exception('Missing HarfangLab configuration')
        if not mdr_config.yara:
            logger.critical('yara_configuration_expected_but_not_found', detail=data.metadata.uuid)
            raise Exception('Missing YARA configuration')
        yara_config = mdr_config.yara
        rule_name = data.name
        yara_rule_name = data.name.lower().replace(' ', '_').replace('-', '_')
        yara_rule_name = ''.join((c if c.isalnum() or c == '_' else '_' for c in yara_rule_name))
        if yara_rule_name and yara_rule_name[0].isdigit():
            yara_rule_name = f'rule_{yara_rule_name}'

        def escape_yara_string(s: str) -> str:
            if not s:
                return ''
            s = s.replace('\\', '\\\\')
            s = s.replace('"', '\\"')
            s = s.replace('\n', '\\n')
            s = s.replace('\r', '')
            return s
        yara_lines = []
        if yara_config.imports:
            for module in yara_config.imports:
                yara_lines.append(f'import "{module}"')
            yara_lines.append('')
        yara_lines.append(f'rule {yara_rule_name} {{')
        if data.metadata.author:
            author = data.metadata.author
        elif (organisation := data.metadata.organisation):
            author = organisation.name
        else:
            author = ''
        yara_lines.append('    meta:')
        yara_lines.append(f'        id = "{data.metadata.uuid}"')
        yara_lines.append(f'        title = "{escape_yara_string(data.name)}"')
        yara_lines.append(f'        description = "{escape_yara_string(data.description)}"')
        yara_lines.append(f'        author = "{escape_yara_string(author)}"')
        if data.metadata.created:
            yara_lines.append(f'        date = "{data.metadata.created}"')
        if data.metadata.modified:
            yara_lines.append(f'        modified = "{data.metadata.modified}"')
        if data.references and data.references.public:
            refs = '\\n'.join([str(ref) for ref in data.references.public.values()])
            yara_lines.append(f'        references = "{refs}"')
        if mdr_config.tags:
            tags_str = ';'.join(mdr_config.tags)
            yara_lines.append(f'        tags = "{tags_str}"')
        os_value = yara_config.meta.os
        contexts = yara_config.meta.context
        compiled_contexts = []
        for ctx in contexts:
            if ctx == 'file' and os_value in OS_TO_FILE_CONTEXT:
                compiled_contexts.append(OS_TO_FILE_CONTEXT[os_value])
            else:
                compiled_contexts.append(ctx)
        if compiled_contexts:
            yara_lines.append(f'''        context = "{','.join(compiled_contexts)}"''')
        yara_lines.append(f'        os = "{os_value}"')
        if yara_config.meta.arch:
            arch_str = ','.join(yara_config.meta.arch) if isinstance(yara_config.meta.arch, list) else yara_config.meta.arch
            yara_lines.append(f'        arch = "{arch_str}"')
        if yara_config.meta.classification:
            yara_lines.append(f'        classification = "{escape_yara_string(yara_config.meta.classification)}"')
        score = None
        if yara_config.meta.score:
            score = SCORE_OVERRIDE_MAP.get(yara_config.meta.score)
        if score is None:
            score = SEVERITY_TO_SCORE.get(data.response.alert_severity, 50)
        yara_lines.append(f'        score = {score}')
        confidence_value = HarfangLabService.map_confidence(mdr_config.confidence)
        yara_lines.append(f'        confidence = "{confidence_value}"')
        yara_lines.append('    strings:')
        for line in yara_config.strings.strip().split('\n'):
            yara_lines.append(f'        {line}')
        yara_lines.append('    condition:')
        for line in yara_config.condition.strip().split('\n'):
            yara_lines.append(f'        {line}')
        yara_lines.append('}')
        yara_content = '\n'.join(yara_lines)
        logger.debug('compiled_yara_rule_content', detail=f'\n{yara_content}')
        source_id = tenant_config.setup.source_id
        hl_status = HarfangLabService.map_maturity_to_hl_status(mdr_config.maturity)
        logger.debug('event', detail=f"Maturity mapping: '{mdr_config.maturity}' -> hl_status='{hl_status}'")
        rule_confidence = HarfangLabService.map_confidence(mdr_config.confidence)
        logger.debug('event', detail=f"Confidence mapping: '{mdr_config.confidence}' -> rule_confidence_override='{rule_confidence}'")
        global_state = HarfangLabService.map_action_to_global_state(mdr_config.action)
        logger.debug('event', detail=f"Action mapping: '{mdr_config.action}' -> global_state='{global_state}'")
        rule_level = HarfangLabService.map_level(data.response.alert_severity)
        logger.debug('event', detail=f"Severity mapping: '{data.response.alert_severity}' -> rule_level_override='{rule_level}'")
        return YaraRule(name=rule_name, content=yara_content, source_id=source_id, global_state=global_state, hl_status=hl_status, rule_confidence_override=rule_confidence, rule_level_override=rule_level)

    def deploy_mdr(self, data: DetectionRule, service: HarfangLabService, tenant_config: ConfigurationModels.Systems.HarfangLab.Tenant):
        """
        Deploys the detection rule: creation, update, deletion, and disabling.
        Supports both Sigma rules and YARA rules.
        Uses the MDR UUID as the rule identifier - no external ID tracking needed.
        """
        mdr_config = data.configurations.harfanglab
        if not mdr_config:
            logger.critical('missing_harfanglab_configuration', detail=data.metadata.uuid)
            raise Exception('Missing HarfangLab configuration')
        rule_id = data.metadata.uuid
        is_sigma = mdr_config.sigma is not None
        is_yara = mdr_config.yara is not None
        if not is_sigma and (not is_yara):
            logger.critical('mdr_must_contain_either_sigma_or_yara_configuration', detail=data.metadata.uuid)
            raise Exception('Invalid HarfangLab configuration')
        if check_status(mdr_config.status) is StatusStrategy.DELETION:
            logger.info('step_in_progress', detail=f'Proceeding with deletion of rule against tenant {tenant_config.name}', context=str(rule_id))
            if is_sigma:
                service.delete_sigma_rule(rule_id=rule_id)
            elif is_yara:
                service.delete_yara_rule(rule_id=rule_id)
            return
        if is_sigma:
            rule = self.compile_sigma_deployment(data=data, tenant_config=tenant_config)
            logger.info('deploying_sigma_rule', detail=rule.name, advice=str(rule_id))
            service.create_or_update_sigma_rule(rule=rule, rule_id=rule_id)
        elif is_yara:
            rule = self.compile_yara_deployment(data=data, tenant_config=tenant_config)
            logger.info('deploying_yara_rule', detail=rule.name, advice=str(rule_id))
            service.create_or_update_yara_rule(rule=rule, rule_id=rule_id)

    def deploy(self, mdr_deployment: Sequence[DetectionRule] | list[str], deployment_plan: DeploymentStrategy):
        """
        Triggers the deployment sequence for a series of MDR uuids or DetectionRule Objects
        """
        logger.info('received_harfanglab_deployment_information', detail=str(mdr_deployment))
        loaded_mdr = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(deployment=mdr_deployment, system=DetectionPlatforms.HARFANGLAB, strategy=deployment_plan)
        for tenant_deployment in deployment.rule_deployment:
            logger.info('currently_targeting_tenant', detail=tenant_deployment.tenant.name)
            service = HarfangLabService(tenant_deployment.tenant)
            tenant_type = tenant_deployment.tenant.setup.type
            for mdr in tenant_deployment.rules:
                mdr_config = mdr.configurations.harfanglab
                if not mdr_config:
                    logger.warning('skipping_mdr_no_harfanglab_config', detail=mdr.name)
                    continue
                is_sigma = mdr_config.sigma is not None
                is_yara = mdr_config.yara is not None
                rule_type = 'Sigma' if is_sigma else 'YARA' if is_yara else None
                if rule_type != tenant_type:
                    logger.info('event', detail=f'Skipping {rule_type} rule on {tenant_type} tenant', context_1=mdr.name, advice=tenant_deployment.tenant.name)
                    continue
                logger.info('processing_rule', detail=mdr.name, advice=mdr.metadata.uuid)
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant_deployment.tenant)

def declare():
    return HarfangLabDeploy()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    HarfangLabDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
