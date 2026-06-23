import sys
import json
from pathlib import Path
from opentide.platforms.sentinel.client import SentinelService
from opentide.core.registry import OpenTide
import structlog
logger = structlog.get_logger('opentide.extraction.sentinel_importer')
GROUPING_CONFIGURATION = '\n      grouping_lookback: {grouping_lookback}\n      matching: {grouping_matching_method}\n{group_by_entities}\n{group_by_alert_details}\n{group_by_custom_details}\n'.strip('\n')
DYNAMIC_PROPERTIES_TEMPLATE = '\n      #- property: \n        #column: \n'.strip('\n')
DYNAMIC_PROPERTIES = '\n      - property: {property} \n        column: {column}\n'.strip('\n')
ENTITIES_TEMPLATE = '\n  #entities:\n    #- entity: \n      #mappings:\n        #- identifier: \n          #column: \n'.strip('\n')
ENTITIES_MAPPINGS = '\n        - identifier: {identifier} \n          column: {column}\n'.strip('\n')
ENTITIES = '\n    - entity: {entity} \n      mappings:\n{mappings}\n'.strip('\n')
TRIGGER_TEMPLATE = '\n  #trigger:\n    #operator: \n    #threshold: \n'.strip('\n')
TRIGGER = '\n  trigger:\n    operator: {operator}\n    threshold: {threshold}\n'.strip('\n')
SCHEDULING = '\n  scheduling:\n    #nrt: false\n    frequency: {frequency} \n    lookback: {lookback}\n'.strip('\n')
NRT_SCHEDULING = '\n  scheduling:\n    nrt: true\n'.strip('\n')
CUSTOM_DETAILS_TEMPLATE = '\n      #- key: \n        #column: \n'.strip('\n')
CUSTOM_DETAILS = '\n      - key: {key} \n        column: {column}\n'.strip('\n')
MDR = '\nname: {rule_name}\n\n#references:\n  #public:\n    #1: \n  #internal:\n    #a: \n\nmetadata:\n  uuid: {rule_uuid}\n  schema: mdr::2.1\n  version: \n  created: {rule_creation}\n  modified: {rule_modified}\n  tlp: amber\n  author: {rule_author} \n  #contributors:\n    #-\n\ndescription: |\n  {rule_description}\n#detection_model: \n\nresponse:\n  alert_severity: {rule_severity}\n  #playbook: https://\n  #responders: \n  #procedure:\n    #analysis: |\n      #...\n    #searches:\n      #- purpose: |\n          #...\n        #system: \n        #query: |\n          #...\n    #containment: |\n      #...\n\nconfigurations:\n  sentinel: \n{sentinel}\n'
SENTINEL = '\n  schema: sentinel::2.1\n  status: {status}\n  tenants:\n    - {tenant_name}\n  #contributors:\n    #-\n \n{trigger}\n  \n{scheduling}\n  \n  alert:\n    create_incident: {create_incident}\n    suppression: {alert_suppression}\n    {alert_title_commented}title: {alert_title_override} \n    {alert_description_commented}description: |\n      {alert_description_override} \n    {custom_details_commented}custom_details:\n{custom_details}\n    {dynamic_properties_commented}dynamic_properties:\n{dynamic_properties}\n    {tactics}\n    {techniques}\n\n  grouping:\n    event: {event_aggregation}\n  \n    alert:\n      enabled: {alert_grouping_enabled}\n      {reopen_closed_incidents_commented}reopen_closed_incidents: {reopen_closed_incidents}\n{grouping_configuration}\n\n  {entities_commented}entities:\n{entities}\n  \n  query: |\n    {query}\n'
if not OpenTide.Configurations.Systems.Sentinel.tenants:
    logger.critical('you_must_first_have_sentinel_tenants_configured_to_initiate_the')
    raise Exception

def convert_period(period: str) -> str:
    return period.removeprefix('PT').removeprefix('P').lower()

def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    sanitized_name = ''
    for char in name:
        if char in invalid_chars:
            sanitized_name += ' '
        else:
            sanitized_name += char
    return sanitized_name
for tenant in OpenTide.Configurations.Systems.Sentinel.tenants:
    service = SentinelService(tenant).connect()
    rules = service.alert_rules.list(resource_group_name=tenant.setup.resource_group, workspace_name=tenant.setup.workspace_name)
    rules_list = [rule.as_dict() for rule in rules]
    with open(f'output-{tenant.name}.json', 'w+', encoding='utf-8') as f:
        json.dump(rules_list, f, indent=4)
    for rule in rules_list:
        tenant_name = tenant.name
        status = 'PRODUCTION' if rule.get('enabled', False) is True else 'DISABLED'
        if rule.get('kind') == 'nrt':
            trigger = TRIGGER_TEMPLATE
            scheduling = NRT_SCHEDULING
        elif rule.get('kind') == 'Scheduled':
            trigger = TRIGGER.format(operator=rule['trigger_operator'], threshold=rule['trigger_threshold'])
            scheduling = SCHEDULING.format(frequency=convert_period(rule['query_frequency']), lookback=convert_period(rule['query_period']))
        else:
            continue
        create_incident = rule.get('incident_configuration', {}).get('create_incident', 'false')
        if rule.get('suppression_enabled', False) is False:
            alert_suppression = 'false'
        else:
            alert_suppression = convert_period(rule['suppression_duration'])
        if (custom_details := rule.get('custom_details')):
            custom_details_commented = ''
            custom_details = '\n'.join([CUSTOM_DETAILS.format(key=k, column=v).strip('\n') for k, v in custom_details.items()])
        else:
            custom_details_commented = '#'
            custom_details = CUSTOM_DETAILS_TEMPLATE.strip('\n')
        if (dynamic_properties := rule.get('dynamic_properties')):
            dynamic_properties_commented = ''
            dynamic_properties = '\n'.join([CUSTOM_DETAILS.format(key=k, column=v).strip('\n') for k, v in dynamic_properties.items()])
        else:
            dynamic_properties_commented = '#'
            dynamic_properties = DYNAMIC_PROPERTIES_TEMPLATE.strip('\n')
        alert_details_override = rule.get('alert_details_override')
        if not alert_details_override:
            alert_title_commented = '#'
            alert_description_commented = '#'
            alert_title_override = ''
            alert_description_override = '#...'
            dynamic_properties_commented = '#'
        else:
            if (title_override := alert_details_override.get('alert_display_name_format')):
                alert_title_commented = ''
                alert_title_override = title_override
            else:
                alert_title_commented = '#'
                alert_title_override = ''
            if (description_override := alert_details_override.get('alert_description_format')):
                alert_description_commented = ''
                alert_description_override = '\n      '.join(description_override.split('\n'))
            else:
                alert_description_commented = '#'
                alert_description_override = '#...'
            if (dynamic_props := alert_details_override.get('alert_dynamic_properties')):
                dynamic_properties_commented = ''
                dynamic_properties = ''
                for dp in dynamic_props:
                    dynamic_properties += '\n' + DYNAMIC_PROPERTIES.format(property=dp['alert_property'], column=dp['value'])
            else:
                dynamic_properties_commented = '#'
                dynamic_properties = DYNAMIC_PROPERTIES_TEMPLATE.strip('\n')
        if (tactics := rule.get('tactics')):
            tactics = 'tactics:\n' + '      - ' + '\n      - '.join(tactics)
        else:
            tactics = 'OPENTIDE::REMOVE'
        if (techniques := rule.get('techniques')):
            techniques = 'techniques:\n' + '      - ' + '\n      - '.join(techniques)
        else:
            techniques = 'OPENTIDE::REMOVE'
        event_aggregation = rule.get('event_grouping_settings', {}).get('aggregation_kind') or 'SingleAlert'
        incident_configuration = rule.get('incident_configuration')
        grouping_configuration = incident_configuration.get('grouping_configuration') or {}
        if grouping_configuration['enabled'] is False:
            alert_grouping_enabled = 'false'
            grouping_configuration = ''
            reopen_closed_incidents_commented = '#'
            reopen_closed_incidents = ''
        else:
            alert_grouping_enabled = 'true'
            reopen_closed_incidents_commented = ''
            reopen_closed_incidents = grouping_configuration.get('reopen_closed_incident', 'false')
            grouping_lookback = convert_period(grouping_configuration['lookback_duration'])
            grouping_matching_method = grouping_configuration['matching_method']
            if (group_by_entities := grouping_configuration.get('group_by_entities')):
                group_by_entities = 'group_by_entities:\n        - ' + '\n      - '.join(group_by_entities)
            else:
                group_by_entities = 'OPENTIDE::REMOVE'
            if (group_by_alert_details := grouping_configuration.get('group_by_alert_details')):
                group_by_alert_details = 'group_by_alert_details:\n        - ' + '\n      - '.join(group_by_alert_details)
            else:
                group_by_alert_details = 'OPENTIDE::REMOVE'
            if (group_by_custom_details := grouping_configuration.get('group_by_custom_details')):
                group_by_custom_details = 'group_by_custom_details:\n        - ' + '\n      - '.join(group_by_custom_details)
            else:
                group_by_custom_details = 'OPENTIDE::REMOVE'
            grouping_configuration = GROUPING_CONFIGURATION.format(**locals()).strip('\n')
        if (entity_mappings := rule.get('entity_mappings')):
            entities_commented = ''
            entities = []
            for entity in entity_mappings:
                field_mappings = entity['field_mappings']
                mappings = []
                for mapping in field_mappings:
                    mappings.append(ENTITIES_MAPPINGS.format(identifier=mapping['identifier'], column=mapping['column_name']).strip('\n'))
                mappings = '\n'.join(mappings)
                entities.append(ENTITIES.format(entity=entity['entity_type'], mappings=mappings).strip('\n'))
            entities = '\n'.join(entities)
        else:
            entities_commented = '#'
            entities = ENTITIES_TEMPLATE.strip('\n')
        query = '\n    '.join(rule['query'].split('\n'))
        sentinel = SENTINEL.format(**locals())
        sentinel = '\n  '.join(sentinel.split('\n')).strip('\n')
        rule_name = '"' + rule['display_name'] + ' - ' + tenant_name + '"'
        rule_uuid = rule['name']
        rule_description = '\n  '.join(rule['description'].split('\n'))
        rule_creation = rule_modified = rule['last_modified_utc'].split('T')[0]
        rule_severity = rule['severity']
        rule_author = 'OpenTide Sentinel Importer'
        mdr = MDR.format(**locals()).strip('\n')
        mdr = '\n'.join([line for line in mdr.split('\n') if 'OPENTIDE::REMOVE' not in line])
        Path('Imported').mkdir(exist_ok=True)
        with open(f'Imported/{sanitize_filename(rule_name)}.yaml', 'w+', encoding='utf-8') as f:
            f.write(mdr)
