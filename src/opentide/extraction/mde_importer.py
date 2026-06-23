import sys
import requests
import json
from dataclasses import dataclass
from opentide.platforms.defender_for_endpoint.client import DefenderForEndpointService
from opentide.models.legacy import ConfigurationModels

class DefenderForEndpointImporter(DefenderForEndpointService):

    def list_rules(self):
        response = self.session.get(self.DETECTION_RULES_ENDPOINT)
        return response.json()
setup = ConfigurationModels.Systems.DefenderForEndpoint.Tenant.Setup(proxy=False, ssl=True, tenant_id='', client_id='', client_secret='')
tenant = ConfigurationModels.Systems.DefenderForEndpoint.Tenant(name='', description='', deployment='', setup=setup)
service = DefenderForEndpointImporter(tenant)
rules = service.list_rules()
template = '\nname: "{name}"\n#references:\n  #public:\n    #1: \n  #internal:\n    #a: \n\nmetadata:\n  uuid: {uuid}\n  schema: mdr::2.1\n  version: 1\n  created: {created}\n  modified: {modified}\n  tlp: amber+strict\n  author: {author}\n  #contributors:\n    #-\n\ndescription: |\n{description}\n#detection_model: \n\nresponse:\n  alert_severity: {alert_severity}\n  #playbook: https://\n  #responders: \n  #procedure:\n\nconfigurations:\n  defender_for_endpoint: \n    rule_id::PandoraStores: {rule_id}\n    schema: defender_for_endpoint::2.0\n    status: {status}\n    {contributors}\n    tenants:\n      - PandoraStores\n    #flags:\n      #-\n    \n    scheduling: {schedule}\n    \n    alert:\n      #title: \n      category: {category}{techniques}\n      #severity: \n      {alert_recommendation}\n    \n    {impacted_entities_flag}impacted_entities:\n      {impacted_device}\n      #mailbox: \n      {impacted_user} \n    \n    #actions:\n    \n      #devices:\n        #isolate_device: \n        #collect_investigation_package: true\n        #run_antivirus_scan: true\n        #initiate_investigation: true\n        #restrict_app_execution: true\n    \n      #files:\n        #allow_block:\n          #action: \n          #column: \n          #groups:\n            #selection: \n            #device_groups:\n              #-\n        #quarantine_file: \n    \n    scope:\n      selection: All\n      #device_groups:\n        #-\n    \n    query: |\n{query}\n'
no_contributors_template = '\n    #contributors:\n      #-\n'
contributors_template = '\n    contributors:\n      - {contributor}\n'
no_recommendation_template = '\n      #recommendation: |\n        #Type Here\n'
recommendation_template = '\n      recommendation: |\n{recommendation}\n'
techniques_template = '\n      techniques:\n        {techniques_list}\n'

def add_space_before_uppercase(s):
    result = ''
    for i, char in enumerate(s):
        if char.isupper() and i > 0:
            result += ' '
        result += char
    return result

def sanitize_filename(name):
    invalid_chars = '<>:"/\\|?*'
    sanitized_name = ''
    for char in name:
        if char in invalid_chars:
            sanitized_name += ' '
        else:
            sanitized_name += char
    return sanitized_name

def fix_multiline(string: str, indentation: int):
    lines = string.splitlines()
    fixed_lines = []
    for line in lines:
        if line.strip():
            fixed_lines.append(' ' * indentation + line.strip())
    return '\n'.join(fixed_lines)
for rule in rules['value']:
    rule_name = rule['displayName']
    rule_id = rule['id']
    rule_uuid = rule['detectorId']
    rule_created = rule['createdDateTime'].split('T')[0]
    rule_modified = rule['lastModifiedDateTime'].split('T')[0]
    rule_severity = rule['detectionAction'].get('alertTemplate', {}).get('severity')
    rule_author = rule['createdBy']
    rule_description = rule['detectionAction'].get('alertTemplate', {}).get('description')
    rule_schedule = rule['schedule']['period'] if rule['schedule']['period'] != '0' else 'NRT'
    rule_category = add_space_before_uppercase(rule['detectionAction'].get('alertTemplate', {}).get('category'))
    rule_query = rule['queryCondition'].get('queryText')
    rule_status = 'PRODUCTION' if rule.get('isEnabled') else 'DISABLED'
    if rule['lastModifiedBy'] != rule_author:
        contributors = contributors_template.format(contributor=rule['lastModifiedBy']).strip()
    else:
        contributors = no_contributors_template.strip()
    techniques = ''
    if (t := rule['detectionAction'].get('alertTemplate', {}).get('mitreTechniques')):
        techniques_list = '- ' + '\n        - '.join(t)
        print(techniques_list)
        techniques = techniques_template.format(techniques_list=techniques_list).rstrip()
    if not rule['detectionAction'].get('alertTemplate', {}).get('recommendedActions'):
        alert_recommendation = no_recommendation_template.strip()
    else:
        rule_description += '\n\n---\n' + 'Recommended Actions : ' + rule['detectionAction'].get('alertTemplate', {}).get('recommendedActions')
        alert_recommendation = recommendation_template.format(recommendation=fix_multiline(rule['detectionAction'].get('alertTemplate', {}).get('recommendedActions'), 8)).strip()
    impacted_device = '#device:'
    impacted_user = '#user:'
    impacted_entities_flag = '#'
    for impacted_asset in rule['detectionAction']['alertTemplate']['impactedAssets']:
        if impacted_asset['@odata.type'].endswith('impactedDeviceAsset'):
            identifier = impacted_asset['identifier']
            impacted_device = f'device: {identifier[0].upper() + identifier[1:]}'
            impacted_entities_flag = ''
        if impacted_asset['@odata.type'].endswith('impactedUserAsset'):
            identifier = impacted_asset['identifier']
            impacted_user = f'user: {identifier[0].upper() + identifier[1:]}'
            impacted_entities_flag = ''
    with open(f'Imported/{sanitize_filename(rule_name)}.yaml', 'w+', encoding='utf-8') as f:
        f.write(template.format(name=rule_name, uuid=rule_uuid, rule_id=rule_id, created=rule_created, modified=rule_modified, alert_severity=rule_severity.title(), alert_recommendation=alert_recommendation, impacted_device=impacted_device, impacted_user=impacted_user, impacted_entities_flag=impacted_entities_flag, author=rule_author, contributors=contributors, description=fix_multiline(rule_description, 2), schedule=rule_schedule, category=rule_category, techniques=techniques, query=fix_multiline(rule_query, 6), status=rule_status).strip())
