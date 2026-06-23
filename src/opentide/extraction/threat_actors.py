import requests
import sys
import json
from pathlib import Path
import pandas as pd
import yaml
from opentide.core.files import IndentFullDumper
from opentide.core.registry import OpenTide
import structlog
logger = structlog.get_logger('opentide.extraction.threat_actors')
RESOURCES_PATH = Path(OpenTide.Configurations.Global.Paths.Index['resources'])
ATTACK_RESOURCES = OpenTide.Configurations.Resources.attack
MISP_RESOURCES = OpenTide.Configurations.Resources.misp
VOCABULARY_PATH = OpenTide.Configurations.Global.Paths.Core.vocabularies
ATTACK_ENTERPRISE_EXCEL = RESOURCES_PATH / ATTACK_RESOURCES['enterprise']
ATTACK_ICS = RESOURCES_PATH / ATTACK_RESOURCES['ics']
ATTACK_MOBILE_EXCEL = RESOURCES_PATH / ATTACK_RESOURCES['mobile']
MISP_THREAT_ACTOR_GALAXY_LINK: str = MISP_RESOURCES.get('galaxies', {}).get('threat_actors')
THREAT_ACTOR_VOCABULARY_FILE = VOCABULARY_PATH / 'Threat Actors.yaml'
THREAT_ACTOR_VOCABULARY_TEMPLATE = {'name': 'Threat Actors', 'field': 'actors', 'description': 'Groups are activity clusters that are tracked by a common name in the\n  security community.\n\n  Analysts track these clusters using various analytic methodologies and terms such\n  as threat groups, activity groups, and threat actors. Some groups have multiple\n  names associated with similar activities due to various organizations tracking similar\n  activities by different names.\n\n  Organizations group definitions may partially overlap with groups designated by\n  other organizations and may disagree on specific activity.', 'model': True, 'icon': '🐲', 'stages': [{'id': 'misp', 'name': 'MISP Threat Actor Galaxy', 'icon': '🌌', 'description': 'Threat Actors extracted from MISP Threat Actor Galaxy/Cluster'}, {'id': 'att&ck', 'name': 'MITRE ATT&CK Groups', 'icon': '🗡️', 'description': 'Threat Actors extracted from MITRE ATT&CK Groups, from Enterprise, ICS and Mobile definitions'}], 'keys': []}

def parse_misp_galaxy(galaxy_link: str) -> list[dict]:
    """
    Extracts group metadata from the MISP
    """
    logger.info('trying_to_reach', arg0=galaxy_link)
    raw_galaxy = requests.get(galaxy_link).text
    logger.info('raw_misp_galaxy', arg0=raw_galaxy)
    galaxy = json.loads(raw_galaxy)
    groups_data = list()
    for actor in galaxy['values']:
        actor_data = dict()
        actor_data['id'] = actor['uuid']
        actor_data['name'] = actor['value']
        actor_data['description'] = actor.get('description')
        if actor.get('meta', {}).get('synonyms'):
            actor_data['alias'] = actor['meta']['synonyms']
        actor_data['tide.vocab.stages'] = 'misp'
        groups_data.append(actor_data)
    return groups_data

def parse_attack_groups(attack_table: Path, prefix: str='') -> list[dict]:
    """
    Extracts group metadata from the ATT&CK Group excel
    """
    df = pd.read_excel(attack_table, sheet_name='groups')
    df = df.replace({float('nan'): None})
    df = df[['ID', 'name', 'description', 'url', 'associated groups']]
    df = df.rename(columns={'ID': 'id', 'url': 'link', 'associated groups': 'alias'})
    groups_data = df.to_dict('records')
    threat_actors = list()
    for p in groups_data:
        p = {k: v for k, v in p.items() if v is not None}
        if prefix:
            p['name'] = f'[{prefix}] ' + p.pop('name')
        if p.get('alias'):
            alias = str(p.pop('alias')).split(',')
            alias = [a.strip() for a in alias]
            p['alias'] = alias
        p['tide.vocab.stages'] = 'att&ck'
        threat_actors.append(p)
    return threat_actors

def main():
    threat_actors = list()
    logger.info('parsing_att_ck_enterprise')
    threat_actors.extend(parse_attack_groups(ATTACK_ENTERPRISE_EXCEL, 'Enterprise'))
    logger.info('parsing_att_ck_ics')
    threat_actors.extend(parse_attack_groups(ATTACK_ICS, 'ICS'))
    logger.info('parsing_att_ck_mobile')
    threat_actors.extend(parse_attack_groups(ATTACK_MOBILE_EXCEL, 'Mobile'))
    logger.info('parsing_misp_galaxy')
    threat_actors.extend(parse_misp_galaxy(MISP_THREAT_ACTOR_GALAXY_LINK))
    actor_vocabulary = THREAT_ACTOR_VOCABULARY_TEMPLATE
    actor_vocabulary['keys'] = threat_actors
    with open(THREAT_ACTOR_VOCABULARY_FILE, 'w+', encoding='utf-8') as vocabulary:
        yaml.dump(actor_vocabulary, vocabulary, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
if __name__ == '__main__':
    main()
