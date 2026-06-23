import sys
import os
from pathlib import Path
import yaml
from opentide.core.files import resolve_paths
from opentide.core.root import get_repo_root
import structlog
logger = structlog.get_logger('opentide.mutation.security_domain')
ROOT = get_repo_root()
PATHS = resolve_paths()
MDR_PATH = PATHS['mdr']

class MigrateSecurityDomainMDR:
    """
    If security_domain is commented, or uncommented, simply makes an indent
    to re-nest under notable. In edge cases where notable is uncommented but
    not security_domain, indent and uncomment notable. In edge cases where 
    security_domain is not present at all, will not add it by safety.
    """

    def indent_security_domain(self, file_path: Path):
        data = open(MDR_PATH / file_path, encoding='utf-8').readlines()
        buffer = []
        for line in data:
            if line.startswith('    security_domain:'):
                line = '  ' + line
                logger.info('found_and_added_indent_to_security_domain')
            buffer.append(line)
        if buffer != data:
            with open(MDR_PATH / file_path, 'w', encoding='utf-8') as file:
                for line in buffer:
                    file.write(line)
            logger.info('rewrote_file')

    def uncomment_keyword(self, file_path: Path, keyword: str):
        data = open(MDR_PATH / file_path, encoding='utf-8').readlines()
        buffer = []
        for line in data:
            if line.strip().replace('#', '').split(':')[0] == keyword:
                line = line.replace('#', '')
                logger.info('found_and_uncommented_target_keyword', arg0=keyword)
            buffer.append(line)
        if buffer != data:
            with open(MDR_PATH / file_path, 'w', encoding='utf-8') as file:
                for line in buffer:
                    file.write(line)
                logger.info('rewrote_file')

    def indent_drilldown_section(self, file_path: Path):
        data = open(MDR_PATH / file_path, encoding='utf-8').readlines()
        buffer = []
        DRILLDOWN_RAW = ['    #drilldown:\n', '      #name: \n', '      #search: |\n', '        #Type Here\n']
        for line in data:
            if line in DRILLDOWN_RAW:
                line = '  ' + line
                logger.info('indented_part_of_the_drilldown_section')
            buffer.append(line)
        if buffer != data:
            with open(MDR_PATH / file_path, 'w', encoding='utf-8') as file:
                for line in buffer:
                    file.write(line)
            logger.info('rewrote_file')

    def migrate(self):
        for mdr in os.listdir(PATHS['mdr']):
            if not mdr.endswith('.yaml'):
                if not mdr.endswith('.yml'):
                    logger.info('the_file_doesn_t_end_with_yaml_or_yml_skipping', arg0=mdr)
                    continue
            data = yaml.safe_load(open(MDR_PATH / mdr, encoding='utf-8'))
            mdr_name = data['name']
            logger.info('assessing_if_security_domain_should_be_migrated', arg0=mdr_name)
            if 'splunk' not in data['configurations']:
                continue
            config = data['configurations']['splunk']
            if 'security_domain' in config:
                logger.info('migrating_security_domain_under_the_notable_block')
                self.indent_security_domain(MDR_PATH / mdr)
                if 'notable' not in config:
                    logger.info('uncommenting_notable_to_allow_nesting')
                    self.uncomment_keyword(MDR_PATH / mdr, 'notable')
            else:
                self.indent_security_domain(MDR_PATH / mdr)
            if 'drilldown' not in config.get('notable', {}):
                logger.info('drilldown_section_not_found_will_run_a_cleanup_in_case_it_is_not')
                self.indent_drilldown_section(MDR_PATH / mdr)

def run():
    MigrateSecurityDomainMDR().migrate()
if __name__ == '__main__':
    run()
