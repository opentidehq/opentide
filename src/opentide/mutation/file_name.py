import sys
import os
import uuid
from pathlib import Path
import yaml
from opentide.core.files import safe_file_name, resolve_configurations, resolve_paths
from opentide.core.root import get_repo_root
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.mutation.file_name')
ROOT = get_repo_root()
CONFIGURATIONS = resolve_configurations()
PATHS = resolve_paths()
MODELS_TYPES = CONFIGURATIONS['global']['objects']

def run():
    emit_section('File Name Aligner')
    logger.info('aligns_the_file_name_with_the_yaml_content_and_assigns_id_if_mis')
    MODELS_TYPES.remove('mdr')
    for model in MODELS_TYPES:
        for file in sorted(os.listdir(PATHS[model])):
            if not file.endswith('.yaml'):
                if not file.endswith('.yml'):
                    logger.info('the_file_doesn_t_end_with_yaml_or_yml_skipping', arg0=file)
                    continue
            data = yaml.safe_load(open(PATHS[model] / file, encoding='utf-8'))
            model_name = data['name']
            standard_name = f'{safe_file_name(model_name)}.yaml'
            if file != standard_name:
                logger.info('re_aligning_file_name_with_model_data', arg0=file)
                os.rename(PATHS[model] / file, PATHS[model] / (standard_name + '.tmp'))
                os.rename(PATHS[model] / (standard_name + '.tmp'), PATHS[model] / standard_name)
                logger.info('step_completed', arg0=standard_name)
        else:
            logger.info('no_files_to_assign_id_or_fix_file_names_in_model_type', arg0=model)
if __name__ == '__main__':
    run()
