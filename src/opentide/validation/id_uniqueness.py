import os
from pathlib import Path

import yaml

from opentide.core.files import resolve_configurations, resolve_paths
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.validation.id_uniqueness')
CORE_CONFIG = resolve_configurations()['global']
METASCHEMAS = CORE_CONFIG['metaschemas']
SKIPS = ['logsources', 'ram', 'mdrv2']
PATHS = resolve_paths()
duplicates = list()
registry = dict()

def run():
    emit_section('ID Duplication Checks')
    logger.info('check_if_id_used_in_coretide_are_uniquely_assigned')
    for meta_name in METASCHEMAS:
        if meta_name not in SKIPS:
            logger.info('now_checking_for_id_duplication_in', detail=f'{meta_name.upper()}...')
            if not os.path.exists(PATHS[meta_name]):
                logger.error('could_not_find_the_folder_at_the_expected_location', detail=str(PATHS[meta_name]), advice='Ensure that your repository and configuration files are aligned')
                continue
            for model in os.listdir(PATHS[meta_name]):
                if not model.endswith('.yaml'):
                    continue
                model_path = Path(PATHS[meta_name]) / model
                with open(model_path, encoding='utf-8') as handle:
                    model_body = yaml.safe_load(handle)
                uuid = model_body.get('metadata', {}).get('uuid')
                file_name = model
                name = model_body['name']
                if uuid not in registry:
                    registry[uuid] = {'name': name, 'file_name': file_name}
                else:
                    duplicates.append({'uuid': uuid, 'name': name, 'file_name': file_name})
    if duplicates:
        for dup in duplicates:
            original = registry[dup['uuid']]
            original_name = original['name']
            original_file_name = original['file_name']
            logger.error('operation_failed', detail=f"Duplicated ID found with {dup['uuid']} - {dup['name']} @ [{dup['file_name']}]", context_1=f'has the same id as {original_name} @ ({original_file_name})')
        logger.critical('cannot_have_duplicated_ids_throughout_multiple_coretide_objects')
        os.environ['VALIDATION_ERROR_RAISED'] = 'True'
    else:
        logger.info('no_duplicated_id_throughout', detail=f'{len(registry)} objects')
if __name__ == '__main__':
    run()
