import pandas as pd
import os
from uuid import UUID
from opentide.core.registry import OpenTide
from opentide.core.files import resolve_configurations
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.validation.uuid_v4')
MODELS_INDEX = OpenTide.Models.Index
CONFIGURATIONS = resolve_configurations()
MODELS_TYPES = CONFIGURATIONS['global']['objects']

def run():
    emit_section('TIDE Objects UUIDv4 Validation')
    logger.info('validates_object_uuids_against_the_v4_specification')
    error_registry = list()
    counter = 0
    for tide_model in MODELS_TYPES:
        for tide_object in MODELS_INDEX[tide_model]:
            tide_object_data = MODELS_INDEX[tide_model][tide_object]
            tide_object_uuid = tide_object_data.get('uuid') or tide_object_data['metadata']['uuid']
            tide_object_name = tide_object_data['name']
            try:
                UUID(tide_object_uuid, version=4)
            except (ValueError, TypeError):
                error_registry.append({'Object Name': tide_object_name, 'UUID': tide_object_uuid})
            counter += 1
    if error_registry:
        os.environ['VALIDATION_ERROR_RAISED'] = 'True'
        logger.warning('event', detail=f' Successfully validated {counter} tide_objects but found', context_1=f'{len(error_registry)} invalid ones')
        error_table = pd.DataFrame(error_registry).to_markdown(index=False, tablefmt='fancy_grid')
        print(error_table)
        logger.error('failed_uuid_validation')
    else:
        logger.info('successfully_validated', detail=f'{counter} tide_objects')
if __name__ == '__main__':
    run()
