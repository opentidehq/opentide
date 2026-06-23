"""Schema validation — Pydantic model_validate pipeline."""
from __future__ import annotations
import os
import sys
from tabulate import tabulate
from opentide.core.registry import OpenTide
from opentide.validation.pipeline import validate_all_objects
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.validation.tide_schema')

def run() -> None:
    emit_section('Pydantic Schema Validation')
    logger.info('validates_all_opentide_objects_via_model_validate')
    OpenTide.initialise()
    errors = validate_all_objects(OpenTide.Index['objects'])
    stats: dict[str, int] = {}
    overall = 0
    for schema in OpenTide.Index['objects']:
        count = len(OpenTide.Index['objects'].get(schema, {}))
        stats[schema.upper()] = count
        overall += count
    for uuid, error_list in errors.items():
        for error in error_list:
            logger.critical('fatal_error', detail=f'Failed validation for object {uuid}', arg0=error)
    if errors:
        logger.critical('failed_schema_validation', detail='OpenTide objects currently do not match Pydantic models', advice='Review the files before running the validation again')
        os.environ['VALIDATION_ERROR_RAISED'] = 'True'
    else:
        statstable = [['Category', 'Count']]
        for key in stats:
            statstable.append([key, stats[key]])
        statstable = tabulate(statstable, headers='firstrow')
        logger.info('step_completed', detail=f'Successfully verified {overall} OpenTide objects')
        print(statstable)
if __name__ == '__main__':
    run()
