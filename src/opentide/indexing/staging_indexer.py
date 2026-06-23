import yaml
import json
from pathlib import Path
import os
from datetime import datetime
import sys
import traceback
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.indexing.staging_indexer')
toolchain_start_time = datetime.now()
from opentide.deployment import modified_mdr_files, DeploymentStrategy
from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.root import get_repo_root
ROOT = get_repo_root()
CORE_CONFIG = resolve_configurations()['global']
PATHS = resolve_paths()
PROJECT_NAME = os.getenv('CI_PROJECT_NAME')
STG_INDEX_PATH = ROOT / CORE_CONFIG['paths']['core']['staging_index_output']
DEPLOYMENT_PLAN = os.getenv('DEPLOYMENT_PLAN')
SCRIPT_NAME = 'MDR Staging Index Updater'
SCRIPT_DESCRIPTION = 'Updates the Staging Index maintained in the Wiki with the latest modification'
print('\n\n' + SCRIPT_NAME.center(80, '='))
print('\n' + SCRIPT_DESCRIPTION + '\n')
emit_section('Staging Index Reconcilier')
logger.info('loads_a_version_of_the_index_which_adds_data_from_mdr_in_staging')
mdr_to_index = modified_mdr_files(DeploymentStrategy.STAGING)
if len(mdr_to_index) == 0:
    try:
        logger.critical('no_deployment_possible_could_not_identify_mdrs_that_can_be_deplo')
        raise Exception('NO_DEPLOYMENT_FOUND')
    except Exception:
        traceback.print_exc()
        sys.exit(19)
else:
    os.environ['DEPLOYMENT'] = str(mdr_to_index)
current_stg_index = dict()
for mdr in mdr_to_index:
    with open(mdr, encoding='utf-8') as mdr_file:
        mdr_data = yaml.safe_load(mdr_file)
    mdr_name = mdr_data.get('name') or mdr_data['title']
    logger.info('updating_the_staging_index', arg0=mdr_name)
    uuid = mdr_data.get('uuid') or mdr_data['metadata']['uuid']
    current_stg_index[uuid] = mdr_data
if not os.path.exists(STG_INDEX_PATH):
    print(' Could not find a staging index file, will create one')
    with open(STG_INDEX_PATH, 'w+') as out:
        json.dump(current_stg_index, out, default=str)
else:
    print(' Found MDR index, extending it with latest values')
    with open(Path(STG_INDEX_PATH), encoding='utf-8') as staging_file:
        stg_index = json.load(staging_file)
    stg_index.update(current_stg_index)
    with open(STG_INDEX_PATH, 'w+') as out:
        json.dump(stg_index, out, default=str, indent=4)
print('\n' + 'Execution Report'.center(80, '='))
time_to_execute = datetime.now() - toolchain_start_time
time_to_execute = '%.2f' % time_to_execute.total_seconds()
print('\n Exported Staging index in {} seconds'.format(time_to_execute))
