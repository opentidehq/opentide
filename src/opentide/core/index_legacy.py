import os
import sys
from pathlib import Path
import json
from typing import Any, Dict, Literal, Mapping, Optional, Sequence, Tuple, Union, overload
from functools import cache
from abc import ABC
from importlib import import_module
from copy import deepcopy
from dataclasses import dataclass, asdict
from opentide.indexing.indexer import indexer
from opentide.models.legacy import DetectionSystems, TideModels, TideDefinitionsModels, TideConfigs, SystemConfig
from opentide.indexing.legacy_patch import LegacyObjectPatch
from opentide.loading.objects import Objects
from opentide.loading.configurations import Configurations
from opentide.core.root import get_repo_root
import structlog
logger = structlog.get_logger('opentide.core.index_legacy')
ROOT = get_repo_root()

class IndexManager:
    """
    Helper class for callable Index related functions. Designed to power
    `DataTide` initialization routine.
    """

    @staticmethod
    def reload():
        """Refresh the in-memory index via opentide IndexManager."""
        from opentide.core.index_manager import IndexManager as OTIndexManager
        from opentide.core.registry import OpenTide
        logger.warning('opentide_re_indexation')
        logger.info('the_repository_will_be_reindexed_to_update_opentide')
        OTIndexManager.reload()
        OpenTide.reload()

    @staticmethod
    def load() -> Dict[str, dict]:
        from opentide.core.index_manager import IndexManager as OTIndexManager
        return OTIndexManager.load()

    @staticmethod
    def reconcile_staging(index):
        """Merge staging index model data into the provided production index.

        If a staging index exists (``staging_index.json`` by default or as
        specified by ``STAGING_INDEX_PATH``), this routine will:
        
        1. Load the staging index
        2. Merge model data (MDRs) from staging into production, where:
           - New MDRs from staging are added
           - MDRs with higher version in staging replace production versions
        3. Load fresh configurations from TOML files

        Args:
            index: The production index dictionary to reconcile against.

        Returns:
            A new index dictionary that contains reconciled model data and fresh
            configurations.
        """
        logger.info('entering_staging_index_reconciliation_routine')
        EXPECTED_STAGING_INDEX_PATH = ROOT / 'staging_index.json'
        STAGING_INDEX_PATH = os.getenv('STAGING_INDEX_PATH') or EXPECTED_STAGING_INDEX_PATH
        if not os.path.exists(STAGING_INDEX_PATH):
            logger.info('no_staging_index_to_reconcile')
            return index
        from opentide.core.files import resolve_configurations
        RECONCILED_INDEX = index.copy()
        STG_INDEX = json.load(open(Path(STAGING_INDEX_PATH)))
        added_mdr = list()
        updated_mdr = list()
        patch = LegacyObjectPatch()
        for mdr in STG_INDEX:
            if mdr not in RECONCILED_INDEX['objects']['mdr']:
                logger.info('patching_mdr_in_staging_index', arg0=mdr)
                RECONCILED_INDEX['objects']['mdr'][mdr] = patch.tide_1_patch(STG_INDEX[mdr], 'mdr')
                added_mdr.append(mdr)
            else:
                main_mdr_metadata = RECONCILED_INDEX['objects']['mdr'][mdr].get('meta') or RECONCILED_INDEX['objects']['mdr'][mdr]['metadata']
                main_version = main_mdr_metadata['version']
                stg_mdr_metadata = STG_INDEX[mdr].get('meta') or STG_INDEX[mdr]['metadata']
                stg_version = stg_mdr_metadata['version']
                mdr_name = STG_INDEX[mdr].get('name') or STG_INDEX[mdr]['title'].split('$')[0].strip()
                if stg_version > main_version:
                    logger.info('event', detail=f'Replacing MDR {mdr_name} from prod index with staging data, as version is higher (main : v{main_version} staging : v{stg_version})')
                    logger.info('doing_a_safety_patching_to_avoid_edge_cases')
                    RECONCILED_INDEX['objects']['mdr'][mdr] = patch.tide_1_patch(STG_INDEX[mdr], 'mdr')
                    updated_mdr.append(mdr)
        logger.info('loading_fresh_configurations_from_toml_files')
        RECONCILED_INDEX['configurations'] = resolve_configurations()
        logger.info('finalized_staging_reconciliation_routine')
        logger.info('updated_mdrs_from_production_index_with_staging_data', detail=str(len(updated_mdr)))
        logger.info('new_mdr_added_from_staging_data', detail=str(len(added_mdr)))
        return RECONCILED_INDEX

    @staticmethod
    def compute_chains(tvm_index: dict) -> dict:
        """Compute chaining relationships between threat vector models (TVMs).

        This function inspects the provided TVM index and builds a mapping of
        TVM UUIDs to their chaining relations. The returned structure maps each
        TVM to another mapping where keys are relation names and values are
        lists of vectors (UUIDs) that are linked under that relation.

        Args:
            tvm_index: A dictionary where keys are TVM identifiers and values
                contain a ``threat`` key which may include a ``chaining`` list.

        Returns:
            A dictionary of the form {tvm_id: {relation: [vector_id, ...]}}
            only for TVMs that include chaining definitions.
        """
        chain = dict()
        for tvm in (n := tvm_index):
            if 'chaining' in n[tvm]['threat']:
                if tvm not in chain:
                    chain[tvm] = dict()
                for link in n[tvm]['threat']['chaining']:
                    if link['relation'] not in chain[tvm]:
                        chain[tvm][link['relation']] = []
                    if link['vector'] not in chain[tvm][link['relation']]:
                        chain[tvm][link['relation']].append(link['vector'])
        return chain

    @staticmethod
    def return_paths(tier: Literal['all', 'core', 'tide']) -> dict[str, Path]:
        """Return pre-computed path mappings from the index for the requested tier.

        Args:
            tier: One of ``"all"``, ``"core"``, or ``"tide"`` specifying the
                scope of paths to return.

        Returns:
            A dict mapping logical path names to Path objects for the requested
            tier. ``"all"`` returns the full paths mapping, while ``"core"``
            and ``"tide"`` return the respective sub-mapping.
        """
        if tier == 'all':
            return IndexManager.load()['paths']
        if tier == 'core':
            return IndexManager.load()['paths']['core']
        if tier == 'tide':
            return IndexManager.load()['paths']['tide']
IndexTide = IndexManager
