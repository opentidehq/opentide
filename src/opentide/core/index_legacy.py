import json
import os
from pathlib import Path
from typing import Literal

from opentide.core.logging import get_logger
from opentide.core.root import get_repo_root
from opentide.indexing.legacy_patch import LegacyObjectPatch

logger = get_logger(__name__)
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

        logger.warning("opentide_reindexation")
        logger.info(
            "reindexing_repository", detail="The repository will be reindexed to update OpenTide"
        )
        OTIndexManager.reload()
        OpenTide.reload()

    @staticmethod
    def load() -> dict[str, dict]:
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
        logger.info("staging_reconciliation_started")
        EXPECTED_STAGING_INDEX_PATH = ROOT / "staging_index.json"
        STAGING_INDEX_PATH = os.getenv("STAGING_INDEX_PATH") or EXPECTED_STAGING_INDEX_PATH
        if not os.path.exists(STAGING_INDEX_PATH):
            logger.info("no_staging_index_to_reconcile")
            return index
        from opentide.core.files import resolve_configurations

        RECONCILED_INDEX = index.copy()
        with open(Path(STAGING_INDEX_PATH), encoding="utf-8") as staging_file:
            STG_INDEX = json.load(staging_file)
        added_mdr = list()
        updated_mdr = list()
        patch = LegacyObjectPatch()
        for mdr in STG_INDEX:
            if mdr not in RECONCILED_INDEX["objects"]["rule"]:
                logger.info("patching_mdr_in_staging_index", mdr=mdr)
                RECONCILED_INDEX["objects"]["rule"][mdr] = patch.tide_1_patch(
                    STG_INDEX[mdr], "rule"
                )
                added_mdr.append(mdr)
            else:
                main_mdr_metadata = (
                    RECONCILED_INDEX["objects"]["rule"][mdr].get("meta")
                    or RECONCILED_INDEX["objects"]["rule"][mdr]["metadata"]
                )
                main_version = main_mdr_metadata["version"]
                stg_mdr_metadata = STG_INDEX[mdr].get("meta") or STG_INDEX[mdr]["metadata"]
                stg_version = stg_mdr_metadata["version"]
                mdr_name = (
                    STG_INDEX[mdr].get("name") or STG_INDEX[mdr]["title"].split("$")[0].strip()
                )
                if stg_version > main_version:
                    logger.info(
                        "replacing_mdr_from_staging",
                        mdr_name=mdr_name,
                        main_version=main_version,
                        staging_version=stg_version,
                    )
                    logger.info("safety_patching_staging_mdr")
                    RECONCILED_INDEX["objects"]["rule"][mdr] = patch.tide_1_patch(
                        STG_INDEX[mdr], "rule"
                    )
                    updated_mdr.append(mdr)
        logger.info("loading_fresh_configurations")
        RECONCILED_INDEX["configurations"] = resolve_configurations()
        logger.info("staging_reconciliation_complete")
        logger.info("updated_mdrs_from_staging", count=len(updated_mdr))
        logger.info("added_mdrs_from_staging", count=len(added_mdr))
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
            if "chaining" in n[tvm]["threat"]:
                if tvm not in chain:
                    chain[tvm] = dict()
                for link in n[tvm]["threat"]["chaining"]:
                    if link["relation"] not in chain[tvm]:
                        chain[tvm][link["relation"]] = []
                    if link["vector"] not in chain[tvm][link["relation"]]:
                        chain[tvm][link["relation"]].append(link["vector"])
        return chain

    @staticmethod
    def return_paths(tier: Literal["all", "core", "tide"]) -> dict[str, Path]:
        """Return pre-computed path mappings from the index for the requested tier.

        Args:
            tier: One of ``"all"``, ``"core"``, or ``"tide"`` specifying the
                scope of paths to return.

        Returns:
            A dict mapping logical path names to Path objects for the requested
            tier. ``"all"`` returns the full paths mapping, while ``"core"``
            and ``"tide"`` return the respective sub-mapping.
        """
        if tier == "all":
            return IndexManager.load()["paths"]
        if tier == "core":
            return IndexManager.load()["paths"]["core"]
        if tier == "tide":
            return IndexManager.load()["paths"]["tide"]
        return None


IndexTide = IndexManager
