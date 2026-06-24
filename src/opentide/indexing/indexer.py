import json
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.logging import get_logger, is_debug_enabled
from opentide.core.logging.console import emit_section

logger = get_logger(__name__)


def indexer(write_index=False) -> dict:
    SKIPS = ["ram", "mdrv2"]
    RESOLVED_CONFIGURATIONS = resolve_configurations()
    CORE_CONFIG = RESOLVED_CONFIGURATIONS["global"]
    RAW_PATHS = CORE_CONFIG["paths"]["tide"]
    RAW_CORE_PATHS = CORE_CONFIG["paths"]["core"]
    RAW_PATHS = RAW_CORE_PATHS | RAW_PATHS
    PATHS, CORE_PATHS = resolve_paths(separate=True)
    PATHS = PATHS | CORE_PATHS
    logger.debug("loaded_all_paths")
    VOCABULARIES_PATH = PATHS["vocabularies"]
    METASCHEMAS = CORE_CONFIG["metaschemas"]
    JSONSCHEMAS_PATH = PATHS["json_schemas"]
    JSONSCHEMAS = CORE_CONFIG["json_schemas"]
    SUBSCHEMAS_PATH = Path(PATHS.get("platform_templates", PATHS.get("subschemas", ".")))
    RECOMPOSITION = CORE_CONFIG["recomposition"]
    TEMPLATES_PATH = PATHS["templates"]
    TEMPLATES = CORE_CONFIG["templates"]
    INDEX_PATH = PATHS["tide_indexes"]

    @dataclass
    class IndexPaths:
        REVISIONS_INDEX_PATH = INDEX_PATH / "revisions.json"

    OUTPUT_PATH = PATHS["index_output"]
    index = dict()
    obj_counter = 0
    emit_section("Tide Indexer")
    logger.info(
        "indexer_started",
        detail="Seeks all Tide related data and stores it for direct access",
    )
    logger.info("resolving_and_indexing", detail="paths")
    index["paths"] = dict()
    index["paths"].update(PATHS)
    index["paths"]["tide"] = PATHS
    index["paths"]["core"] = CORE_PATHS
    index["paths"]["raw"] = RAW_PATHS
    index["paths"]["raw"]["tide"] = RAW_PATHS
    index["paths"]["raw"]["core"] = RAW_CORE_PATHS
    logger.info("resolving_and_index", detail="configurations")
    index["configurations"] = RESOLVED_CONFIGURATIONS
    logger.info("indexing_vocabularies")
    from opentide.vocabulary.io import load_vocab_file

    voc_index = dict()
    for voc_file in sorted(os.listdir(VOCABULARIES_PATH)):
        if not voc_file.endswith(".vocab.toml"):
            continue
        obj_counter += 1
        voc_path = VOCABULARIES_PATH / voc_file
        try:
            vocabulary = load_vocab_file(voc_path)
        except Exception as exc:
            logger.error("could_not_read_vocabulary", detail=str(exc))
            continue
        voc_index[vocabulary.metadata.field] = vocabulary.to_index_dict()
    index["vocabs"] = voc_index
    logger.info("indexing_json_schemas")
    json_index = dict()
    for meta_name in JSONSCHEMAS:
        json_schema_path = JSONSCHEMAS_PATH / JSONSCHEMAS[meta_name]
        if os.path.isfile(json_schema_path):
            if is_debug_enabled():
                logger.debug("loading_json_schema", path=str(json_schema_path))
            with open(json_schema_path, encoding="utf-8") as json_schema_file:
                json_schema_body = json.load(json_schema_file)
            json_index[meta_name] = json_schema_body
            obj_counter += 1
    index["json_schemas"] = json_index
    from opentide.generation.pydantic_metaschema import (
        build_core_schema_source,
        build_definition_index,
        build_platform_schema_source,
    )
    from opentide.models.platform_schema import platform_model_for_key

    logger.info("indexing_pydantic_schema_sources")
    meta_index = dict()
    for meta_name in METASCHEMAS:
        obj_counter += 1
        meta_index[meta_name] = build_core_schema_source(meta_name)
    index["metaschemas"] = meta_index
    logger.info("indexing_definitions")
    definition_index = build_definition_index()
    index["definitions"] = definition_index
    logger.info("indexing_templates")
    template_index = dict()
    for cat in TEMPLATES:
        template_path = TEMPLATES_PATH / TEMPLATES[cat]
        if os.path.isfile(template_path):
            with open(template_path, encoding="utf-8") as template_file:
                template = template_file.read()
            template_index[cat] = template
            obj_counter += 1
    logger.info("indexing_recomposition_templates")
    logger.info("indexing_subschemas")
    subschemas_index = dict()
    for recomp in RECOMPOSITION:
        template_index[recomp] = {}
        subschemas_index[recomp] = {}
        sub_folder = RECOMPOSITION[recomp]
        sub_templates_path = SUBSCHEMAS_PATH / sub_folder / "Templates"
        recomp_data = index["configurations"][recomp]
        for data in recomp_data:
            obj_counter += 1
            try:
                sub_name = recomp_data[data]["tide"]["name"]
            except Exception:
                sub_name = recomp_data[data]["platform"]["name"]
            platform_model = platform_model_for_key(data)
            sub_body = build_platform_schema_source(platform_model)
            subschemas_index[recomp][data] = sub_body
            try:
                with open(
                    sub_templates_path / (sub_name + " Template.yaml"), encoding="utf-8"
                ) as template_file:
                    template_body = template_file.read()
                template_index[recomp][data] = template_body
            except Exception:
                logger.critical(
                    "could_not_find_template_for",
                    detail="This will be skipped as it is expected when creating new subschemas",
                )
    index["templates"] = template_index
    index["subschemas"] = subschemas_index
    logger.info("indexing_objects")
    objects_index = dict()
    files_index = dict()
    objects_index["signal"] = dict()
    for meta_name in METASCHEMAS:
        if meta_name not in SKIPS:
            model_cat_index = dict()
            if not os.path.exists(PATHS[meta_name]):
                logger.error(
                    "could_not_find_the_folder_at_the_expected_location",
                    detail=str(str(PATHS[meta_name]))
                    + " | "
                    + "Ensure that your repository and configuration files are aligned",
                )
                objects_index[meta_name] = {}
                continue
            for model in os.listdir(PATHS[meta_name]):
                if model == ".gitkeep":
                    continue
                model_path = Path(PATHS[meta_name]) / model
                if not os.path.isdir(model_path) and str(model_path).endswith(".yaml"):
                    obj_counter += 1
                    if not model.endswith(".debug.yaml"):
                        with open(model_path, encoding="utf-8") as model_file:
                            model_body = yaml.safe_load(model_file)
                        identifier = model_body.get("uuid") or model_body.get("metadata", {}).get(
                            "uuid"
                        )
                        if not identifier:
                            logger.critical("missing_identifier_from_model_in_file", detail=model)
                        else:
                            model_cat_index[identifier] = model_body
                            files_index[identifier] = model
                            if meta_name == "objective":
                                signals = model_body.get("objective", {}).get("signals", [])
                                for idx, signal in enumerate(signals or []):
                                    if not signal:
                                        logger.critical(
                                            "signal_at_index",
                                            detail=str(f"File: {model}")
                                            + " | "
                                            + str(f"Detection Objective UUID: {identifier}")
                                            + " | "
                                            + "Ensure all signals in the 'signals' list are properly defined",
                                        )
                                        raise ValueError(
                                            f"Empty signal at index {idx} in Detection Objective '{model}'"
                                        )
                                    if not signal.get("uuid"):
                                        signal_name = signal.get("name", "unnamed")
                                        logger.critical(
                                            "signal",
                                            detail=str(f"File: {model}")
                                            + " | "
                                            + str(f"Detection Objective UUID: {identifier}")
                                            + " | "
                                            + "Every signal must have a unique 'uuid' field",
                                        )
                                        raise ValueError(
                                            f"Signal '{signal_name}' missing UUID in Detection Objective '{model}'"
                                        )
                                    signal_copy = signal.copy()
                                    signal_copy["parent"] = identifier
                                    objects_index["signal"][signal["uuid"]] = signal_copy
            objects_index[meta_name] = model_cat_index
    index["objects"] = objects_index
    index["files"] = files_index
    from opentide.indexing.object_vocab import build_object_vocabularies

    doc_config = RESOLVED_CONFIGURATIONS.get("documentation", {})
    object_vocab_index = build_object_vocabularies(
        object_scope=CORE_CONFIG.get("objects", []),
        models_index=objects_index,
        icons=doc_config.get("icons", {}),
        object_names=doc_config.get("object_names", {}),
    )
    index["vocabs"].update(object_vocab_index)
    logger.info(
        "built_inline_object_vocabularies_from_indexed_models", detail=str(len(object_vocab_index))
    )
    indexes_index: dict[str, object] = {"objects": object_vocab_index}
    if not os.path.exists(IndexPaths.REVISIONS_INDEX_PATH):
        logger.info(
            "not_able_to_find_a_revisions_json_index_in_tide_instance",
            detail="Should be generated in the next Framework generation pipeline run",
        )
    else:
        with open(IndexPaths.REVISIONS_INDEX_PATH, encoding="utf-8") as revisions_file:
            revisions_index = json.load(revisions_file)
        indexes_index["revisions"] = revisions_index
    index["indexes"] = indexes_index
    if write_index or os.getenv("WRITE_INDEX"):
        logger.info("exporting_index_file", path=str(OUTPUT_PATH))
        with open(OUTPUT_PATH, "w+", encoding="utf-8") as index_file:
            json.dump(index, index_file, default=str)
    return index


if __name__ == "__main__":
    indexer(write_index=True)
