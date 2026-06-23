import os
import yaml
import json
from pathlib import Path
import sys
import toml
import uuid
from pprint import pprint
from dataclasses import dataclass


from opentide.core.files import resolve_paths, resolve_configurations
from opentide.core.logging import log

def indexer(write_index=False) -> dict:
    SKIPS = ["ram", "mdrv2"]
    RESOLVED_CONFIGURATIONS = resolve_configurations()

    CORE_CONFIG = RESOLVED_CONFIGURATIONS["global"]

    RAW_PATHS = CORE_CONFIG["paths"]["tide"]
    RAW_CORE_PATHS = CORE_CONFIG["paths"]["core"]
    RAW_PATHS = RAW_CORE_PATHS | RAW_PATHS

    PATHS, CORE_PATHS = resolve_paths(separate=True)
    PATHS = PATHS | CORE_PATHS

    log("DEBUG", "Loaded all paths")
    VOCABULARIES_PATH = PATHS["vocabularies"]
    METASCHEMAS = CORE_CONFIG["metaschemas"]
    JSONSCHEMAS_PATH = PATHS["json_schemas"]
    JSONSCHEMAS = CORE_CONFIG["json_schemas"]
    SUBSCHEMAS_PATH = Path(PATHS.get("platform_templates", PATHS.get("subschemas", ".")))
    DEFINITIONS_PATH = Path(PATHS.get("definitions", "."))
    RECOMPOSITION = CORE_CONFIG["recomposition"]
    TEMPLATES_PATH = PATHS["templates"]
    TEMPLATES = CORE_CONFIG["templates"]
    INDEX_PATH = PATHS["tide_indexes"]
    
    @dataclass
    class IndexPaths:
        REVISIONS_INDEX_PATH = INDEX_PATH / "revisions.json"


    OUTPUT_PATH = PATHS["index_output"]


    # Controls whether the index should keep in memory or export to a file
    # In-memory is helpful when index is used to accelerate functions, like
    # for example to enrich deployment tags.

    index = dict()
    obj_counter = 0

    log("TITLE", "Tide Indexer")
    log("INFO", "Seeks all Tide related data and stores it for direct access")
    # Vocab Indexer

    log("INFO", "Resolving and indexing", "paths")
    index["paths"] = dict()
    index["paths"].update(PATHS)
    index["paths"]["tide"] = PATHS
    index["paths"]["core"] = CORE_PATHS
    index["paths"]["raw"] = RAW_PATHS
    index["paths"]["raw"]["tide"] = RAW_PATHS
    index["paths"]["raw"]["core"] = RAW_CORE_PATHS

    log("INFO", "Resolving and index", "configurations")
    # Config Indexer
    # Configurations resolve by merging the default Core configs
    # with custom ones defined in the user space

    index["configurations"] = RESOLVED_CONFIGURATIONS

    print("📒 Indexing Vocabularies...")

    from opentide.generation.vocabulary import VocabularyLoadError, parse_yaml_vocabulary

    voc_index = dict()
    for voc_file in sorted(os.listdir(VOCABULARIES_PATH)):
        if not voc_file.endswith((".yaml", ".yml")):
            continue
        obj_counter += 1
        voc_path = VOCABULARIES_PATH / voc_file
        try:
            voc_body = yaml.safe_load(open(voc_path, encoding="utf-8"))
        except Exception as exc:
            log("FAILURE", f"Could not read vocabulary YAML {voc_file}", str(exc))
            continue

        if not voc_body:
            log("WARNING", "Could not find data in vocabulary/index", voc_file)
            continue

        try:
            vocabulary = parse_yaml_vocabulary(voc_body, source=voc_file)
        except VocabularyLoadError as exc:
            log("FAILURE", str(exc), voc_file)
            continue

        voc_index[vocabulary.metadata.field] = vocabulary.to_index_dict()

    index["vocabs"] = voc_index

    # JSON Schemas Indexer
    print("🛠️ Indexing JSON Schemas...")

    json_index = dict()

    for meta_name in JSONSCHEMAS:
        json_schema_path = JSONSCHEMAS_PATH / JSONSCHEMAS[meta_name]
        if os.path.isfile(
            json_schema_path
        ):  # In case we are generating the json for the first time
            print("Loading... " + str(json_schema_path))
            json_schema_body = json.load(open(json_schema_path, encoding="utf-8"))
            json_index[meta_name] = json_schema_body
            obj_counter += 1

    index["json_schemas"] = json_index

    # Core schema sources are generated from Pydantic models at index time.
    from opentide.generation.pydantic_metaschema import (
        build_core_schema_source,
        build_definition_index,
        build_platform_schema_source,
    )
    from opentide.models.platform_schema import platform_model_for_key

    print("🛠️ Indexing Pydantic schema sources...")

    meta_index = dict()
    for meta_name in METASCHEMAS:
        obj_counter += 1
        meta_index[meta_name] = build_core_schema_source(meta_name)

    index["metaschemas"] = meta_index

    print("🛠️ Indexing Definitions...")
    definition_index = build_definition_index()
    index["definitions"] = definition_index

    print("📐 Indexing Templates")

    template_index = dict()

    for cat in TEMPLATES:

        template_path = TEMPLATES_PATH / TEMPLATES[cat]

        if os.path.isfile(template_path):
            template = open(template_path, encoding="utf-8").read()
            template_index[cat] = template
            obj_counter += 1

    # Template indexer and Subschema indexer (as dependent on recomposition)
    print("📐 Indexing Recomposition Templates")
    print("🧩 Indexing Subschemas")

    subschemas_index = dict()
    for recomp in RECOMPOSITION:
        template_index[recomp] = {}
        subschemas_index[recomp] = {}
        sub_folder = RECOMPOSITION[recomp]
        subchemas_path = SUBSCHEMAS_PATH / sub_folder
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
                template_body = open(
                    sub_templates_path / (sub_name + " Template.yaml"), encoding="utf-8"
                ).read()
                template_index[recomp][data] = template_body
            except Exception:
                log(
                    "FATAL",
                    f"Could not find template for {sub_name} at location {sub_templates_path}",
                    "This will be skipped as it is expected when creating new subschemas",
                )

    index["templates"] = template_index
    index["subschemas"] = subschemas_index

    # Objects Indexer

    print("📊 Indexing Objects...")

    objects_index = dict()
    files_index = dict()
    objects_index["signal"] = dict()

    for meta_name in METASCHEMAS:
        if meta_name not in SKIPS:
            model_cat_index = dict()
            
            if not os.path.exists(PATHS[meta_name]):
                log("FAILURE",
                    "Could not find the folder at the expected location",
                    str(PATHS[meta_name]),
                    "Ensure that your repository and configuration files are aligned")
                objects_index[meta_name] = {}
                continue

            for model in os.listdir(PATHS[meta_name]):
                
                #Skips for empty InitTide repositories
                if model == ".gitkeep":
                    continue
                
                model_path = Path(PATHS[meta_name]) / model
                if (not os.path.isdir(model_path)) and (str(model_path).endswith(".yaml")):
                    obj_counter += 1

                    if not model.endswith(".debug.yaml"):
                        model_body = yaml.safe_load(open(model_path, encoding="utf-8"))

                        identifier = model_body.get("uuid") or model_body.get("metadata",{}).get("uuid")
                        if not identifier:
                            log("FATAL", "Missing identifier from model in file", model)
                        else:
                            model_cat_index[identifier] = model_body
                            files_index[identifier] = model

                            # Creating a sub-index for signals so we can more easily search in them through OpenTide
                            # We copy each signal to avoid polluting the DOM data with the 'parent' field
                            if meta_name == "objective":
                                signals = model_body.get("objective",{}).get("signals", [])
                                for idx, signal in enumerate(signals or []):
                                    if not signal:
                                        log("FATAL", 
                                            f"Signal at index {idx} is empty/null in Detection Objective",
                                            f"File: {model}",
                                            f"Detection Objective UUID: {identifier}",
                                            "Ensure all signals in the 'signals' list are properly defined")
                                        raise ValueError(f"Empty signal at index {idx} in Detection Objective '{model}'")
                                    if not signal.get("uuid"):
                                        signal_name = signal.get("name", "unnamed")
                                        log("FATAL", 
                                            f"Signal '{signal_name}' is missing a UUID",
                                            f"File: {model}",
                                            f"Detection Objective UUID: {identifier}",
                                            "Every signal must have a unique 'uuid' field")
                                        raise ValueError(f"Signal '{signal_name}' missing UUID in Detection Objective '{model}'")
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

    log(
        "INFO",
        "Built inline object vocabularies from indexed models",
        str(len(object_vocab_index)),
    )

    indexes_index: dict[str, object] = {"objects": object_vocab_index}

    if not os.path.exists(IndexPaths.REVISIONS_INDEX_PATH):
        log("SKIP", "Not able to find a revisions.json index in Tide instance",
            "Should be generated in the next Framework generation pipeline run")
    else:
        revisions_index = json.load(open(IndexPaths.REVISIONS_INDEX_PATH, encoding="utf-8"))
        indexes_index["revisions"] = revisions_index

    index["indexes"] = indexes_index

    # Security Stack Mapping Indexer

    # print("🔒 Indexing Cloud Security Stack Mappings...")
    #
    # CLOUD_MITIGATIONS = Path(CONFIG["paths"]["resources"]) / "security-stack-mappings"
    # CLOUD_PLATFORMS = ["AWS", "Azure" ,"GCP"]
    # CLOUD_MAPPINGS_INDEX = dict()
    #
    # for plat in CLOUD_PLATFORMS:
    #    path = CLOUD_MITIGATIONS / plat
    #    buf = list()
    #    for file in os.listdir(path):
    #        if not os.path.isdir(path / file) is True and file.endswith(".yaml"):
    #            obj_counter += 1
    #
    #            body = yaml.safe_load(open(path / file, encoding='utf-8'))
    #            buf.append(body)
    #    CLOUD_MAPPINGS_INDEX[plat] = buf
    #
    # index["security-stack-mappings"] = CLOUD_MAPPINGS_INDEX
    #
    #
    #
    ##ATT&CK relationship Indexer
    #
    # print("⛓️ Indexing ATT&CK Relationships...")
    #
    # ATTACK_ENT = Path(CONFIG["paths"]["att&ck"]) / CONFIG["resources"]["attack"]["enterprise"]
    # ATTACK_ICS = Path(CONFIG["paths"]["att&ck"]) / CONFIG["resources"]["attack"]["ics"]
    # ATTACK_MOB = Path(CONFIG["paths"]["att&ck"]) / CONFIG["resources"]["attack"]["mobile"]
    #
    # ENTERPRISE = pd.read_excel(open(ATTACK_ENT, 'rb'), sheet_name='relationships')
    # ICS = pd.read_excel(open(ATTACK_ICS, 'rb'), sheet_name='relationships')
    # MOBILE = pd.read_excel(open(ATTACK_MOB, 'rb'), sheet_name='relationships')
    #
    # df = pd.concat([ENTERPRISE, ICS, MOBILE])
    #
    # RELATIONSHIPS = df.to_json(orient="records")
    #
    # index["attack-relationships"] = RELATIONSHIPS
    #
    # obj_counter += len(df)
    #
    ##Atomics Indexer
    #
    # print("⚛️ Indexing Atomic Red Tests...")
    #
    # ATOMICS = Path(CONFIG["paths"]["resources"]) / "atomics"
    # ATOMICS_MAPPINGS_INDEX = dict()
    # KB_TO_ATOMIC = Path("../../../Automation/Resources/atomics/")
    #
    # for folder in os.listdir(ATOMICS):
    #    if os.path.isdir(ATOMICS/folder) and folder != "Indexes":
    #        obj_counter += 1
    #
    #        file_name = folder + ".yaml"
    #        doc_name = folder + ".md"
    #        body = yaml.safe_load(open(ATOMICS/folder/file_name, encoding='utf-8'))
    #        body["doc"] = open(ATOMICS/folder/doc_name, encoding='utf-8').read()
    #        ATOMICS_MAPPINGS_INDEX[folder] = body
    #
    # index["atomics"] = ATOMICS_MAPPINGS_INDEX
    #
    #

    if write_index or os.getenv("WRITE_INDEX"):
        print("📝 Exporting Index file to : {} ...".format(OUTPUT_PATH))
        with open(OUTPUT_PATH, "w+", encoding="utf-8") as index_file:
            json.dump(index, index_file, default=str)

    return index


if __name__ == "__main__":
    # if os.environ.get("GENERATE_INDEX_FILE"):
    #    indexer(write_index=True)
    # else:
    #    indexer()
    indexer(write_index=True)
