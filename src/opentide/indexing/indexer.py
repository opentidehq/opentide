import os
import yaml
import json
from pathlib import Path
from dataclasses import dataclass
from opentide.core.files import resolve_paths, resolve_configurations
from opentide.core.logging import log

def indexer(write_index=False) -> dict:
    SKIPS = ['ram', 'mdrv2']
    RESOLVED_CONFIGURATIONS = resolve_configurations()
    CORE_CONFIG = RESOLVED_CONFIGURATIONS['global']
    RAW_PATHS = CORE_CONFIG['paths']['tide']
    RAW_CORE_PATHS = CORE_CONFIG['paths']['core']
    RAW_PATHS = RAW_CORE_PATHS | RAW_PATHS
    PATHS, CORE_PATHS = resolve_paths(separate=True)
    PATHS = PATHS | CORE_PATHS
    log('DEBUG', 'Loaded all paths')
    VOCABULARIES_PATH = PATHS['vocabularies']
    METASCHEMAS = CORE_CONFIG['metaschemas']
    JSONSCHEMAS_PATH = PATHS['json_schemas']
    JSONSCHEMAS = CORE_CONFIG['json_schemas']
    SUBSCHEMAS_PATH = Path(PATHS.get('platform_templates', PATHS.get('subschemas', '.')))
    RECOMPOSITION = CORE_CONFIG['recomposition']
    TEMPLATES_PATH = PATHS['templates']
    TEMPLATES = CORE_CONFIG['templates']
    INDEX_PATH = PATHS['tide_indexes']

    @dataclass
    class IndexPaths:
        REVISIONS_INDEX_PATH = INDEX_PATH / 'revisions.json'
    OUTPUT_PATH = PATHS['index_output']
    index = dict()
    obj_counter = 0
    log('TITLE', 'Tide Indexer')
    log('INFO', 'Seeks all Tide related data and stores it for direct access')
    log('INFO', 'Resolving and indexing', 'paths')
    index['paths'] = dict()
    index['paths'].update(PATHS)
    index['paths']['tide'] = PATHS
    index['paths']['core'] = CORE_PATHS
    index['paths']['raw'] = RAW_PATHS
    index['paths']['raw']['tide'] = RAW_PATHS
    index['paths']['raw']['core'] = RAW_CORE_PATHS
    log('INFO', 'Resolving and index', 'configurations')
    index['configurations'] = RESOLVED_CONFIGURATIONS
    print(' Indexing Vocabularies...')
    from opentide.vocabulary.io import load_vocab_file
    voc_index = dict()
    for voc_file in sorted(os.listdir(VOCABULARIES_PATH)):
        if not voc_file.endswith('.vocab.toml'):
            continue
        obj_counter += 1
        voc_path = VOCABULARIES_PATH / voc_file
        try:
            vocabulary = load_vocab_file(voc_path)
        except Exception as exc:
            log('FAILURE', f'Could not read vocabulary {voc_file}', str(exc))
            continue
        voc_index[vocabulary.metadata.field] = vocabulary.to_index_dict()
    index['vocabs'] = voc_index
    print(' Indexing JSON Schemas...')
    json_index = dict()
    for meta_name in JSONSCHEMAS:
        json_schema_path = JSONSCHEMAS_PATH / JSONSCHEMAS[meta_name]
        if os.path.isfile(json_schema_path):
            print('Loading... ' + str(json_schema_path))
            with open(json_schema_path, encoding='utf-8') as json_schema_file:
                json_schema_body = json.load(json_schema_file)
            json_index[meta_name] = json_schema_body
            obj_counter += 1
    index['json_schemas'] = json_index
    from opentide.generation.pydantic_metaschema import build_core_schema_source, build_definition_index, build_platform_schema_source
    from opentide.models.platform_schema import platform_model_for_key
    print(' Indexing Pydantic schema sources...')
    meta_index = dict()
    for meta_name in METASCHEMAS:
        obj_counter += 1
        meta_index[meta_name] = build_core_schema_source(meta_name)
    index['metaschemas'] = meta_index
    print(' Indexing Definitions...')
    definition_index = build_definition_index()
    index['definitions'] = definition_index
    print(' Indexing Templates')
    template_index = dict()
    for cat in TEMPLATES:
        template_path = TEMPLATES_PATH / TEMPLATES[cat]
        if os.path.isfile(template_path):
            with open(template_path, encoding='utf-8') as template_file:
                template = template_file.read()
            template_index[cat] = template
            obj_counter += 1
    print(' Indexing Recomposition Templates')
    print(' Indexing Subschemas')
    subschemas_index = dict()
    for recomp in RECOMPOSITION:
        template_index[recomp] = {}
        subschemas_index[recomp] = {}
        sub_folder = RECOMPOSITION[recomp]
        sub_templates_path = SUBSCHEMAS_PATH / sub_folder / 'Templates'
        recomp_data = index['configurations'][recomp]
        for data in recomp_data:
            obj_counter += 1
            try:
                sub_name = recomp_data[data]['tide']['name']
            except Exception:
                sub_name = recomp_data[data]['platform']['name']
            platform_model = platform_model_for_key(data)
            sub_body = build_platform_schema_source(platform_model)
            subschemas_index[recomp][data] = sub_body
            try:
                with open(sub_templates_path / (sub_name + ' Template.yaml'), encoding='utf-8') as template_file:
                    template_body = template_file.read()
                template_index[recomp][data] = template_body
            except Exception:
                log('FATAL', f'Could not find template for {sub_name} at location {sub_templates_path}', 'This will be skipped as it is expected when creating new subschemas')
    index['templates'] = template_index
    index['subschemas'] = subschemas_index
    print(' Indexing Objects...')
    objects_index = dict()
    files_index = dict()
    objects_index['signal'] = dict()
    for meta_name in METASCHEMAS:
        if meta_name not in SKIPS:
            model_cat_index = dict()
            if not os.path.exists(PATHS[meta_name]):
                log('FAILURE', 'Could not find the folder at the expected location', str(PATHS[meta_name]), 'Ensure that your repository and configuration files are aligned')
                objects_index[meta_name] = {}
                continue
            for model in os.listdir(PATHS[meta_name]):
                if model == '.gitkeep':
                    continue
                model_path = Path(PATHS[meta_name]) / model
                if not os.path.isdir(model_path) and str(model_path).endswith('.yaml'):
                    obj_counter += 1
                    if not model.endswith('.debug.yaml'):
                        with open(model_path, encoding='utf-8') as model_file:
                            model_body = yaml.safe_load(model_file)
                        identifier = model_body.get('uuid') or model_body.get('metadata', {}).get('uuid')
                        if not identifier:
                            log('FATAL', 'Missing identifier from model in file', model)
                        else:
                            model_cat_index[identifier] = model_body
                            files_index[identifier] = model
                            if meta_name == 'objective':
                                signals = model_body.get('objective', {}).get('signals', [])
                                for idx, signal in enumerate(signals or []):
                                    if not signal:
                                        log('FATAL', f'Signal at index {idx} is empty/null in Detection Objective', f'File: {model}', f'Detection Objective UUID: {identifier}', "Ensure all signals in the 'signals' list are properly defined")
                                        raise ValueError(f"Empty signal at index {idx} in Detection Objective '{model}'")
                                    if not signal.get('uuid'):
                                        signal_name = signal.get('name', 'unnamed')
                                        log('FATAL', f"Signal '{signal_name}' is missing a UUID", f'File: {model}', f'Detection Objective UUID: {identifier}', "Every signal must have a unique 'uuid' field")
                                        raise ValueError(f"Signal '{signal_name}' missing UUID in Detection Objective '{model}'")
                                    signal_copy = signal.copy()
                                    signal_copy['parent'] = identifier
                                    objects_index['signal'][signal['uuid']] = signal_copy
            objects_index[meta_name] = model_cat_index
    index['objects'] = objects_index
    index['files'] = files_index
    from opentide.indexing.object_vocab import build_object_vocabularies
    doc_config = RESOLVED_CONFIGURATIONS.get('documentation', {})
    object_vocab_index = build_object_vocabularies(object_scope=CORE_CONFIG.get('objects', []), models_index=objects_index, icons=doc_config.get('icons', {}), object_names=doc_config.get('object_names', {}))
    index['vocabs'].update(object_vocab_index)
    log('INFO', 'Built inline object vocabularies from indexed models', str(len(object_vocab_index)))
    indexes_index: dict[str, object] = {'objects': object_vocab_index}
    if not os.path.exists(IndexPaths.REVISIONS_INDEX_PATH):
        log('SKIP', 'Not able to find a revisions.json index in Tide instance', 'Should be generated in the next Framework generation pipeline run')
    else:
        with open(IndexPaths.REVISIONS_INDEX_PATH, encoding='utf-8') as revisions_file:
            revisions_index = json.load(revisions_file)
        indexes_index['revisions'] = revisions_index
    index['indexes'] = indexes_index
    if write_index or os.getenv('WRITE_INDEX'):
        print(' Exporting Index file to : {} ...'.format(OUTPUT_PATH))
        with open(OUTPUT_PATH, 'w+', encoding='utf-8') as index_file:
            json.dump(index, index_file, default=str)
    return index
if __name__ == '__main__':
    indexer(write_index=True)
