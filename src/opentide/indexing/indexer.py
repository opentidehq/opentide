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
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.indexing.indexer')

def indexer(write_index=False) -> dict:
    SKIPS = ['ram', 'mdrv2']
    RESOLVED_CONFIGURATIONS = resolve_configurations()
    CORE_CONFIG = RESOLVED_CONFIGURATIONS['global']
    DATA_FIELD = CORE_CONFIG['data_fields']
    RAW_PATHS = CORE_CONFIG['paths']['tide']
    RAW_CORE_PATHS = CORE_CONFIG['paths']['core']
    RAW_PATHS = RAW_CORE_PATHS | RAW_PATHS
    PATHS, CORE_PATHS = resolve_paths(separate=True)
    PATHS = PATHS | CORE_PATHS
    logger.debug('loaded_all_paths')
    VOCABULARIES_PATH = PATHS['vocabularies']
    METASCHEMA_PATH = PATHS['metaschemas']
    METASCHEMAS = CORE_CONFIG['metaschemas']
    JSONSCHEMAS_PATH = PATHS['json_schemas']
    JSONSCHEMAS = CORE_CONFIG['json_schemas']
    SUBSCHEMAS_PATH = PATHS['subschemas']
    DEFINITIONS_PATH = PATHS['definitions']
    RECOMPOSITION = CORE_CONFIG['recomposition']
    TEMPLATES_PATH = PATHS['templates']
    TEMPLATES = CORE_CONFIG['templates']
    INDEX_PATH = PATHS['tide_indexes']

    @dataclass
    class IndexPaths:
        OBJECTS_INDEX_PATH = INDEX_PATH / 'objects.json'
        REVISIONS_INDEX_PATH = INDEX_PATH / 'revisions.json'
    OUTPUT_PATH = PATHS['index_output']
    index = dict()
    obj_counter = 0
    emit_section('Tide Indexer')
    logger.info('seeks_all_tide_related_data_and_stores_it_for_direct_access')
    logger.info('resolving_and_indexing', detail='paths')
    index['paths'] = dict()
    index['paths'].update(PATHS)
    index['paths']['tide'] = PATHS
    index['paths']['core'] = CORE_PATHS
    index['paths']['raw'] = RAW_PATHS
    index['paths']['raw']['tide'] = RAW_PATHS
    index['paths']['raw']['core'] = RAW_CORE_PATHS
    logger.info('resolving_and_index', detail='configurations')
    index['configurations'] = RESOLVED_CONFIGURATIONS
    logger.info('indexing_vocabularies')
    from opentide.generation.vocabulary import VocabularyLoadError, parse_yaml_vocabulary
    voc_index = dict()
    for voc_file in sorted(os.listdir(VOCABULARIES_PATH)):
        if not voc_file.endswith(('.yaml', '.yml')):
            continue
        obj_counter += 1
        voc_path = VOCABULARIES_PATH / voc_file
        try:
            voc_body = yaml.safe_load(open(voc_path, encoding='utf-8'))
        except Exception as exc:
            logger.error('vocabulary_read_failed', file=voc_file, detail=str(exc))
            continue
        if not voc_body:
            logger.warning('could_not_find_data_in_vocabulary_index', arg0=voc_file)
            continue
        try:
            vocabulary = parse_yaml_vocabulary(voc_body, source=voc_file)
        except VocabularyLoadError as exc:
            logger.error('operation_failed', detail=str(exc), arg0=voc_file)
            continue
        voc_index[vocabulary.metadata.field] = vocabulary.to_index_dict()
    index['vocabs'] = voc_index
    logger.info('indexing_json_schemas')
    json_index = dict()
    for meta_name in JSONSCHEMAS:
        json_schema_path = JSONSCHEMAS_PATH / JSONSCHEMAS[meta_name]
        if os.path.isfile(json_schema_path):
            print('Loading... ' + str(json_schema_path))
            json_schema_body = json.load(open(json_schema_path, encoding='utf-8'))
            json_index[meta_name] = json_schema_body
            obj_counter += 1
    index['json_schemas'] = json_index
    logger.info('indexing_metaschemas')
    meta_index = dict()
    for meta_name in METASCHEMAS:
        obj_counter += 1
        meta_body = yaml.safe_load(open(METASCHEMA_PATH / METASCHEMAS[meta_name], encoding='utf-8'))
        meta_index[meta_name] = meta_body
    index['metaschemas'] = meta_index
    logger.info('indexing_definitions')
    definition_index = dict()
    for definition in os.listdir(DEFINITIONS_PATH):
        definition_body = yaml.safe_load(open(DEFINITIONS_PATH / definition, encoding='utf-8'))
        definition_name = definition.split('.')[0]
        definition_index[definition_name] = definition_body
    index['definitions'] = definition_index
    print('📐 Indexing Templates')
    template_index = dict()
    for cat in TEMPLATES:
        template_path = TEMPLATES_PATH / TEMPLATES[cat]
        if os.path.isfile(template_path):
            template = open(template_path, encoding='utf-8').read()
            template_index[cat] = template
            obj_counter += 1
    print('📐 Indexing Recomposition Templates')
    print('🧩 Indexing Subschemas')
    subschemas_index = dict()
    for recomp in RECOMPOSITION:
        template_index[recomp] = {}
        subschemas_index[recomp] = {}
        sub_folder = RECOMPOSITION[recomp]
        subchemas_path = SUBSCHEMAS_PATH / sub_folder
        sub_templates_path = SUBSCHEMAS_PATH / sub_folder / 'Templates'
        recomp_data = index['configurations'][recomp]
        for data in recomp_data:
            obj_counter += 1
            try:
                sub_name = recomp_data[data]['tide']['name']
                subschema_name = recomp_data[data]['tide']['subschema']
            except:
                sub_name = recomp_data[data]['platform']['name']
                subschema_name = recomp_data[data]['platform']['subschema']
            sub_body = yaml.safe_load(open(subchemas_path / (subschema_name + '.yaml'), encoding='utf-8'))
            subschemas_index[recomp][data] = sub_body
            try:
                template_body = open(sub_templates_path / (sub_name + ' Template.yaml'), encoding='utf-8').read()
                template_index[recomp][data] = template_body
            except:
                logger.critical('template_not_found', template=subschema_name, path=subchemas_path, detail='This will be skipped as it is expected when creating new subschemas')
    index['templates'] = template_index
    index['subschemas'] = subschemas_index
    logger.info('indexing_objects')
    objects_index = dict()
    files_index = dict()
    objects_index['signal'] = dict()
    for meta_name in METASCHEMAS:
        if meta_name not in SKIPS:
            model_cat_index = dict()
            if not os.path.exists(PATHS[meta_name]):
                logger.error('could_not_find_the_folder_at_the_expected_location', detail=str(PATHS[meta_name]), advice='Ensure that your repository and configuration files are aligned')
                objects_index[meta_name] = {}
                continue
            for model in os.listdir(PATHS[meta_name]):
                if model == '.gitkeep':
                    continue
                model_path = Path(PATHS[meta_name]) / model
                if not os.path.isdir(model_path) and str(model_path).endswith('.yaml'):
                    obj_counter += 1
                    if not model.endswith('.debug.yaml'):
                        model_body = yaml.safe_load(open(model_path, encoding='utf-8'))
                        identifier = model_body.get('uuid') or model_body.get('metadata', {}).get('uuid')
                        if not identifier:
                            logger.critical('missing_identifier_from_model_in_file', arg0=model)
                        else:
                            model_cat_index[identifier] = model_body
                            files_index[identifier] = model
                            if meta_name == 'dom':
                                signals = model_body.get('objective', {}).get('signals', [])
                                for idx, signal in enumerate(signals or []):
                                    if not signal:
                                        logger.critical('empty_signal', index=idx, detail=f'File: {model}', advice=f'Detection Objective UUID: {identifier}', arg2="Ensure all signals in the 'signals' list are properly defined")
                                        raise ValueError(f"Empty signal at index {idx} in Detection Objective '{model}'")
                                    if not signal.get('uuid'):
                                        signal_name = signal.get('name', 'unnamed')
                                        logger.critical('signal_missing_uuid', signal_name=signal_name, detail=f'File: {model}', advice=f'Detection Objective UUID: {identifier}', arg2="Every signal must have a unique 'uuid' field")
                                        raise ValueError(f"Signal '{signal_name}' missing UUID in Detection Objective '{model}'")
                                    signal_copy = signal.copy()
                                    signal_copy['parent'] = identifier
                                    objects_index['signal'][signal['uuid']] = signal_copy
            objects_index[meta_name] = model_cat_index
    index['objects'] = objects_index
    index['files'] = files_index
    logger.info('retrieving_all_tide_indexes_built_on_the_tide_instance', detail='Injected onto vocabulary index to be retrieved in generation jobs')
    indexes_index = {}
    if not os.path.exists(IndexPaths.OBJECTS_INDEX_PATH):
        logger.info('not_able_to_find_a_objects_json_index_in_tide_instance', detail='Should be generated in the next Framework generation pipeline run')
    else:
        objects_index = json.load(open(IndexPaths.OBJECTS_INDEX_PATH, encoding='utf-8'))
        configured_objects = set(RESOLVED_CONFIGURATIONS['global'].get('objects', []))
        filtered_objects_index = {}
        for object_type, object_vocab in objects_index.items():
            if object_type not in configured_objects:
                logger.info('ignoring_stored_object_index_for_inactive_object_type', arg0=object_type, advice='Regenerate Schemas/Indexes/objects.json to remove stale object families')
                continue
            if not isinstance(object_vocab, dict) or not isinstance(object_vocab.get('metadata'), dict) or (not isinstance(object_vocab.get('entries'), dict)):
                logger.warning('ignoring_malformed_stored_object_index', arg0=object_type, advice='Object indexes must expose both metadata and entries before being used as vocabularies')
                continue
            filtered_objects_index[object_type] = object_vocab
        indexes_index['objects'] = filtered_objects_index
        if filtered_objects_index:
            index['vocabs'].update(filtered_objects_index)
    if not os.path.exists(IndexPaths.REVISIONS_INDEX_PATH):
        logger.info('not_able_to_find_a_revisions_json_index_in_tide_instance', detail='Should be generated in the next Framework generation pipeline run')
    else:
        revisions_index = json.load(open(IndexPaths.REVISIONS_INDEX_PATH, encoding='utf-8'))
        indexes_index['revisions'] = revisions_index
    index['indexes'] = indexes_index
    if write_index or os.getenv('WRITE_INDEX'):
        print('📝 Exporting Index file to : {} ...'.format(OUTPUT_PATH))
        with open(OUTPUT_PATH, 'w+', encoding='utf-8') as index_file:
            json.dump(index, index_file, default=str)
    return index
if __name__ == '__main__':
    indexer(write_index=True)
