import os
import sys
from pathlib import Path
import yaml
from opentide.core.files import resolve_paths
from opentide.core.root import get_repo_root
import structlog
logger = structlog.get_logger('opentide.mutation.references')
ROOT = get_repo_root()
PATHS = resolve_paths()
MODELS_SCOPE = ['tvm', 'mdr']
MODELS_FOLDER = dict()
for model in MODELS_SCOPE:
    MODELS_FOLDER[model] = PATHS[model]
PRIVATE_DOMAIN = 's.cec.eu.int'
REF_TEMPLATE = '#references:\n  #public:\n    #1: \n  #internal:\n    #a:\n  #restricted:\n    #A:\n'

def upgrade_refs(old_refs):
    new = dict()
    if old_refs:
        public_refs = dict()
        internal_refs = dict()
        internal_refs_list = [ref.strip() for ref in old_refs if PRIVATE_DOMAIN in ref or ('.pdf' in ref and 'https' not in ref)]
        public_refs_list = [ref.strip() for ref in old_refs if ref not in internal_refs_list]
        public_counter = 1
        for pub_ref in public_refs_list:
            public_refs[public_counter] = pub_ref
            public_counter += 1
        internal_counter = 'a'
        for int_ref in internal_refs_list:
            internal_refs[chr(ord(internal_counter))] = int_ref
            internal_counter = chr(ord(internal_counter) + 1)
        if public_refs:
            new['public'] = public_refs
        else:
            new['com_public'] = {'com_1': 'rem'}
        if internal_refs:
            new['internal'] = internal_refs
        else:
            new['com_internal'] = {'com_a': 'rem'}
        new['com_restricted'] = {'com_A': 'rem'}
        new['com_reports'] = ['list']
        new = {'references': new}
        new = yaml.dump(new, sort_keys=False)
        new = new.replace('com_', '#')
        new = new.replace('rem', '')
        new = new.replace('- list', '  #-')
    else:
        new = REF_TEMPLATE
    return new

def run():
    for model_type in MODELS_SCOPE:
        folder = MODELS_FOLDER[model_type]
        if not folder.exists():
            logger.warning('model_folder_configured_but_not_found_skipping', detail=f'{model_type} -> {folder}')
            continue
        logger.info('now_processing_all_files_under_model_type', arg0=model_type)
        for file in sorted(os.listdir(folder)):
            if not file.endswith('.yaml'):
                if not file.endswith('.yml'):
                    logger.info('the_file_doesn_t_end_with_yaml_or_yml_skipping', arg0=file)
                    continue
            raw_body = open(folder / file, 'r', encoding='utf-8').read()
            yaml_body = yaml.safe_load(raw_body)
            current_references = yaml_body.get('references')
            if 'meta' in yaml_body:
                metadata_keyword = 'meta:'
            elif 'metadata' in yaml_body:
                metadata_keyword = 'metadata:'
            if current_references and type(current_references) is not list:
                logger.debug('no_need_to_migrate', arg0=file)
            elif current_references and type(current_references) is not dict or '#public:' not in raw_body.split(metadata_keyword)[0]:
                logger.info('migrating_to_new_references_model', arg0=file)
                header = raw_body.split(metadata_keyword)[0]
                large_block = 'metadata:' + raw_body.split(metadata_keyword)[1]
                if not current_references:
                    new_references = REF_TEMPLATE
                    header = header.split('#references')[0]
                    large_block = '\n' + large_block
                if current_references:
                    new_references = upgrade_refs(current_references)
                    new_references = new_references + '\n'
                    header = header.split('references')[0]
                body = ''
                body = header + new_references + large_block
                output_path = folder / file
                with open(output_path, 'w+', encoding='utf-8') as export:
                    export.write(body)
                    logger.info('migrated_reference_schema_correctly')
    logger.info('ensured_all_files_are_migrated_to_the_new_reference_schema')
if __name__ == '__main__':
    run()
