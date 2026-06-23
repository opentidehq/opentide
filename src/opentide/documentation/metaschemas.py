import os
import sys
import shutil
import time
from pathlib import Path
import pandas as pd
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.documentation.metaschemas')
start_time = time.time()
from opentide.documentation.core import get_icon, name_subschema_doc, DOCUMENTATION_TARGET, TARGET_WITH_DASH_PATHS
from opentide.core.registry import OpenTide
from opentide.deployment import CIEnvironment
from opentide.core.root import get_repo_root
ROOT = get_repo_root()
METASCHEMAS_INDEX = OpenTide.TideSchemas.Index
SUBSCHEMAS_INDEX = OpenTide.TideSchemas.subschemas
TEMPLATES_INDEX = OpenTide.Templates.Index
SCHEMA_DOCS_PATH = Path(OpenTide.Configurations.Global.Paths.Core.schemas_docs_folder)
DOC_TITLES = OpenTide.Configurations.Documentation.titles
ICONS = OpenTide.Configurations.Documentation.icons
columns = ['Field', 'Name', 'Description', 'Type', 'Example']
METASCHEMA_DOC_TEMPLATE = '\n\n> {description}\n\n{table}\n\n### Template\n\n`{template_name}`\n\n```yaml\n{template}\n```\n\n'

def gen_schema_md(metaschema, template, model_type=None):
    """
    Generates the markdown documentation for a given metaschema path

    Parameters
    ----------
    metaschema_path : Body of metaschema yaml file
    template_path : Body of the template corresponding to the metaschema, so
                    it may be appended to the documentation

    Returns
    -------
    schemamarkdown : Markdown formatted representation of the metaschema
    toc : Separate corresponding table of content entry

    """
    title = DOC_TITLES.get(model_type, ' ')
    description = metaschema.get('description', '')
    template_name = ''
    if model_type:
        if model_type == 'mdr':
            template_name = 'MDR Detection Name.yaml'
        else:
            template_name = f'Object Name.yaml'
    table = gen_schema_md_table(metaschema)
    template = template.rstrip()
    documentation = METASCHEMA_DOC_TEMPLATE.format(title=title, description=description, table=table, template=template, template_name=template_name)
    if DOCUMENTATION_TARGET not in [CIEnvironment.CIPlatforms.GitlabCI, CIEnvironment.CIPlatforms.AzurePipeline]:
        if title:
            documentation = f'# {title} \n\n' + documentation
    return documentation

def definition_handler(entry_point):
    return OpenTide.TideSchemas.definitions[entry_point]

def construct_meta_doc_data(metaschema, assembly=[], depth=0):
    recurs = 'Sub' * depth + 'Field'
    for key in metaschema:
        buffer = {}
        if type(metaschema[key]) == dict:
            if 'tide.meta.definition' in metaschema[key]:
                if metaschema[key]['tide.meta.definition'] == True:
                    assembly = construct_meta_doc_data({key: definition_handler(key)}, assembly=assembly, depth=depth)
                else:
                    assembly = construct_meta_doc_data({key: definition_handler(metaschema[key]['tide.meta.definition'])}, assembly=assembly, depth=depth)
            else:
                buffer[recurs] = '`' + key + '`'
                title = metaschema[key].get('title')
                icon = get_icon(key, metaschema=metaschema) or get_icon(key)
                buffer['Name'] = f'{icon} {title}'.strip()
                buffer['Description'] = metaschema[key].get('description', '').replace('\n', ' ')
                buffer['Type'] = metaschema[key].get('type')
                buffer['Example'] = metaschema[key].get('example') or ''
                if 'parameter' in metaschema[key].keys():
                    buffer['Parameter'] = metaschema[key]['parameter']
                assembly.append(buffer)
                if 'properties' in metaschema[key]:
                    assembly = construct_meta_doc_data(metaschema[key]['properties'], assembly=assembly, depth=depth + 1)
                elif 'items' in metaschema[key]:
                    if 'properties' in metaschema[key]['items'].keys():
                        assembly = construct_meta_doc_data(metaschema[key]['items']['properties'], assembly=assembly, depth=depth + 1)
    return assembly

def gen_schema_md_table(metaschema):
    recursion = construct_meta_doc_data(metaschema['properties'], assembly=[])
    df = pd.DataFrame(recursion)
    df.fillna('', inplace=True)
    df.insert(0, 'Name', df.pop('Name'))
    if 'Parameter' in df.keys():
        new_order = ['Description', 'Parameter', 'Type', 'Example']
    else:
        new_order = ['Description', 'Type', 'Example']
    for key in new_order:
        insert = df.pop(key)
        df.insert(len(df.columns), key, insert)
    markdown = df.to_markdown(index=False)
    return markdown

def run():
    emit_section('Schema Documentation')
    logger.info('generates_documentation_for_tide_schemas_and_subschemas')
    if os.path.exists(SCHEMA_DOCS_PATH):
        shutil.rmtree(SCHEMA_DOCS_PATH)
    SCHEMA_DOCS_PATH.mkdir(parents=True)
    for model in METASCHEMAS_INDEX:
        if model in DOC_TITLES.keys():
            icon = ICONS.get(model) or ICONS.get('metaschemas') or ''
            print(f'{icon} Generating documentation for {model.upper()} metaschema')
            meta = METASCHEMAS_INDEX[model]
            template = TEMPLATES_INDEX[model]
            doc = gen_schema_md(meta, template, model)
            output_path = SCHEMA_DOCS_PATH / (icon + ' ' + DOC_TITLES[model] + '.md')
            if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
                output_path = Path(str(output_path).replace(' ', '-'))
            with open(output_path, 'w+', encoding='utf-8') as output:
                output.write(doc)
    for recomp in SUBSCHEMAS_INDEX:
        for sub in SUBSCHEMAS_INDEX[recomp]:
            icon = ICONS.get('subschemas')
            subschema = SUBSCHEMAS_INDEX[recomp][sub]
            sub_template = TEMPLATES_INDEX[recomp].get(sub)
            if sub_template:
                subschema_name = name_subschema_doc(recomp, sub)
                logger.info('generating_sub_schema_documentation', arg0=subschema_name)
                doc = gen_schema_md(subschema, sub_template)
                output_path = SCHEMA_DOCS_PATH / (subschema_name + '.md')
                if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
                    output_path = Path(str(output_path).replace(' ', '-'))
                with open(output_path, 'w+', encoding='utf-8') as output:
                    output.write(doc)
if __name__ == '__main__':
    run()
