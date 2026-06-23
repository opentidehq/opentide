import pandas as pd
import sys
import json
from typing import Literal, Union, Optional
from opentide.generation.framework import get_type, model_value, get_value_metaschema, get_vocab_entry, strip_vocab_stage_prefix
from opentide.core.registry import OpenTide
from opentide.deployment import CIEnvironment
import structlog
logger = structlog.get_logger('opentide.documentation.core')
TARGET_WITH_DASH_PATHS = [CIEnvironment.CIPlatforms.AzurePipeline, CIEnvironment.CIPlatforms.GitlabCI]
VOCAB_INDEX = OpenTide.Vocabularies.Index
DOCUMENTATION_TARGET = CIEnvironment()._check_ci_environment()
logger.info('identified_ci_environment', detail=str(DOCUMENTATION_TARGET.name))
if DOCUMENTATION_TARGET is CIEnvironment.CIPlatforms.GitlabCI:
    UUID_PERMALINKS = OpenTide.Configurations.Documentation.gitlab.get('uuid_permalinks', False)
    logger.info('enabling_uuid_permalinking_for_gitlab_target')
else:
    logger.info('disabling_uuid_permalinking_for_gitlab_target')
    UUID_PERMALINKS = False
ICONS = OpenTide.Configurations.Documentation.icons
DOCUMENTATION_CONFIG = OpenTide.Configurations.Documentation
CONFIG_INDEX = OpenTide.Configurations.Index
DEFINITIONS_INDEX = OpenTide.TideSchemas.definitions
MODELS_INDEX = OpenTide.Models.Index
FOLD = '\n<details>\n<summary>{}</summary>\n\n{}\n\n</details>\n&nbsp; \n'

class GitlabMarkdown:

    @staticmethod
    def negative_diff(string: str) -> str:
        return f'[- {string} -]'

    @staticmethod
    def positive_diff(string: str) -> str:
        return f'[+ {string} +]'

def sanitize_hover(hover: str) -> str:
    """
    Removes forbidden characters from infobubbles/popovers on
    markdown formatted links
    """
    ALLOWED_CHARACTERS = ['&', '#', ' ', ';', ',', '-', '_']
    return ''.join((ch for ch in hover if ch.isalnum() or ch in ALLOWED_CHARACTERS))

def object_name(key):
    """
    Return a pretty print name for the TIDe object.
    """
    if key == 'Unknown':
        return ''
    name = model_value(key, 'name')
    name = f"  {get_icon(get_type(key)) or ''} {name}"
    return name or key

def make_json_table(dataframe: pd.DataFrame) -> str:
    """
    Converts a dataframe into a searchable and sortable json table,
    rendered in Gitlab.
    """
    df = dataframe
    data = df.to_json(orient='records')
    columns = list(df.columns)
    char = 'a'
    optimized_cols = {}
    for c in columns:
        optimized_cols[c] = char
        char = chr(ord(char) + 1)
    sortable_columns = [{'key': optimized_cols[key], 'label': key, 'sortable': 'true'} for key in columns]
    items = json.loads(data)
    optimized_items = []
    for i in items:
        buffer = {}
        for old_name in i:
            new_name = optimized_cols[old_name]
            buffer[new_name] = i[old_name]
        optimized_items.append(buffer)
    json_data = {'fields': sortable_columns, 'items': optimized_items, 'filter': 'true', 'markdown': 'true', 'sortable': 'true'}
    json_data = json.dumps(json_data, separators=(',', ':'), ensure_ascii=False)
    json_table = f'\n```json:table\n{json_data}\n```\n    '
    return json_table

def get_icon(value, vocab=None, parent_icon=True, metaschema=None, legacy=False) -> str:
    if metaschema:
        meta_icon = get_value_metaschema(value, metaschema, 'icon')
        if meta_icon:
            return str(meta_icon)
        else:
            return ''
    elif value in ICONS:
        return str(ICONS[value])
    elif value in VOCAB_INDEX:
        return VOCAB_INDEX[value].metadata.icon or ''
    elif vocab and vocab in VOCAB_INDEX:
        vocabulary = VOCAB_INDEX[vocab]
        lookup_value = strip_vocab_stage_prefix(vocab, value)
        entry = vocabulary.entries.get(lookup_value)
        if entry and entry.icon:
            return entry.icon
        elif parent_icon is True:
            return vocabulary.metadata.icon or ''
        elif legacy:
            for entry in vocabulary.entries.values():
                if entry.get('legacy') == value:
                    return entry.icon or ''
        else:
            return ''
    else:
        return ''

def make_attack_link(technique: str, fmt: Literal['full', 'compact']='full', hover=True) -> str:
    details = VOCAB_INDEX['att&ck'].entries[technique]
    technique_link = details.link
    if fmt == 'full':
        link_title = technique + ' : ' + details.name
    elif fmt == 'compact':
        link_title = technique
    if hover:
        technique_description = details.description
        technique_link += f" '{sanitize_hover(technique_description)[:150]}'"
    link = f'[{link_title}]({technique_link})'
    return link

def rich_attack_links(techniques: list[str], wrap=20, output: Literal['string', 'list']='string', hover=True) -> str:
    """
    Make an enriched string of attack techniques, with wrapping

    hover: Add an infobubble with the description of the technique, accessible when hovering
    """
    if not techniques:
        return ''
    rich_techniques = str()
    if len(techniques) < wrap:
        techniques = [make_attack_link(x, hover=hover) for x in techniques]
    else:
        techniques = [make_attack_link(x, fmt='compact', hover=hover) for x in techniques]
    if output == 'string':
        rich_techniques = ', '.join(techniques)
    elif output == 'list':
        if len(techniques) > 1:
            rich_techniques = '\n- ' + '\n- '.join(techniques)
    return rich_techniques

def backlink_resolver(model_uuid: str, raw_link: bool=False, raw_hover: bool=False, hover_length: int=150, hover: bool=True, current_page: Optional[str]=None):
    """
    Formats a markdown link to the model, using localized paths.

    raw_link: returns the raw link, without markdown link formatting
    raw_hover: in combination with raw_link, returns a tuple with the cursor hovering content
    hover: when False, omits the title tooltip from the markdown link to reduce output size
    """
    model_type = get_type(model_uuid)
    file_link = backlink_name = icon = str()
    model_data: dict = MODELS_INDEX[model_type][model_uuid]
    icon = ICONS[model_type]
    if model_type == 'signal':
        doc_path = '../' + DOCUMENTATION_CONFIG.object_names['dom'] + '/'
    else:
        doc_path = '../' + DOCUMENTATION_CONFIG.object_names[model_type] + '/'
        hover_content = ''

    def mdr_statuses(mdr_id):
        mdr_configs = MODELS_INDEX['mdr'][mdr_id]['configurations']
        system_statuses = {}
        for system in mdr_configs:
            sys_status = mdr_configs[system]['status']
            sys_status_icon = get_icon(sys_status, 'status')
            system_statuses[system.upper()] = f'{sys_status_icon} {sys_status}'
        return [f'[{s}] : {status}' for s, status in system_statuses.items()]
    if model_type == 'tvm':
        hover_content = model_value(model_uuid, 'description')
    if model_type == 'dom':
        objective_data = OpenTide.Models.DOM[model_uuid]
        hover_content = objective_data.objective.description
    if model_type == 'signal':
        signal_data = OpenTide.Models.Signal[model_uuid]
        objective_data = OpenTide.Models.DOM[signal_data.parent]
        if current_page:
            backlink_name = signal_data.name
            hover_content = signal_data.description
            file_link = f"#{signal_data.name.replace(' ', '-').lower()}"
        else:
            backlink_name = objective_data.name + '::' + signal_data.name
            hover_content = signal_data.description
            file_link = objective_data.name + f"#{signal_data.name.replace(' ', '-').lower()}"
    elif model_type == 'mdr':
        model_name = model_data['name']
        backlink_name = model_name.replace('_', ' ')
        hover_content = '&#013;&#010;'.join(mdr_statuses(model_uuid))
        mdr_description = model_value(model_uuid, 'description') or ''
        mdr_description = mdr_description
        hover_content += f'&#013;&#010;&#013;&#010;{mdr_description}'
        file_link = f'{doc_path}{icon} {model_name}'
    else:
        model_name = model_data['name'].strip()
        backlink_name = model_name
        file_link = f'{doc_path}{icon} {model_name}'
    if DOCUMENTATION_TARGET in TARGET_WITH_DASH_PATHS:
        if UUID_PERMALINKS:
            if model_type == 'signal':
                signal_data = OpenTide.Models.Signal[model_uuid]
                parent_uuid = signal_data.parent
                file_link = doc_path + parent_uuid
            else:
                file_link = doc_path + model_data.get('metadata', {}).get('uuid')
        file_link = file_link.replace(' ', '-').replace('_', '-')
    else:
        file_link = file_link.replace(' ', '%20')
        if not current_page:
            file_link += '.md'
    hover_text = sanitize_hover(str(hover_content))
    if len(hover_text) > hover_length:
        hover_text = hover_text[:hover_length] + '...'
    if hover:
        backlink = f"[{backlink_name}]({file_link} '{hover_text}')"
    else:
        backlink = f'[{backlink_name}]({file_link})'
    if raw_link:
        if raw_hover:
            return (file_link, hover_content)
        return file_link
    return backlink

def get_field_title(field, metaschema, icon=True):
    """
    Retreives the field verbose title from the field key, recursively at any
    depth

    Parameters
    ----------
    field : from which the corresponding title will be retrieved
    metaschema : search space

    Returns
    -------
    title: the title of the field to research.

    """
    if metaschema:
        if field in metaschema.keys():
            title = metaschema[field].get('title')
            if not title:
                if metaschema[field].get('tide.vocab'):
                    if metaschema[field]['tide.vocab'] == True:
                        vocab_name = metaschema[field]['tide.vocab']
                    else:
                        vocab_name = field
                    title = VOCAB_INDEX[vocab_name].metadata.name
                elif (definition := metaschema[field].get('tide.meta.definition')):
                    definition_schema = DEFINITIONS_INDEX[definition]
                    title = definition_schema.get('title', '')
                    if icon is True:
                        title = definition_schema.get('icon', '') + ' ' + title
            if icon is True:
                title_icon = metaschema[field].get('icon') or get_icon(field) or ''
                title = title_icon + ' ' + (title or '_Missing_')
            return title.strip()
        else:
            for key in metaschema.keys():
                if metaschema[key].get('type') in ['object'] and (not metaschema[key].get('patternProperties')):
                    if get_field_title(field, metaschema[key].get('properties'), icon=icon):
                        return get_field_title(field, metaschema[key].get('properties'), icon=icon)
                elif (metadef := metaschema[key].get('tide.meta.definition')):
                    if metadef is True:
                        definition = DEFINITIONS_INDEX[key]
                    else:
                        definition = DEFINITIONS_INDEX[metadef]
                    if field == key:
                        return definition['title'].strip()
                    elif get_field_title(field, definition.get('properties'), icon=icon):
                        return get_field_title(field, definition.get('properties'), icon=icon)

def get_vocab_description(vocab, key):
    description = get_vocab_entry(vocab, key, 'description')
    description = description.replace('\n', ' ')
    return description

def make_vocab_link(field, key):
    if field not in VOCAB_INDEX:
        return key
    lookup_key = strip_vocab_stage_prefix(field, key)
    entry = VOCAB_INDEX[field].entries.get(lookup_key)
    vocab_reference = VOCAB_INDEX[field].metadata.get('reference')
    key = (get_icon(key, vocab=field, parent_icon=False) or '') + ' ' + key
    if entry is None:
        return f'`{key}`'
    if entry.link:
        link = '[`' + key + '`]' + '(' + entry.link + ')'
    elif vocab_reference is not None:
        link = '[`' + key + '`]' + '(' + vocab_reference.split(',')[0] + ')'
    else:
        link = f'`{key}`'
    return link

def model_value_doc(model_id, key, with_icon=False, max_chars=None, legacy=False):
    """
    Version of model_value() that add icon and data enrichment functions
    """
    from opentide.generation.framework import get_type, model_value
    value = model_value(model_id, key)
    if value:
        if with_icon:
            if type(value) is list:
                value = [f'{get_icon(v, vocab=key, parent_icon=False, legacy=legacy)} {v}'.strip() for v in value]
            elif type(value) is str:
                value_icon = get_icon(value, vocab=key, parent_icon=False, legacy=legacy)
                value = f'{value_icon} {value}'.strip()
                if max_chars:
                    if len(value) > max_chars:
                        value = value[:max_chars] + '...'
    return value

def name_subschema_doc(recomposition: str, identifier: str, with_icon: bool=True) -> str:
    SUFFIX = ' Schema'
    subschema_name = str()
    composition_name = str()
    recomp_config = CONFIG_INDEX[recomposition][identifier]
    try:
        composition_name = recomp_config['tide'].get('name')
    except:
        composition_name = recomp_config['platform'].get('name')
    if composition_name:
        subschema_name = recomposition.title() + ' - ' + composition_name + SUFFIX
    else:
        logger.info('event', detail=f'There is no name assigned to {identifier}', context_1='A name is strongly recommended for most documentation functions', advice="Ensure to add a name to 'config.yaml'")
        subschema_name = identifier.replace('_', ' ').title() + SUFFIX
    if with_icon:
        subschema_name = str(ICONS.get('subschemas')) + ' ' + subschema_name
    return subschema_name
