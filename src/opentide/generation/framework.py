from typing import Any, Literal, Tuple, overload
from opentide.core.registry import OpenTide
from opentide.core.logging import log
DEFINITIONS_INDEX: dict[str, Any] = {}
VOCAB_INDEX = OpenTide.Vocabularies.Index
MODELS_INDEX = OpenTide.Models.Index
CHAINING_INDEX = OpenTide.Models.chaining

def unroll_dot_dict(dot_dict, separator='.'):
    """
    Processes a dot (or other arbitrary symbol) separated dictionary into a nested dictionary
    Useful for turning nested params into a data structure that
    can be merged into another config dictionary.
    """
    if len(dot_dict.keys()) > 1:
        print(f' Cannot process dictionary {str(dot_dict)}, expecting a single item dictionary')
        return None
    (long_key, value), = dot_dict.items()
    nested_keys = long_key.split(separator)
    nested_keys.reverse()
    unrolled = dict()
    for key in nested_keys:
        current_index = nested_keys.index(key)
        if current_index == 0:
            unrolled[key] = value
        else:
            copy_dict = unrolled.copy()
            unrolled = {}
            unrolled[key] = copy_dict.copy()
    return unrolled

def key_value_transform(kv_store_list: list) -> dict:
    kv_store = dict()
    for elem in kv_store_list:
        kv_store[elem['key']] = elem['value']
    return kv_store

def rename_param_nest(nest, schema, scope=None):
    from opentide.generation.pydantic_metaschema import lookup_schema_extra
    nest_copy = nest.copy()
    for item in nest_copy:
        parameter_name = lookup_schema_extra(schema, item, 'tide.mdr.parameter', scope=scope)
        temp = nest[item]
        nest.pop(item)
        nest[parameter_name] = temp
        if type(nest_copy[item]) == list:
            if lookup_schema_extra(schema, item, 'key_value_store'):
                nest[parameter_name] = key_value_transform(nest_copy[item])
            else:
                for elem in nest_copy[item]:
                    rename_param_nest(elem, schema, scope=item)
        elif type(nest_copy[item]) == dict:
            rename_param_nest(nest[parameter_name], schema, scope=item)
    return nest

def deep_update(dictionary, key, new_value):
    """
    Walks a nested dictionary at all depth until it meets key, then updates with new_value
    Note that the dictionary must contain the expected key at some depth, else
    will return None.
    """
    dict_copy = dictionary.copy()
    if key in dict_copy.keys():
        dictionary[key] = new_value
    else:
        for k in dict_copy:
            if type(dict_copy[k]) == dict:
                deep_update(dictionary[k], key, new_value)
    return dictionary

def vocab_metadata(vocab: str, field=None) -> str | dict:
    """
    Returns the metadata (description, links, icon etc.) for a given vocabulary.
    If field is set to None returns the entire metadata
    """
    if vocab not in VOCAB_INDEX:
        return ''
    metadata = VOCAB_INDEX[vocab].metadata
    if field:
        value = metadata.get(field)
        if value in (None, ''):
            log('FAILURE', f'{field} does not exist in vocab', vocab)
            return ''
        return value
    return metadata.to_dict()

def get_vocab_stage_details(vocabulary: str, stage_identifier: str) -> None | Tuple[str, str]:
    """
    Return a tuple of the name and description for a particular stage of a vocabulary.
    If no stage correspond, or the vocabulary has no stages, returns nothing.
    """
    if vocabulary not in VOCAB_INDEX:
        log('FAILURE', 'The requested vocabulary does not exist in the index space', vocabulary)
        return None
    stages_section = VOCAB_INDEX[vocabulary].metadata.get('stages')
    if not stages_section:
        log('FAILURE', 'The requested vocabulary does not contain a stage section', vocabulary)
        return None
    for stage in stages_section:
        if stage.get('id') == stage_identifier:
            log('INFO', f'Found corresponding stage in the requested vocabulary {vocabulary}', stage_identifier, str(stage))
            return (stage.get('name'), stage.get('description'))
    return None

def strip_vocab_stage_prefix(vocab: str, identifier: str) -> str:
    """Strip a leading stage prefix from a vocabulary identifier.

    Staged vocabularies (e.g. *surface*) store entries without the stage
    prefix in VOCAB_INDEX, but callers may supply stage-prefixed values
    such as ``OS::Windows::Desktop``.  This helper returns the key as it
    appears in the index (``Windows::Desktop``).
    """
    if '::' in identifier and vocab in VOCAB_INDEX:
        stages = VOCAB_INDEX[vocab].metadata.get('stages') or []
        stage_ids = {s['id'] for s in stages if 'id' in s}
        first_segment = identifier.split('::')[0]
        if first_segment in stage_ids:
            return identifier.split('::', 1)[1]
    return identifier

def get_vocab_entry(vocab, identifier, field=None, newlines=False):
    """
    Returns data for a particular entry of a voacbulary.
    Supports two modes : if field is None, will return all data from
    the entry as a dict, else will fetch the data for the given
    identifier.
    """
    if vocab not in VOCAB_INDEX:
        return ''
    identifier = strip_vocab_stage_prefix(vocab, identifier)
    vocabulary = VOCAB_INDEX[vocab]
    if identifier in vocabulary.entries:
        entry = vocabulary.entries[identifier]
        if field is None:
            return entry.as_dict()
        value = entry.get(field)
        if value in (None, ''):
            print(f' Could not retrieve parameter [ {field} ] for entry with identifier [ {identifier} ] from vocabulary data of : {vocab}')
            return ''
        if newlines is False and isinstance(value, str):
            return value.replace('\n', '')
        return value
    for entry_key, entry in vocabulary.entries.items():
        if entry.get('legacy') == identifier:
            if field is None:
                return entry.as_dict()
            value = entry.get(field)
            if value in (None, ''):
                return ''
            if newlines is False and isinstance(value, str):
                return value.replace('\n', '')
            return value
    print(f' Could not retrieve identifier [ {identifier} ] from vocabulary data of : {vocab}')
    return ''

def get_key_in_model_body(model_body, key):
    """
    Self-recursive function to return the value of a key nested within
    the body of a model data.
    """
    if key in model_body.keys():
        return model_body[key]
    else:
        for model_key in model_body.keys():
            if type(model_body[model_key]) is dict:
                if get_key_in_model_body(model_body[model_key], key) is not None:
                    return get_key_in_model_body(model_body[model_key], key)
    return None

def model_value(id, key):
    model_type = get_type(id)
    if not MODELS_INDEX.get(model_type):
        log('FAILURE', 'Could not find object index', model_type)
        return None
    data = MODELS_INDEX[model_type][id]
    value = get_key_in_model_body(data, key)
    return value

def parents(id: str) -> list:
    """
    Returns the list of parents for any given CoreTIDE Object.
    If the Object does not have possible parent relationships,
    or in other word is a top-level Object, returns an empty string.
    """
    model_type = get_type(id)
    parents = []
    parent_mappings = {'objective': {'data': 'objective', 'parent': 'threats'}, 'signal': {'parent': 'parent'}, 'rule': {'parent': 'detection_model'}}
    if model_type not in parent_mappings:
        return []
    if not MODELS_INDEX.get(model_type):
        return []
    model_data = MODELS_INDEX[model_type][id]
    parent_loc = parent_mappings[model_type]
    if 'data' in parent_loc:
        parents = model_data[parent_loc['data']].get(parent_loc['parent']) or []
    else:
        parents = model_data.get(parent_loc['parent']) or []
    if type(parents) is str:
        parents = [parents]
    return parents

def childs(model_id: str) -> list:
    """
    Returns the list of direct descendants for any given OpenTide Object,
    by performing a forward search.

    If the object can not have descendants, or in other word is a last-line
    Object (such as MDRs), will return an empty list
    """
    implementations = []
    mappings = {'threat': {'child_types': ['objective'], 'data_sections': ['detection', 'objective'], 'references': ['vectors', 'threats']}, 'objective': {'child_types': ['signal', 'rule'], 'references': ['detection_model', 'parent']}, 'signal': {'child_types': ['rule'], 'references': ['detection_model']}}
    model_type = get_type(model_id)
    if model_type not in mappings.keys():
        return []
    child_types = mappings[model_type]['child_types']
    child_types = [child_types] if type(child_types) is str else child_types
    data_sections = mappings[model_type].get('data_sections', None)
    references = mappings[model_type]['references']
    for child_type in child_types:
        CHILDS_INDEX = MODELS_INDEX.get(child_type, {})
        for child in CHILDS_INDEX:
            if data_sections:
                for section in data_sections:
                    for reference in references:
                        if model_id in CHILDS_INDEX[child].get(section, {}).get(reference, []):
                            implementations.append(child)
            else:
                for reference in references:
                    if model_id in CHILDS_INDEX[child].get(reference, []):
                        implementations.append(child)
    return implementations

@overload
def get_type(model_uuid: str) -> str:
    pass


@overload
def get_type(model_uuid: str, mute: Literal[True]) -> str | None:
    pass


@overload
def get_type(model_uuid: str, mute: Literal[False]) -> str:
    pass

def get_type(model_uuid: str, mute: bool=False):
    """
    Return the model type based on the schema identifier format.
    """
    model_body = OpenTide.Models.FlatIndex.get(model_uuid, {})
    if not model_body:
        if mute:
            return None
        else:
            log('FATAL', 'UUID does not exist in the index of Tide Objects', model_uuid)
            raise Exception
    schema = model_body.get('metadata', {}).get('schema')
    if not schema:
        if model_uuid in OpenTide.Models.signals:
            return 'signal'
        if model_body.get('configurations'):
            return 'rule'
        if mute:
            return None
        else:
            log('FATAL', 'Missing schema identifier in object', model_body.get('name', 'NAME NOT FOUND'))
            raise Exception
    return schema.split('::')[0]

def keep_active_rules(rule_list: list[str]) -> list[str]:
    """
    Given a list of MDRs, only keep the ones considered Active,
    which mean none of the system they configure are set with a
    Deprecated status.
    """
    from opentide.deployment import check_status, DEPRECATED_STATUSES
    active_rules = []
    for mdr in rule_list:
        try:
            mdr_data = OpenTide.Models.Index['rule'][mdr]
        except Exception:
            log('FAILURE', 'Could not retrieve UUID in MDR Index', mdr)
            continue
        deprecated = False
        for system in mdr_data['configurations']:
            system_data = mdr_data['configurations'][system]
            if check_status(system_data['status']) in DEPRECATED_STATUSES:
                log('INFO', 'Skipping MDR as is in a deprecated status', mdr)
                deprecated = True
        if deprecated is False:
            active_rules.append(mdr)
    return active_rules

def techniques_resolver(model_id: str, recursive=True) -> list:
    """
    Returns the relevant technique for any object, based on its own
    and its parent properties. WARNING : only works when index is loaded
    in memory.

    Returns
    -------
    techniques: List of resolved techniques.
    """
    techniques = []
    model_type = get_type(model_id)
    if not MODELS_INDEX.get(model_type):
        log('FAILURE', 'Could not find object index', model_type)
        return []
    model_body = MODELS_INDEX[model_type][model_id]
    if model_type == 'rule':
        parent_id = model_body.get('detection_model') or model_body.get('tags', {}).get('coretide')
        if not parent_id:
            return []
        elif recursive:
            techniques.extend(techniques_resolver(parent_id))
        else:
            return techniques
    if model_type == 'objective':
        if 'att&ck' in model_body['objective']:
            techniques = model_body['objective']['att&ck']
        else:
            parent_ids = model_body['objective'].get('threats')
            if recursive:
                if parent_ids:
                    for parent_id in parent_ids:
                        techniques.extend(techniques_resolver(parent_id))
            else:
                return techniques
    if model_type == 'threat':
        techniques = model_body['threat']['att&ck']
    techniques = list(dict.fromkeys(techniques))
    return techniques

def relations_downstream(id):
    tree = {}
    if get_type(id) in ['signal']:
        tree = keep_active_rules(childs(id))
    elif get_type(id) == 'objective':
        for child in childs(id):
            if get_type(child) == 'signal':
                tree[child] = relations_downstream(child)
            elif get_type(child) == 'rule':
                tree[child] = None
    else:
        for c in childs(id):
            tree[c] = relations_downstream(c)
    return tree

def relations_upstream(id):
    tree = {}
    if get_type(id) == 'threat':
        tree = []
    else:
        for p in parents(id):
            tree[p] = relations_upstream(p)
    return tree

def relations_list(id, mode: Literal['count', 'flat']='flat', direction: Literal['upstream', 'downstream', 'both']='downstream'):
    flat = {}
    if direction == 'upstream':
        relations = relations_upstream(id)
    elif direction == 'downstream':
        relations = relations_downstream(id)
    elif direction == 'both':
        merged = relations_list(id, mode, direction='downstream')
        merged.update(relations_list(id, mode, 'upstream'))
        return merged

    def recursive_items(dictionary):
        for key, value in dictionary.items():
            if type(value) is dict:
                yield (key, value)
                yield from recursive_items(value)
            else:
                yield (key, value)
    if relations and type(relations) is list:
        flat[get_type(relations[0])] = relations
    if type(relations) is dict:
        for k, v in recursive_items(relations):
            if k:
                if type(k) is list:
                    k_type = get_type(k[0])
                    flat.setdefault(k_type, [])
                    flat[k_type].extend(k)
                if type(k) is str:
                    k_type = get_type(k)
                    flat.setdefault(k_type, [])
                    flat[k_type].append(k)
            if v:
                if type(v) is list:
                    v_type = get_type(v[0])
                    flat.setdefault(v_type, [])
                    flat[v_type].extend(v)
                if type(v) is str:
                    v_type = get_type(v)
                    flat.setdefault(v_type, [])
                    flat[v_type].append(v)
    for k, v in flat.items():
        flat[k] = list(set(v))
    if (rule_list := flat.get('rule')):
        active_rules = keep_active_rules(rule_list)
        flat['rule'] = active_rules
    if mode == 'count':
        for k, v in flat.items():
            flat[k] = len(v)
    return flat

def chain_resolver(entry_point: str, chain: dict | None = None) -> dict:
    """
    Search all chaining nodes and relations links
    of a given tvm to the n node, and recursively search for all returned value
    to reconstruct the full chain.
    """
    if chain is None:
        chain = {}
    vector_chaining = CHAINING_INDEX.get(entry_point)
    if vector_chaining:
        for link in vector_chaining:
            if entry_point not in chain:
                chain[entry_point] = dict()
            if link not in chain[entry_point]:
                chain[entry_point][link] = []
            for v in vector_chaining[link]:
                if v not in chain[entry_point][link]:
                    chain[entry_point][link].append(v)
                    chain = chain_resolver(v, chain)
    return chain
