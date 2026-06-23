import json
from pathlib import Path
from opentide.core.registry import OpenTide
import structlog
from opentide.core.logging.console import emit_section
logger = structlog.get_logger('opentide.generation.vscode_snippets')
ICONS = OpenTide.Configurations.Documentation.icons
PATHS = OpenTide.Configurations.Global.Paths.Index
SNIPPETS_PATH = OpenTide.Configurations.Global.Paths.Tide.snippet_file
RECOMPOSITION = OpenTide.Configurations.Global.recomposition
SUBSCHEMAS_FOLDER = Path(OpenTide.Configurations.Global.Paths.Core.subschemas)
CONFIG_INDEX = OpenTide.Configurations.Index

def vs_code_snippet_generator(template_path, prefix, blanks=0):
    """
    Generates the body of a snippet by reading the file lines by line, which
    when dumped to json creates an array of strings preserving spaces as per
    vscode requirement.

    Parameters
    ----------
    template_path : path of the template file to convert to vscode snippet
    description : description of the snippet (will be shown to user)
    prefix : keywords that will trigger intellisense

    Returns
    -------
    snippet : snippet body, to be assembled in final snippet json file

    """
    file = open(template_path, 'r')
    buffer = []
    for b in range(0, blanks):
        buffer.append('')
    for line in file:
        buffer.append(line)
    file.close()
    buffer = [word.replace('\n', '') for word in buffer]
    snippet = {}
    snippet['prefix'] = prefix
    snippet['body'] = buffer
    return snippet

def run():
    emit_section('Generate VSCode Snippets')
    logger.info('converts_the_templates_into_vscode_formatted_snippets_inproject')
    snippets = {}
    for model in OpenTide.Configurations.Global.metaschemas:
        if model in (t := OpenTide.Configurations.Global.templates):
            model_icon = ICONS.get(model, '')
            full_name = OpenTide.Configurations.Documentation.object_names[model]
            keyword = f'{model_icon} {full_name} Template'
            template_path = Path(PATHS['templates']) / t[model]
            logger.info('generating_snippets_for', arg0=full_name)
            snippet = vs_code_snippet_generator(template_path, keyword)
            snippets[keyword] = snippet
    for recomp in RECOMPOSITION:
        subschema_type_folder = RECOMPOSITION[recomp]
        subschema_icon = ICONS[recomp]
        for entry in CONFIG_INDEX[recomp]:
            recomp_entry = CONFIG_INDEX[recomp][entry]
            enabled = False
            try:
                if recomp_entry['tide']['enabled'] == True:
                    enabled = True
            except Exception:
                if recomp_entry['platform']['enabled'] == True:
                    enabled = True
            if enabled:
                try:
                    subschema_name = recomp_entry['tide']['name']
                except Exception:
                    subschema_name = recomp_entry['platform']['name']
                logger.info('generating_snippets_for', arg0=subschema_name)
                subchema_template_name = f'{subschema_name} Template.yaml'
                subschema_template_path = SUBSCHEMAS_FOLDER / subschema_type_folder / 'Templates' / subchema_template_name
                keyword = f'{subschema_icon} {subschema_type_folder} : {subschema_name} Template'
                snippet = vs_code_snippet_generator(subschema_template_path, keyword, blanks=1)
                snippets[keyword] = snippet
    output = open(SNIPPETS_PATH, 'w')
    json.dump(snippets, output, indent=4, sort_keys=False, default=str)
    output.close()
if __name__ == '__main__':
    run()
