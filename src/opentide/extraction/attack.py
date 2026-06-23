import pandas as pd
import yaml
import os
import sys
from pathlib import Path
from opentide.core.files import IndentFullDumper
from opentide.core.registry import OpenTide
RESOURCES_PATH = Path(OpenTide.Configurations.Global.Paths.Index['resources'])
ATTACK_RESOURCES = OpenTide.Configurations.Resources.attack
enterprise = RESOURCES_PATH / ATTACK_RESOURCES['enterprise']
mobile = RESOURCES_PATH / ATTACK_RESOURCES['mobile']
ics = RESOURCES_PATH / ATTACK_RESOURCES['ics']
vocab_folder = Path(OpenTide.Configurations.Global.Paths.Core.vocabularies)
techniques_vocab = 'ATT&CK Techniques.yaml'
datasources_vocab = 'ATT&CK Data Sources.yaml'
mitigations_vocab = 'ATT&CK Mitigations.yaml'
groups_vocab = vocab_folder / 'ATT&CK Groups.yaml'

def gen_techniques_vocab(attack_table, out_file, prefix=None):
    if prefix is None:
        prefix = ''
    else:
        prefix += ' : '
    df = pd.read_excel(attack_table, sheet_name='techniques')
    df = df[['ID', 'name', 'tactics', 'description', 'url']]
    df = df.rename(columns={'ID': 'id', 'tactics': 'tide.vocab.stages', 'url': 'link'})
    keys = df.to_dict('records')
    for p in keys:
        print(p)
        p['name'] = prefix + p['name']
        p['tide.vocab.stages'] = [tac.replace('Ics', '').strip() if tac != 'Evasion Ics' else 'Defense Evasion' for tac in p['tide.vocab.stages'].split(', ')]
    out_file_body = yaml.safe_load(open(out_file, encoding='utf-8'))
    out_file_body['keys'].extend(keys)
    output = open(out_file, 'w', encoding='utf-8')
    yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
    output.close()

def gen_datasources_vocab(attack_table, out_file):
    df = pd.read_excel(attack_table, sheet_name='datasources')
    df = df[['ID', 'name', 'description', 'url']]
    df = df.rename(columns={'ID': 'id', 'url': 'link'})
    "\n    for col in ['id', 'link']:\n        df[col] = df[col].ffill()\n    "
    keys = df.to_dict('records')
    reference = keys.copy()
    for item in keys:
        if type(item['id']) != str:
            suffix = item['name'].split(':')[1].lstrip()
            prefix = item['name'].split(':')[0].rstrip()
            print(prefix)
            link = item['link']
            for internal in reference:
                if internal['name'] == prefix:
                    item['id'] = internal['id']
                    item['name'] = suffix
                    item['link'] = internal['link']
    out_file_body = yaml.safe_load(open(out_file, encoding='utf-8'))
    out_file_body['keys'].extend(keys)
    output = open(out_file, 'w', encoding='utf-8')
    yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
    output.close()

def gen_mitigations_vocab(attack_table, out_file, prefix=None):
    if prefix is None:
        prefix = ''
    else:
        prefix += ' : '
    df = pd.read_excel(attack_table, sheet_name='mitigations')
    df = df[['ID', 'name', 'description', 'url']]
    df = df.rename(columns={'ID': 'id', 'url': 'link'})
    keys = df.to_dict('records')
    for p in keys:
        p['name'] = prefix + p['name']
    out_file_body = yaml.safe_load(open(out_file, encoding='utf-8'))
    out_file_body['keys'].extend(keys)
    output = open(out_file, 'w', encoding='utf-8')
    yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
    output.close()
out_file_body = yaml.safe_load(open(vocab_folder / techniques_vocab, encoding='utf-8'))
out_file_body['keys'].clear()
output = open(vocab_folder / techniques_vocab, 'w', encoding='utf-8')
yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
output.close()
gen_techniques_vocab(enterprise, os.path.join(vocab_folder, techniques_vocab))
gen_techniques_vocab(mobile, os.path.join(vocab_folder, techniques_vocab), prefix='Mobile')
gen_techniques_vocab(ics, os.path.join(vocab_folder, techniques_vocab), prefix='Industrial')
out_file_body = yaml.safe_load(open(vocab_folder / datasources_vocab))
out_file_body['keys'].clear()
output = open(vocab_folder / datasources_vocab, 'w', encoding='utf-8')
yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
output.close()
gen_datasources_vocab(enterprise, os.path.join(vocab_folder, datasources_vocab))
out_file_body = yaml.safe_load(open(vocab_folder / mitigations_vocab, encoding='utf-8'))
out_file_body['keys'].clear()
output = open(vocab_folder / mitigations_vocab, 'w', encoding='utf-8')
yaml.dump(out_file_body, output, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
output.close()
gen_mitigations_vocab(enterprise, os.path.join(vocab_folder, mitigations_vocab))
gen_mitigations_vocab(mobile, os.path.join(vocab_folder, mitigations_vocab), prefix='Mobile')
gen_mitigations_vocab(ics, os.path.join(vocab_folder, mitigations_vocab), prefix='Industrial')
gen_mitigations_vocab(mobile, os.path.join(vocab_folder, mitigations_vocab), prefix='Mobile')
gen_mitigations_vocab(ics, os.path.join(vocab_folder, mitigations_vocab), prefix='Industrial')
