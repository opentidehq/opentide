import pandas as pd
import yaml
import os
import sys
from pathlib import Path
import unicodedata
from opentide.core.files import IndentFullDumper
from opentide.core.registry import OpenTide
RESOURCES = OpenTide.Configurations.Global.Paths.Core.resources
NIST_DATA = OpenTide.Configurations.Resources.nist['data']
VOCABS_PATH = OpenTide.Configurations.Global.Paths.Core.vocabularies
nist_vocab = 'NIST Cybersecurity Framework.yaml'
df = pd.read_excel(RESOURCES / NIST_DATA)
df = df.drop_duplicates(subset=['Subcategory'])
df = df.fillna(method='ffill')
keys = df.to_dict('records')
out = []
for k in keys:
    buf = {}
    buf['id'] = str(k['Subcategory']).split(':')[0].rstrip()
    buf['name'] = str(k['Subcategory']).split(':')[1].lstrip()
    buf['description'] = 'Category : ' + k['Category'].replace('’', "'")
    buf['stage'] = k['Function'].capitalize().split(' (')[0]
    out.append(buf)
out_file_body = yaml.safe_load(open(VOCABS_PATH / nist_vocab, encoding='utf-8'))
out_file_body['keys'] = out
output = open(VOCABS_PATH / nist_vocab, 'w', encoding='utf-8')
yaml.dump(out_file_body, output, sort_keys=False, Dumper=IndentFullDumper)
output.close()
