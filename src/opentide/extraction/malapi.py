import requests
from bs4 import BeautifulSoup
import pandas as pd
import yaml
from pathlib import Path
import os
import sys
from datetime import datetime
from opentide.core.files import IndentFullDumper
from opentide.core.registry import OpenTide
import structlog
logger = structlog.get_logger('opentide.extraction.malapi')
DEBUG = False
VOCAB_FILE_PATH = Path(OpenTide.Configurations.Global.Paths.Core.vocabularies) / "malapi.vocab.toml"
API_DETAILS_FIELD_MAPPING = {'Function Name': 'name', 'Description': 'description', 'Library': 'library', 'Associated Attacks': 'tide.vocab.stages', 'Documentation': 'link'}
STAGE_ICON_MAPPING = {key: '' for key in ('Enumeration', 'Injection', 'Evasion', 'Spying', 'Internet', 'Anti-Debugging', 'Ransomware', 'Helper')}
MALAPI_URL = 'https://malapi.io'
start_time = datetime.now()

def fetch_win_api_details(api):
    logger.info('fetching_api_details', arg0=api)
    url = MALAPI_URL + '/winapi/' + api
    try:
        page = requests.get(url)
        soup = BeautifulSoup(page.text, 'html.parser')
    except Exception as e:
        logger.error('failed_to_retrieve_details_for', arg0=api)
        raise e
    details = {}
    details_page = soup.find_all('div', {'class': 'detail-container'})
    for detail in details_page:
        detail_name = detail.find('div', attrs={'class': 'heading'})
        detail_data = detail.find('div', attrs={'class': 'content'})
        if detail_name:
            detail_name = detail_name.text.strip()
            detail_name = API_DETAILS_FIELD_MAPPING[detail_name]
            if detail_data:
                detail_data = detail_data.text.strip()
                details[detail_name] = detail_data
    if details.get('library'):
        details['description'] += f"\nLibrary : `{details.pop('library')}`"
    if details.get('stage'):
        stage_data = details.pop('tide.vocab.stages')
        stage_data = stage_data.replace('\n\n', ',')
        stage_data = stage_data.replace('\n', '').replace(' ', '')
        if ',' in stage_data:
            stage_data = stage_data.split(',')
        details['stage'] = stage_data
    if not details:
        logger.error('error_in_parsing_no_data_returned', arg0=api)
        raise ValueError('Empty parsed API')
    if DEBUG:
        logger.debug('event', detail=str(details))
    return details
logger.info('fetching_malapi_attacks_category_details')
attacks = list()
page = requests.get(MALAPI_URL)
soup = BeautifulSoup(page.text, 'lxml')
table = soup.find('table', id='main-table')
for i in table.find_all('th'):
    title = i.text.strip()
    description = i.find('img')['title'].strip()
    entry = dict()
    entry['name'] = title
    entry['icon'] = STAGE_ICON_MAPPING[title]
    entry['description'] = description
    attacks.append(entry)
attacks_list = [a['name'] for a in attacks]
logger.info('retrieved_all_attacks_detailed', detail=', '.join(attacks_list))
rows = list()
api_list = list()
for j in table.find_all('tr')[1:]:
    row_data = j.find_all('tbody')
    for row in row_data:
        row_values = []
        a_class = row.find_all('a')
        for a in a_class:
            row_values.append(a.text.strip())
        if row_values:
            rows.append(row_values)
            api_list.extend(row_values)
df = pd.DataFrame(data=rows).transpose()
df.columns = list(attacks_list)
api_list = list(set(api_list))
malapi_content = list()
logger.info('fetching_all_api_details')
for api in sorted(api_list):
    malapi_content.append(fetch_win_api_details(api))
time_elapsed = datetime.now() - start_time
time_elapsed = '%.2f' % time_elapsed.total_seconds()
logger.info('successfully_retrieved', detail=f'{len(malapi_content)} APIs', advice=f'in {time_elapsed} seconds')
vocab_content = {'name': 'Malicious Window API', 'field': 'malapi', 'description': 'MalAPI.io maps Windows APIs to common techniques used by malware.', 'reference': MALAPI_URL, 'icon': '', 'stages': attacks, 'keys': malapi_content}
logger.info('writing_to_file_at_location', detail=str(VOCAB_FILE_PATH))
with open(VOCAB_FILE_PATH, encoding='utf-8', mode='w+') as vocab:
    yaml.dump(vocab_content, vocab, sort_keys=False, allow_unicode=True, Dumper=IndentFullDumper)
logger.info('wrote_to_vocabulary_file')
