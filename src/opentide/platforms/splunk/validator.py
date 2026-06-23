import os
import json
from splunklib import client
import traceback
from opentide.platforms.splunk.client import connect_splunk, create_query, SplunkConnection
from opentide.platforms.plugins import QueryValidator
from opentide.core.logging import log
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide

class SplunkQueryValidator(SplunkConnection, QueryValidator):

    def check_query(self, mdr: dict, service: client.Service):
        mdr_uuid = mdr.get('uuid') or mdr['metadata']['uuid']
        query: str = mdr['configurations'][self.DEPLOYER_IDENTIFIER].get('query')
        if not query:
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
            log('FATAL', 'Missing query in MDR', f"{mdr.get('name')} ({mdr_uuid})")
            return
        query = create_query(mdr)
        if not query.startswith('| '):
            query = '| search ' + query
            log('INFO', 'Adding implicit `| search` as could not find starting command')
        try:
            response = service.parse(query.strip(), enable_lookups=True, output_mode='json', reload_macros=True)
            status = response['status']
            if status == 19:
                if (reason := response.get('reason')):
                    if reason == 'Temporary Redirect':
                        if 'Network Error' in str(response['body'].read()):
                            log('FAILURE', 'We encountered an unexpected error, which has shown empirically to be related to time-out', 'The query is assumed to be valid, be aware that if deployment fails it may be related to the query')
                            os.environ['VALIDATION_WARNING_RAISED'] = 'True'
                            return
                parsing = response['body'].read()
                parsing = json.loads(parsing)
                log('DEBUG', 'Parsed Body', parsing)
                for message in parsing['messages']:
                    log('FATAL', f"The SPL query is invalid for : {mdr['name']} ({mdr_uuid})", message.get('text', ''), 'Review the error and ensure it can run on the Splunk Search console')
                os.environ['VALIDATION_ERROR_RAISED'] = 'True'
                return
            elif status == 200:
                log('SUCCESS', 'The query is a valid SPL that can be parsed by Splunk')
                return
            else:
                log('FATAL', 'Unexpected Error Code', str(response))
                return
        except Exception as e:
            log('FATAL', 'An unknown error was found', repr(e))
            traceback.print_exc()
            raise

    def validate(self, deployment: list[str], deployment_plan=None):
        if not deployment:
            raise Exception('DEPLOYMENT NOT FOUND')
        self.configure_proxy()
        service = connect_splunk(host=self.SPLUNK_URL, port=self.SPLUNK_PORT, token=self.SPLUNK_TOKEN, app=self.SPLUNK_APP, allow_http_errors=True, ssl_enabled=self.SSL_ENABLED)
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.rules[mdr]
            mdr_uuid = mdr_data.get('uuid') or mdr_data['metadata']['uuid']
            if self.DEPLOYER_IDENTIFIER in mdr_data['configurations'].keys():
                log('ONGOING', 'Validating SPL Query', f"{mdr_data['name']} ({mdr_uuid}")
                self.check_query(mdr_data, service)
            else:
                log('SKIP', f" Skipping {mdr_data.get('name')} as does not contain a Splunk configuration section")

def declare():
    return SplunkQueryValidator()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    SplunkQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
