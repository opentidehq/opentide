import os
import sys
import json
from typing import Literal
from splunklib import client, results
import traceback
import pandas as pd
from opentide.platforms.splunk.client import connect_splunk, create_query, SplunkConnection
from opentide.platforms.plugins import QueryValidator
from opentide.core.debug import DebugEnvironment
from opentide.core.registry import OpenTide
import structlog
logger = structlog.get_logger('opentide.platforms.splunk.validator')

class SplunkQueryValidator(SplunkConnection, QueryValidator):

    def check_query(self, mdr: dict, service: client.Service):
        mdr_uuid = mdr.get('uuid') or mdr['metadata']['uuid']
        query: str = mdr['configurations'][self.DEPLOYER_IDENTIFIER].get('query')
        if not query:
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
            logger.critical('missing_query_in_mdr', detail=f"{mdr.get('name')} ({mdr_uuid})")
            return
        query = create_query(mdr)
        if not query.startswith('| '):
            query = '| search ' + query
            logger.info('adding_implicit_search_as_could_not_find_starting_command')
        try:
            response = service.parse(query.strip(), enable_lookups=True, output_mode='json', reload_macros=True)
            status = response['status']
            if status == 19:
                if (reason := response.get('reason')):
                    if reason == 'Temporary Redirect':
                        if 'Network Error' in str(response['body'].read()):
                            logger.error('we_encountered_an_unexpected_error_which_has_shown_empirically_t', detail='The query is assumed to be valid, be aware that if deployment fails it may be related to the query')
                            os.environ['VALIDATION_WARNING_RAISED'] = 'True'
                            return
                parsing = response['body'].read()
                parsing = json.loads(parsing)
                logger.debug('parsed_body', arg0=parsing)
                for message in parsing['messages']:
                    logger.critical('fatal_error', detail=f"The SPL query is invalid for : {mdr['name']} ({mdr_uuid})", context_1=message.get('text', ''), advice='Review the error and ensure it can run on the Splunk Search console')
                os.environ['VALIDATION_ERROR_RAISED'] = 'True'
                return
            elif status == 200:
                parsing = response['body'].read()
                parsing = json.loads(parsing)
                logger.info('the_query_is_a_valid_spl_that_can_be_parsed_by_splunk')
                return
            else:
                logger.critical('unexpected_error_code', detail=str(response))
                return
        except Exception as e:
            logger.critical('an_unknown_error_was_found', detail=repr(e))
            traceback.print_exc()
            raise

    def validate(self, deployment: list[str]):
        if not deployment:
            raise Exception('DEPLOYMENT NOT FOUND')
        self.configure_proxy()
        service = connect_splunk(host=self.SPLUNK_URL, port=self.SPLUNK_PORT, token=self.SPLUNK_TOKEN, app=self.SPLUNK_APP, allow_http_errors=True, ssl_enabled=self.SSL_ENABLED)
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.mdr[mdr]
            mdr_uuid = mdr_data.get('uuid') or mdr_data['metadata']['uuid']
            if self.DEPLOYER_IDENTIFIER in mdr_data['configurations'].keys():
                logger.info('validating_spl_query', detail=f"{mdr_data['name']} ({mdr_uuid}")
                self.check_query(mdr_data, service)
            else:
                logger.info('mdr_skipped', mdr_name=mdr_data.get('name'))

def declare():
    return SplunkQueryValidator()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    SplunkQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
