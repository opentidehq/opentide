import os
import sys
from cbc_sdk.rest_api import CBCloudAPI
from opentide.core.debug import DebugEnvironment
from opentide.platforms.plugins import QueryValidator
from opentide.core.registry import OpenTide
from opentide.platforms.carbon_black.client import CarbonBlackCloudConnection
import structlog
logger = structlog.get_logger('opentide.platforms.carbon_black.validator')

class CarbonBlackCloudQueryValidator(CarbonBlackCloudConnection, QueryValidator):

    def check_query(self, mdr: dict, service: CBCloudAPI):
        query: str = mdr['configurations']['carbon_black_cloud'].get('query')
        mdr_uuid = mdr.get('uuid') or mdr['metadata']['uuid']
        if not query:
            os.environ['VALIDATION_ERROR_RAISED'] = 'True'
            logger.critical('missing_query_in_mdr', detail=f"{mdr.get('name')} ({mdr_uuid})")
            return
        try:
            result = service.validate_process_query(query)
            if result:
                logger.info('the_query_is_a_valid_cbc_search')
            else:
                logger.critical('fatal_error', detail=f"The CBC query is invalid for : {mdr['name']} ({mdr_uuid})", advice='Ensure a value is included and slashes, colons, and spaces are manually escaped')
        except Exception as error:
            logger.critical('failed_to_validate_the_query_on_the_cbc_tenant')
            raise error

    def validate(self, deployment: list[str]):
        if not deployment:
            raise Exception('DEPLOYMENT NOT FOUND')
        self.configure_proxy()
        ORG_KEY = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]['org_key']
        TOKEN = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]['token']
        service = CBCloudAPI(url=self.CBC_URL, token=TOKEN, org_key=ORG_KEY, ssl_verify=self.SSL_ENABLED)
        logger.info('successfully_connected_to_carbon_black_cloud_on_tenant', detail=self.VALIDATION_ORGANIZATION)
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.mdr[mdr]
            mdr_uuid = mdr_data.get('uuid') or mdr_data['metadata']['uuid']
            if self.DEPLOYER_IDENTIFIER in mdr_data['configurations'].keys():
                logger.info('validating_cbc_lucene_query', detail=f"{mdr_data['name']} ({mdr_uuid}")
                self.check_query(mdr_data, service)
            else:
                logger.info('mdr_skipped', mdr_name=mdr_data.get('name'))

def declare():
    return CarbonBlackCloudQueryValidator()
if __name__ == '__main__' and DebugEnvironment.ENABLED:
    CarbonBlackCloudQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
