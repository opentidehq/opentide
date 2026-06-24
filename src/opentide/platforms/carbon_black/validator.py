import os

from cbc_sdk.rest_api import CBCloudAPI

from opentide.core.debug import DebugEnvironment
from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.platforms.carbon_black.client import CarbonBlackCloudConnection
from opentide.platforms.plugins import QueryValidator

logger = get_logger(__name__)


class CarbonBlackCloudQueryValidator(CarbonBlackCloudConnection, QueryValidator):
    def check_query(self, mdr: dict, service: CBCloudAPI):
        query: str = mdr["configurations"]["carbon_black_cloud"].get("query")
        mdr_uuid = mdr.get("uuid") or mdr["metadata"]["uuid"]
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical(
                "missing_query_in_mdr",
                detail=f"{mdr.get('name')} ({mdr_uuid})",
            )
            return
        try:
            result = service.validate_process_query(query)
            if result:
                logger.info("valid_cbc_search")
            else:
                logger.critical(
                    "invalid_cbc_query",
                    mdr_name=mdr["name"],
                    mdr_uuid=mdr_uuid,
                    advice=(
                        "Ensure a value is included and slashes, colons, and spaces "
                        "are manually escaped"
                    ),
                )
        except Exception as error:
            logger.critical("cbc_query_validation_failed")
            raise error

    def validate(self, deployment: list[str], deployment_plan=None):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")
        self.configure_proxy()
        org_key = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["org_key"]
        token = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["token"]
        service = CBCloudAPI(
            url=self.CBC_URL,
            token=token,
            org_key=org_key,
            ssl_verify=self.SSL_ENABLED,
        )
        logger.info(
            "connected_to_carbon_black_cloud",
            tenant=self.VALIDATION_ORGANIZATION,
        )
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.rules[mdr]
            mdr_uuid = mdr_data.get("uuid") or mdr_data["metadata"]["uuid"]
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"]:
                logger.info(
                    "validating_cbc_lucene_query",
                    detail=f"{mdr_data['name']} ({mdr_uuid})",
                )
                self.check_query(mdr_data, service)
            else:
                logger.info(
                    "skipping_mdr_without_cbc_config",
                    detail=(
                        f"Skipping {mdr_data.get('name')} as does not contain a "
                        "Carbon Black configuration section"
                    ),
                )


def declare():
    return CarbonBlackCloudQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
