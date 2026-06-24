import json
import os
import traceback

from splunklib import client

from opentide.core.debug import DebugEnvironment
from opentide.core.logging import get_logger
from opentide.core.registry import OpenTide
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.splunk.client import SplunkConnection, connect_splunk, create_query

logger = get_logger(__name__)


class SplunkQueryValidator(SplunkConnection, QueryValidator):
    def check_query(self, mdr: dict, service: client.Service):
        mdr_uuid = mdr.get("uuid") or mdr["metadata"]["uuid"]
        query: str = mdr["configurations"][self.DEPLOYER_IDENTIFIER].get("query")
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical(
                "missing_query_in_mdr",
                detail=f"{mdr.get('name')} ({mdr_uuid})",
            )
            return
        query = create_query(mdr)
        if not query.startswith("| "):
            query = "| search " + query
            logger.info("adding_implicit_search_prefix")
        try:
            response = service.parse(
                query.strip(),
                enable_lookups=True,
                output_mode="json",
                reload_macros=True,
            )
            status = response["status"]
            if status == 19:
                if reason := response.get("reason"):
                    if reason == "Temporary Redirect":
                        if "Network Error" in str(response["body"].read()):
                            logger.error(
                                "splunk_parse_timeout_assumed_valid",
                                detail=(
                                    "We encountered an unexpected error, which has shown "
                                    "empirically to be related to time-out. The query is "
                                    "assumed to be valid; if deployment fails it may be "
                                    "related to the query."
                                ),
                            )
                            os.environ["VALIDATION_WARNING_RAISED"] = "True"
                            return
                parsing = json.loads(response["body"].read())
                logger.debug("splunk_parse_body", body=parsing)
                for message in parsing["messages"]:
                    logger.critical(
                        "invalid_spl_query",
                        mdr_name=mdr["name"],
                        mdr_uuid=mdr_uuid,
                        detail=message.get("text", ""),
                        advice=(
                            "Review the error and ensure it can run on the Splunk Search console"
                        ),
                    )
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
                return
            if status == 200:
                logger.info("valid_spl_query")
                return
            logger.critical("unexpected_splunk_error_code", detail=str(response))
        except Exception as exc:
            logger.critical("splunk_validation_error", detail=repr(exc))
            traceback.print_exc()
            raise

    def validate(self, deployment: list[str], deployment_plan=None):
        if not deployment:
            raise Exception("DEPLOYMENT NOT FOUND")
        self.configure_proxy()
        service = connect_splunk(
            host=self.SPLUNK_URL,
            port=self.SPLUNK_PORT,
            token=self.SPLUNK_TOKEN,
            app=self.SPLUNK_APP,
            allow_http_errors=True,
            ssl_enabled=self.SSL_ENABLED,
        )
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.rules[mdr]
            mdr_uuid = mdr_data.get("uuid") or mdr_data["metadata"]["uuid"]
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"]:
                logger.info(
                    "validating_spl_query",
                    detail=f"{mdr_data['name']} ({mdr_uuid})",
                )
                self.check_query(mdr_data, service)
            else:
                logger.info(
                    "skipping_mdr_without_splunk_config",
                    mdr_name=mdr_data.get("name"),
                )


def declare():
    return SplunkQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
