from __future__ import annotations

import json
import os
import traceback
from collections.abc import Sequence

import structlog
from splunklib import client

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.splunk.client import (
    SplunkConnection,
    connect_splunk,
    create_query,
    create_query_v4,
)

logger = structlog.get_logger(__name__)


class SplunkQueryValidator(SplunkConnection, QueryValidator):
    def check_query(self, mdr: dict[str, object], service: client.Service) -> None:
        mdr_uuid = str(mdr.get("uuid") or mdr["metadata"]["uuid"])  # type: ignore[index]
        query: str | None = mdr["configurations"][self.DEPLOYER_IDENTIFIER].get("query")  # type: ignore[index]
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", mdr_name=mdr.get("name"), uuid=mdr_uuid)
            return
        query = create_query(mdr)  # type: ignore[arg-type]
        self._validate_spl_query(query, str(mdr["name"]), mdr_uuid, service)

    def check_query_v4(self, data: DetectionRule, service: client.Service) -> None:
        splunk_config = data.configurations.splunk
        if not splunk_config or not splunk_config.query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", mdr_name=data.name, uuid=data.metadata.uuid)
            return
        query = create_query_v4(data)
        self._validate_spl_query(query, data.name, data.metadata.uuid, service)

    def _validate_spl_query(
        self, query: str, mdr_name: str, mdr_uuid: str, service: client.Service
    ) -> None:
        if not query.startswith("| "):
            query = "| search " + query
            logger.info("adding_implicit_search_prefix")
        try:
            response = service.parse(
                query.strip(), enable_lookups=True, output_mode="json", reload_macros=True
            )
            status = response["status"]
            if status == 19:
                if (reason := response.get("reason")) and reason == "Temporary Redirect":
                    if "Network Error" in str(response["body"].read()):
                        logger.warning("query_validation_timeout_assumed_valid", mdr_name=mdr_name)
                        os.environ["VALIDATION_WARNING_RAISED"] = "True"
                        return
                parsing = json.loads(response["body"].read())
                for message in parsing["messages"]:
                    logger.critical(
                        "invalid_spl_query",
                        mdr_name=mdr_name,
                        uuid=mdr_uuid,
                        detail=message.get("text", ""),
                    )
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
            elif status == 200:
                logger.info("valid_spl_query", mdr_name=mdr_name)
            else:
                logger.critical("unexpected_splunk_validation_response", response=str(response))
        except Exception as exc:
            logger.critical("splunk_query_validation_failed", error=repr(exc))
            traceback.print_exc()
            raise

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str] | None = None,
        deployment_plan: DeploymentStrategy | None = None,
        deployment: list[str] | None = None,
    ) -> None:
        if mdr_deployment is not None:
            loaded_mdr: list[DetectionRule] = []
            for mdr in mdr_deployment:
                if isinstance(mdr, str):
                    loaded_mdr.append(OpenTide.Rules[mdr])
                elif isinstance(mdr, DetectionRule):
                    loaded_mdr.append(mdr)
            if not deployment_plan:
                raise ValueError("deployment_plan is required for MDRv4 Splunk validation")
            tide_deployment = TideDeployment(
                deployment=loaded_mdr,
                system=DetectionPlatforms.SPLUNK,
                strategy=deployment_plan,
            )
            self.configure_proxy()
            for tenant_deployment in tide_deployment.rule_deployment:
                tenant = tenant_deployment.tenant
                service = connect_splunk(
                    host=tenant.setup.url,
                    port=tenant.setup.port,
                    token=tenant.setup.token,
                    app=tenant.setup.app,
                    allow_http_errors=True,
                    ssl_enabled=tenant.setup.ssl,
                )
                for mdr in tenant_deployment.rules:
                    if mdr.configurations.splunk:
                        logger.info(
                            "validating_spl_query", mdr_name=mdr.name, uuid=mdr.metadata.uuid
                        )
                        self.check_query_v4(mdr, service)
                    else:
                        logger.info(
                            "mdr_skipped", mdr_name=mdr.name, reason="no Splunk configuration"
                        )
            return

        if not deployment:
            raise ValueError("DEPLOYMENT NOT FOUND")
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
                logger.info("validating_spl_query", mdr_name=mdr_data["name"], uuid=mdr_uuid)
                self.check_query(mdr_data, service)
            else:
                logger.info(
                    "mdr_skipped",
                    mdr_name=mdr_data.get("name"),
                    reason="no Splunk configuration section",
                )


def declare():
    return SplunkQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkQueryValidator().validate(deployment=DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
