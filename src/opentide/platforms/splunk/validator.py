from __future__ import annotations

import json
import os
import traceback
from collections.abc import Sequence
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from splunklib.client import Service

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
)

logger = structlog.get_logger(__name__)


class SplunkQueryValidator(SplunkConnection, QueryValidator):
    def check_query(self, data: DetectionRule, service: Service) -> None:
        splunk_config = data.configurations.splunk
        if not splunk_config or not splunk_config.query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", mdr_name=data.name, uuid=data.metadata.uuid)
            return
        query = create_query(data)
        self._validate_spl_query(query, data.name, data.metadata.uuid, service)

    def _validate_spl_query(
        self, query: str, mdr_name: str, mdr_uuid: str, service: Service
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
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        if not deployment_plan:
            raise ValueError("deployment_plan is required for Splunk validation")

        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)

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
                    logger.info("validating_spl_query", mdr_name=mdr.name, uuid=mdr.metadata.uuid)
                    self.check_query(mdr, service)
                else:
                    logger.info("mdr_skipped", mdr_name=mdr.name, reason="no Splunk configuration")


def declare():
    return SplunkQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkQueryValidator().validate(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG
    )
