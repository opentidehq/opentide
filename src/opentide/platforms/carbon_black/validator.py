from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import DeploymentStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.carbon_black.client import (
    CarbonBlackCloudConnection,
    CarbonBlackCloudService,
)
from opentide.platforms.plugins import QueryValidator

if TYPE_CHECKING:
    from cbc_sdk.rest_api import CBCloudAPI

logger = structlog.get_logger(__name__)


class CarbonBlackCloudQueryValidator(CarbonBlackCloudConnection, QueryValidator):
    def check_query(self, mdr: dict[str, object], service: CBCloudAPI) -> None:
        query: str | None = mdr["configurations"]["carbon_black_cloud"].get("query")  # type: ignore[index]
        mdr_uuid = str(mdr.get("uuid") or mdr["metadata"]["uuid"])  # type: ignore[index]
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", mdr_name=mdr.get("name"), uuid=mdr_uuid)
            return
        self._validate_cbc_query(query, str(mdr["name"]), mdr_uuid, service)

    def check_query_v4(self, data: DetectionRule, service: CBCloudAPI) -> None:
        config = data.configurations.carbon_black_cloud
        if not config or not config.query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", mdr_name=data.name, uuid=data.metadata.uuid)
            return
        self._validate_cbc_query(config.query, data.name, data.metadata.uuid, service)

    def _validate_cbc_query(
        self, query: str, mdr_name: str, mdr_uuid: str, service: CBCloudAPI
    ) -> None:
        try:
            result = service.validate_process_query(query)
            if result:
                logger.info("valid_cbc_query", mdr_name=mdr_name)
            else:
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
                logger.critical(
                    "invalid_cbc_query",
                    mdr_name=mdr_name,
                    uuid=mdr_uuid,
                    advice="Ensure a value is included and escape slashes, colons, and spaces",
                )
        except Exception as error:
            logger.critical("cbc_query_validation_failed", mdr_name=mdr_name)
            raise error

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
                raise ValueError("deployment_plan is required for MDRv4 CBC validation")
            tide_deployment = TideDeployment(
                deployment=loaded_mdr,
                system=DetectionPlatforms.CARBON_BLACK_CLOUD,
                strategy=deployment_plan,
            )
            self.configure_proxy()
            for tenant_deployment in tide_deployment.rule_deployment:
                cbc_service = CarbonBlackCloudService(tenant_deployment.tenant)
                for mdr in tenant_deployment.rules:
                    if mdr.configurations.carbon_black_cloud:
                        logger.info(
                            "validating_cbc_query", mdr_name=mdr.name, uuid=mdr.metadata.uuid
                        )
                        self.check_query_v4(mdr, cbc_service.service)
                    else:
                        logger.info(
                            "mdr_skipped",
                            mdr_name=mdr.name,
                            reason="no Carbon Black Cloud configuration section",
                        )
            return

        if not deployment:
            raise ValueError("DEPLOYMENT NOT FOUND")
        self.configure_proxy()
        org_key = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["org_key"]
        token = self.CBC_SECRETS[self.VALIDATION_ORGANIZATION]["token"]
        from cbc_sdk.rest_api import CBCloudAPI

        service = CBCloudAPI(
            url=self.CBC_URL, token=token, org_key=org_key, ssl_verify=self.SSL_ENABLED
        )
        logger.info("connected_to_cbc_tenant", org=self.VALIDATION_ORGANIZATION)
        for mdr in deployment:
            mdr_data: dict = OpenTide.Models.rules[mdr]
            mdr_uuid = mdr_data.get("uuid") or mdr_data["metadata"]["uuid"]
            if self.DEPLOYER_IDENTIFIER in mdr_data["configurations"]:
                logger.info("validating_cbc_query", mdr_name=mdr_data["name"], uuid=mdr_uuid)
                self.check_query(mdr_data, service)
            else:
                logger.info(
                    "mdr_skipped",
                    mdr_name=mdr_data.get("name"),
                    reason="no Carbon Black Cloud configuration section",
                )


def declare():
    return CarbonBlackCloudQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudQueryValidator().validate(deployment=DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS)
