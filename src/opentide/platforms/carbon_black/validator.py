from __future__ import annotations

import os
from collections.abc import Sequence
from typing import TYPE_CHECKING

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, Opentide
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.platforms.carbon_black.client import (
    CarbonBlackCloudConnection,
    CarbonBlackCloudService,
)
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.transport import reaching_tenant

if TYPE_CHECKING:
    from cbc_sdk.rest_api import CBCloudAPI

logger = structlog.get_logger(__name__)


class CarbonBlackCloudQueryValidator(CarbonBlackCloudConnection, QueryValidator):
    def check_query(self, data: DetectionRule, service: CBCloudAPI) -> None:
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
        mdr_deployment: Sequence[DetectionRule] | list[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        if not strategies:
            raise ValueError("run strategies are required for CBC validation")

        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)

        tide_deployment = TideDeployment(
            deployment=loaded_mdr,
            system=DetectionPlatforms.CARBON_BLACK_CLOUD,
            strategies=strategies,
        )
        for tenant_deployment in tide_deployment.rule_deployment:
            tenant = tenant_deployment.tenant
            with reaching_tenant("carbon_black_cloud", tenant.name, tenant.setup.url):
                cbc_service = CarbonBlackCloudService(tenant)
                for mdr in tenant_deployment.rules:
                    if mdr.configurations.carbon_black_cloud:
                        logger.info(
                            "validating_cbc_query", mdr_name=mdr.name, uuid=mdr.metadata.uuid
                        )
                        self.check_query(mdr, cbc_service.service)
                    else:
                        logger.info(
                            "mdr_skipped",
                            mdr_name=mdr.name,
                            reason="no Carbon Black Cloud configuration section",
                        )


def declare():
    return CarbonBlackCloudQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    CarbonBlackCloudQueryValidator().validate(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, (StatusStrategy.PREVIEW,)
    )
