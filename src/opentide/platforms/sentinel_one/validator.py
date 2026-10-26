import os
from collections.abc import Sequence

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, Opentide
from opentide.deployment import TideDeployment
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.sentinel_one.client import SentinelOneService
from opentide.platforms.transport import reaching_tenant

logger = structlog.get_logger("opentide.platforms.sentinel_one.validator")


class SentinelOneQueryValidator(QueryValidator):
    def check_query(self, mdr: DetectionRule, service: SentinelOneService):
        config = mdr.platform_configs().sentinel_one
        if not config:
            raise Exception
        if config.condition.type == "Single Event":
            if not config.condition.single_event:
                raise Exception
            query = config.condition.single_event.query
            logger.info("validating_query", arg0=query)
            validation = service.validate_query(query)
            if not validation:
                os.environ["VALIDATION_ERROR_RAISED"] = "True"
        elif config.condition.type == "Correlation":
            if not config.condition.correlation:
                raise Exception
            for sub_query in config.condition.correlation.sub_queries:
                query = sub_query.query
                logger.info("validating_query", arg0=query)
                validation = service.validate_query(query)
                if not validation:
                    os.environ["VALIDATION_ERROR_RAISED"] = "True"

    def validate(
        self,
        mdr_deployment: Sequence[DetectionRule] | Sequence[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr
        deployment = TideDeployment(
            deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL_ONE, strategies=strategies
        )
        for tenant_deployment in deployment.rule_deployment:
            tenant = batch_tenant(tenant_deployment, ConfigurationModels.Systems.SentinelOne.Tenant)
            with reaching_tenant("sentinel_one", tenant.name, tenant.setup.url):
                service = SentinelOneService(tenant)
                for mdr in tenant_deployment.rules:
                    logger.info(
                        "event",
                        detail=f"Starting query validation on tenant {tenant.name}",
                        context_1=mdr.name,
                        advice=mdr.metadata.uuid,
                    )
                    self.check_query(mdr=mdr, service=service)


def declare():
    return SentinelOneQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelOneQueryValidator().validate(
        DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, (StatusStrategy.PREVIEW,)
    )
