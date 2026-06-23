import os
import sys


from cbc_sdk.rest_api import CBCloudAPI
from typing import Sequence, Union


from opentide.core.logging import log
from opentide.core.debug import DebugEnvironment
from opentide.platforms.plugins import QueryValidator
from opentide.core.registry import OpenTide, DetectionPlatforms
from opentide.models.rule import DetectionRule
from opentide.models.legacy import (
                                    DeploymentStrategy,
                                    ConfigurationModels) 
from opentide.deployment import TideDeployment
from opentide.platforms.sentinel_one.client import SentinelOneService

class SentinelOneQueryValidator(QueryValidator):

    def check_query(self,
                    mdr:DetectionRule,
                    service:SentinelOneService):
        
        config = mdr.configurations.sentinel_one
        if not config: 
            raise Exception
        
        if config.condition.type == "Single Event":
            if not config.condition.single_event:
                raise Exception
            
            query = config.condition.single_event.query
            log("ONGOING", "Validating query", query)
            validation = service.validate_query(query)
            
            if not validation:
                os.environ["VALIDATION_ERROR_RAISED"] = "True" 
        
        elif config.condition.type == "Correlation":
            if not config.condition.correlation:
                raise Exception
            
            for sub_query in config.condition.correlation.sub_queries:
                query = sub_query.query
                log("ONGOING", "Validating query", query)
                validation = service.validate_query(query)
                if not validation:
                    os.environ["VALIDATION_ERROR_RAISED"] = "True" 

    def validate(self,
                 mdr_deployment: Union[Sequence[DetectionRule], Sequence[str]],
                 deployment_plan:DeploymentStrategy):
        
        loaded_mdr = []
        for mdr in mdr_deployment:
            if type(mdr) is str:
                loaded_mdr.append(OpenTide.Models.MDR[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        mdr_deployment = loaded_mdr

        deployment = TideDeployment(deployment=mdr_deployment,
                                    system=DetectionPlatforms.SENTINEL_ONE,
                                    strategy=deployment_plan)
        
        for tenant_deployment in deployment.rule_deployment:
            service = SentinelOneService(tenant_deployment.tenant)

            for mdr in tenant_deployment.rules:
                log("INFO",
                    f"Starting query validation on tenant {tenant_deployment.tenant.name}",
                    mdr.name,
                    mdr.metadata.uuid)
                
                self.check_query(mdr=mdr,
                                service=service)

def declare():
    return SentinelOneQueryValidator()

if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelOneQueryValidator().validate(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)