from __future__ import annotations

import os
from collections.abc import Sequence
from datetime import timedelta
from typing import TYPE_CHECKING

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.errors import Errors
from opentide.core.registry import Opentide
from opentide.deployment import DetectionPlatforms
from opentide.models.deployment_enums import RunStrategies, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels, batch_tenant
from opentide.platforms.plugins import QueryValidator
from opentide.platforms.transport import tenant_tls_verify

logger = structlog.get_logger("opentide.platforms.sentinel.validator")

if TYPE_CHECKING:
    from azure.core.exceptions import HttpResponseError
    from azure.monitor.query import LogsQueryClient


class SentinelQueryValidator(QueryValidator):
    def check_query(
        self,
        mdr: DetectionRule,
        tenant_config: ConfigurationModels.Systems.Sentinel.Tenant,
        service: LogsQueryClient,
    ):
        from azure.core.exceptions import (
            ClientAuthenticationError,
            HttpResponseError,
            ServiceRequestError,
        )
        from azure.identity import CredentialUnavailableError

        mdr_uuid = mdr.metadata.uuid
        sentinel = mdr.platform_configs().sentinel
        if not sentinel:
            raise Errors.TideMDRDataModelErrors("Missing Sentinel")
        query: str = sentinel.query
        if not query:
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
            logger.critical("missing_query_in_mdr", detail=f"{mdr.name} ({mdr_uuid})")
            return
        query += " | limit 1"
        try:
            service.query_workspace(
                workspace_id=tenant_config.setup.workspace_id,
                query=query,
                timespan=timedelta(minutes=1),
            )
            logger.info("the_query_is_a_valid_sentinel_kql", detail=f"{mdr.name} ({mdr_uuid})")
        except CredentialUnavailableError as error:
            logger.critical(
                "fatal_error",
                detail=f"Azure credential unavailable for : {mdr.name} ({mdr_uuid})",
                context=str(error),
                advice=(
                    "The credential provider could not authenticate. Check that tenant_id, "
                    "client_id and client_secret are correctly configured."
                ),
            )
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
        except ClientAuthenticationError as error:
            logger.critical(
                "fatal_error",
                detail=f"Azure authentication failed for : {mdr.name} ({mdr_uuid})",
                context=str(error.message),
                advice=(
                    "The service principal credentials may be expired or invalid. Verify the "
                    "client secret has not expired in Entra ID."
                ),
            )
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
        except ServiceRequestError as error:
            logger.critical(
                "fatal_error",
                detail=f"Network error reaching Azure Monitor for : {mdr.name} ({mdr_uuid})",
                context=str(error),
                advice=(
                    "Could not connect to the Azure Monitor endpoint. Check network "
                    "connectivity, proxy settings and SSL configuration."
                ),
            )
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
        except HttpResponseError as error:
            logger.debug("full_error_message", detail=str(error))
            try:
                logger.critical(
                    "fatal_error",
                    detail=f"The KQL query is invalid for : {mdr.name} ({mdr_uuid})",
                    context_1=_inner_message(error),
                    advice=(
                        "Review the error and ensure your search can work in the relevant "
                        f"Sentinel workspace ({tenant_config.setup.workspace_name})"
                    ),
                )
            except Exception:
                logger.error(
                    "not_able_to_parse_out_the_error_message",
                    detail="This may mean that there is a more complex problem",
                    advice="Will print out the full error package now",
                )
                logger.error("full_error_message", detail=str(error))
            os.environ["VALIDATION_ERROR_RAISED"] = "True"
        except Exception as error:
            logger.critical(
                "fatal_error",
                detail=f"Unexpected error during query validation for : {mdr.name} ({mdr_uuid})",
                context_1=f"{type(error).__name__}: {error}",
                advice="An unhandled exception occurred. Review the error details above.",
            )
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
        from azure.identity import ClientSecretCredential
        from azure.monitor.query import LogsQueryClient

        from opentide.core.environment import reject_unsubstituted_placeholders
        from opentide.deployment import TideDeployment

        deployment = TideDeployment(
            deployment=mdr_deployment, system=DetectionPlatforms.SENTINEL, strategies=strategies
        )
        for tenant_deployment in deployment.rule_deployment:
            tenant_config = batch_tenant(
                tenant_deployment, ConfigurationModels.Systems.Sentinel.Tenant
            )
            tenant_setup = tenant_config.setup
            logger.info("acquiring_azure_credentials_for_tenant", detail=tenant_config.name)
            reject_unsubstituted_placeholders(
                tenant_setup.azure_tenant_id,
                tenant_setup.azure_client_id,
                tenant_setup.azure_client_secret,
                client="Azure",
            )
            verify = tenant_tls_verify(
                tenant_setup.ssl, platform="sentinel", tenant=tenant_config.name
            )
            credentials = ClientSecretCredential(
                tenant_setup.azure_tenant_id,
                tenant_setup.azure_client_id,
                tenant_setup.azure_client_secret,
                connection_verify=verify,
            )
            logger.info(
                "azure_credentials_prepared_for_tenant",
                detail=tenant_config.name,
                advice="Note: credentials are validated lazily on first API call",
            )
            logger.info("initialising_logsqueryclient_for_tenant", detail=tenant_config.name)
            service = LogsQueryClient(credential=credentials, connection_verify=verify)
            logger.info("logsqueryclient_ready_for_tenant", detail=tenant_config.name)
            for mdr in tenant_deployment.rules:
                logger.info("validating_kql_query", detail=f"{mdr.name} ({mdr.metadata.uuid})")
                logger.info(
                    "sending_query_to_azure_monitor_workspace",
                    detail=f"{mdr.name} ({mdr.metadata.uuid})",
                )
                self.check_query(mdr=mdr, service=service, tenant_config=tenant_config)


def declare():
    return SentinelQueryValidator()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SentinelQueryValidator().validate(
        ["5e791284-684c-4245-9ac7-cf00a1d041d6"], (StatusStrategy.PREVIEW,)
    )


def _inner_message(error: HttpResponseError) -> str:
    """The KQL parser's message inside an Azure Monitor error; KeyError when absent."""
    odata = error.error
    if odata is None or not odata.innererror:
        raise KeyError("innererror")
    return odata.innererror["innererror"]["message"]
