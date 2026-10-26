"""Elastic Security detection rule deployer (RFC 0007 §5)."""

from __future__ import annotations

import copy
import os
from collections.abc import Sequence
from typing import Any

import requests
import structlog

from opentide.core.registry import Opentide
from opentide.deployment import TideDeployment, check_status
from opentide.deployment.external_ids import without_legacy_external_ids
from opentide.models.deployment_enums import (
    DetectionPlatforms,
    RunStrategies,
    StatusStrategy,
)
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.attack import find_non_enterprise_techniques
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import compile_rule
from opentide.platforms.elastic.es_checks import (
    ElasticRuleCheckError,
    ElasticTenantError,
    run_elasticsearch_checks,
)
from opentide.platforms.transport import tenant_tls_verify

logger = structlog.get_logger(__name__)


def _deployment_error(event: str, **kwargs: Any) -> None:
    logger.error(event, **kwargs)
    os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"


def _deployment_warning(event: str, **kwargs: Any) -> None:
    logger.warning(event, **kwargs)
    os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"


def _check_rule(
    client: ElasticClient,
    block: dict[str, Any],
    setup_index: list[str],
    *,
    rule_id: str,
    rule_name: str,
) -> bool:
    """Run Elasticsearch checks. Return whether the rule may be deployed.

    A tenant failure (auth) propagates. A rule failure is recorded and skips
    that rule. Warnings are recorded and the rule still deploys.
    """
    try:
        reported = run_elasticsearch_checks(client, block, setup_index=setup_index)
    except ElasticTenantError:
        raise
    except ElasticRuleCheckError as exc:
        _deployment_error(
            "elasticsearch_checks_failed",
            rule_id=rule_id,
            rule=rule_name,
            error=str(exc),
        )
        return False
    if isinstance(reported, list):
        for warning in reported:
            _deployment_warning(
                "elasticsearch_check_warning",
                rule_id=rule_id,
                rule=rule_name,
                warning=warning,
            )
    return True


def _write_failed(resp: Any, event: str, rule_id: str, tenant: str) -> bool:
    """Record a failed Kibana write and return whether it failed.

    RFC 0007 §5: 401 or 403 fails the tenant. Any other error (400, 404, 409,
    or a 429/5xx that outlived the client's retries) fails only this rule, and
    the batch continues.
    """
    if resp.status_code in (401, 403):
        raise ElasticTenantError(
            f"Tenant {tenant} auth error: HTTP {resp.status_code}: {_kibana_error(resp)}"
        )
    if resp.status_code >= 400:
        _deployment_error(
            event, rule_id=rule_id, status_code=resp.status_code, error=_kibana_error(resp)
        )
        return True
    return False


def _kibana_error(resp: Any) -> str:
    """Kibana's ``message`` from an error body, else the raw body text."""
    try:
        body = resp.json()
    except ValueError:
        return resp.text
    if isinstance(body, dict) and body.get("message"):
        return str(body["message"])
    return resp.text


PRESERVED_FIELDS = (
    "actions",
    "exceptions_list",
    "response_actions",
    "timeline_id",
    "timeline_title",
    "concurrent_searches",
    "items_per_search",
    "meta",
    "output_index",
    "namespace",
    "throttle",
)


def _is_prebuilt_rule(remote: dict[str, Any]) -> bool:
    if remote.get("immutable") is True:
        return True
    rule_source = remote.get("rule_source")
    if isinstance(rule_source, dict) and rule_source.get("type") == "external":
        return True
    return False


class ElasticDeploy:
    """Deploy detection rules to Elastic Security Detection Engine."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: ConfigurationModels.Systems.Elastic.Tenant | None = None,
    ) -> dict[str, Any]:
        """Compile a detection rule into an Elastic Security rule payload."""
        if find_non_enterprise_techniques(data):
            os.environ["DEPLOYMENT_WARNING_RAISED"] = "1"
        return compile_rule(data, tenant_config=tenant_config)

    def deploy_mdr(
        self,
        batch: Any,
        client: ElasticClient,
        tenant_config: ConfigurationModels.Systems.Elastic.Tenant,
    ) -> None:
        """Process rules for one tenant: delete, disable, create, or update."""
        suppression_warned: set[str] = set()
        setup = tenant_config.setup

        for rule in batch.rules:
            cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
            if not cfg:
                continue

            rule_id = rule.metadata.uuid if rule.metadata else ""
            status = cfg.status
            strategy = check_status(status)

            if strategy is StatusStrategy.INERT:
                continue

            if strategy is StatusStrategy.DELETION:
                logger.info("deleting_elastic_rule", rule_id=rule_id, name=rule.name)
                try:
                    resp = client.delete_rule(rule_id)
                    if resp.status_code not in (200, 404):
                        resp.raise_for_status()
                except Exception as exc:
                    status_code = getattr(getattr(exc, "response", None), "status_code", None)
                    if status_code == 404:
                        logger.info("delete_elastic_rule_not_found_success", rule_id=rule_id)
                    elif status_code in (401, 403):
                        raise
                    else:
                        _deployment_error(
                            "delete_elastic_rule_failed", rule_id=rule_id, error=str(exc)
                        )
                continue

            # Active deployment: PREVIEW, RELEASE, or DISABLEMENT
            if setup.suppression is False and cfg.suppression is not None:
                if rule_id not in suppression_warned:
                    _deployment_warning(
                        "suppression_omitted_basic_license",
                        rule=rule.name,
                        rule_id=rule_id,
                        tenant=tenant_config.name,
                    )
                    suppression_warned.add(rule_id)

            block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
            if not _check_rule(
                client,
                block_dict,
                list(setup.index or []),
                rule_id=rule_id,
                rule_name=rule.name,
            ):
                continue

            compiled = self.compile_deployment(rule, tenant_config=tenant_config)
            if strategy is StatusStrategy.DISABLEMENT:
                compiled["enabled"] = False
            else:
                compiled["enabled"] = True

            # GET existing rule by rule_id
            try:
                get_resp = client.get_rule(rule_id)
            except Exception as exc:
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                if status_code in (401, 403):
                    raise
                _deployment_error("get_elastic_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            if get_resp.status_code in (401, 403):
                raise ElasticTenantError(
                    f"Tenant {tenant_config.name} auth error: HTTP {get_resp.status_code}"
                )

            if get_resp.status_code == 404:
                # Rule not found: POST. 401/403 fails the tenant; any other
                # error fails this rule only (RFC 0007 §5).
                logger.info("creating_elastic_rule", rule_id=rule_id, name=rule.name)
                try:
                    create_resp = client.create_rule(compiled)
                except requests.RequestException as exc:
                    _deployment_error("create_elastic_rule_failed", rule_id=rule_id, error=str(exc))
                    continue
                _write_failed(
                    create_resp, "create_elastic_rule_failed", rule_id, tenant_config.name
                )
                continue

            if get_resp.status_code != 200:
                # 429 and 5xx were already retried by the client. Anything else
                # fails this rule, never silently (RFC 0007 §5).
                _deployment_error(
                    "get_elastic_rule_failed",
                    rule_id=rule_id,
                    status_code=get_resp.status_code,
                    error=get_resp.text,
                )
                continue

            remote = get_resp.json()
            if _is_prebuilt_rule(remote):
                _deployment_error(
                    "refusing_to_modify_prebuilt_rule",
                    rule_id=rule_id,
                    name=rule.name,
                )
                continue

            # Preserve remote fields when not set in authored block
            for key in PRESERVED_FIELDS:
                if key not in compiled and key in remote:
                    compiled[key] = copy.deepcopy(remote[key])

            remote_type = remote.get("type")
            compiled_type = compiled.get("type")

            if remote_type != compiled_type:
                # PUT cannot change type: DELETE then POST with the same rule_id
                # and the preserved fields (RFC 0007 §5, Type changes).
                logger.info(
                    "type_change_recreating_elastic_rule",
                    rule_id=rule_id,
                    remote_type=remote_type,
                    new_type=compiled_type,
                )
                del_resp = client.delete_rule(rule_id)
                if del_resp.status_code != 404 and _write_failed(
                    del_resp, "recreate_elastic_rule_delete_failed", rule_id, tenant_config.name
                ):
                    continue
                post_resp = client.create_rule(compiled)
                if _write_failed(
                    post_resp, "recreate_elastic_rule_failed", rule_id, tenant_config.name
                ):
                    # The old rule is already gone. Say so, so the operator can redeploy.
                    logger.error("elastic_rule_deleted_not_recreated", rule_id=rule_id)
            else:
                logger.info("updating_elastic_rule", rule_id=rule_id, name=rule.name)
                put_resp = client.update_rule(compiled)
                _write_failed(put_resp, "update_elastic_rule_failed", rule_id, tenant_config.name)

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        strategies: RunStrategies | None = None,
    ) -> None:
        """Deploy detection rules using TideDeployment tenant batches."""
        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(Opentide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)
        loaded_mdr = without_legacy_external_ids(loaded_mdr, platform="elastic")
        if not loaded_mdr:
            logger.info("no_rules_to_deploy_for_elastic")
            return
        deployment = TideDeployment(loaded_mdr, DetectionPlatforms.ELASTIC, strategies)
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.Elastic.Tenant = batch.tenant
            client = ElasticClient(
                url=tenant.setup.url,
                elasticsearch_url=tenant.setup.elasticsearch_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=tenant_tls_verify(
                    getattr(tenant.setup, "ssl", True), platform="elastic", tenant=tenant.name
                ),
            )
            try:
                self.deploy_mdr(batch, client, tenant)
            except Exception as exc:
                logger.critical(
                    "elastic_tenant_deployment_failed",
                    tenant=tenant.name,
                    error=str(exc),
                )
                os.environ["DEPLOYMENT_ERROR_RAISED"] = "1"


def declare() -> ElasticDeploy:
    """Entry point declared in pyproject.toml."""
    return ElasticDeploy()
