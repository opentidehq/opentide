"""Elastic Security detection rule deployer (RFC 0007 §5)."""

from __future__ import annotations

import copy
import json
from collections.abc import Sequence
from typing import Any

import structlog

from opentide.deployment import TideDeployment, check_status
from opentide.models.deployment_enums import (
    DeploymentStrategy,
    DetectionPlatforms,
    StatusStrategy,
)
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic.client import ElasticClient
from opentide.platforms.elastic.compile import compile_rule
from opentide.platforms.elastic.es_checks import run_elasticsearch_checks

logger = structlog.get_logger(__name__)

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
        return compile_rule(data, tenant_config=tenant_config)

    def deploy_mdr(
        self,
        batch: Any,
        client: ElasticClient,
        tenant_config: ConfigurationModels.Systems.Elastic.Tenant,
    ) -> None:
        """Process rules for one tenant: delete, disable, create, or update."""
        if getattr(tenant_config.setup, "bulk_import", False):
            self._deploy_bulk(batch, client, tenant_config)
            return

        suppression_warned: set[str] = set()
        setup = tenant_config.setup

        for rule in batch.rules:
            cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
            if not cfg:
                continue

            rule_id = rule.metadata.uuid if rule.metadata else ""
            status = cfg.status or "STAGING"
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
                        logger.error("delete_elastic_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            # Active deployment: PREVIEW, RELEASE, or DISABLEMENT
            if setup.suppression is False and cfg.suppression is not None:
                if rule_id not in suppression_warned:
                    logger.warning(
                        "suppression_omitted_basic_license",
                        rule=rule.name,
                        rule_id=rule_id,
                        tenant=tenant_config.name,
                    )
                    suppression_warned.add(rule_id)

            # Mandatory Elasticsearch pre-flight checks
            block_dict = cfg.model_dump(by_alias=True, exclude_none=False)
            try:
                run_elasticsearch_checks(client, block_dict, setup_index=list(setup.index or []))
            except Exception as exc:
                logger.error("elasticsearch_checks_failed", rule_id=rule_id, rule=rule.name, error=str(exc))
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
                logger.error("get_elastic_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            if get_resp.status_code in (401, 403):
                raise RuntimeError(
                    f"Authentication/authorization error for tenant {tenant_config.name}: HTTP {get_resp.status_code}"
                )

            if get_resp.status_code == 404:
                # Rule not found: POST
                logger.info("creating_elastic_rule", rule_id=rule_id, name=rule.name)
                try:
                    create_resp = client.create_rule(compiled)
                    if create_resp.status_code in (400, 409):
                        logger.error(
                            "create_elastic_rule_failed",
                            rule_id=rule_id,
                            status_code=create_resp.status_code,
                            error=create_resp.text,
                        )
                        continue
                    if create_resp.status_code in (401, 403):
                        raise RuntimeError(f"Tenant auth error: HTTP {create_resp.status_code}")
                    create_resp.raise_for_status()
                except Exception as exc:
                    status_code = getattr(getattr(exc, "response", None), "status_code", None)
                    if status_code in (401, 403):
                        raise
                    logger.error("create_elastic_rule_error", rule_id=rule_id, error=str(exc))
                continue

            if get_resp.status_code == 200:
                remote = get_resp.json()
                if _is_prebuilt_rule(remote):
                    logger.error(
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
                    # Type changed: DELETE then POST with same rule_id and preserved fields
                    logger.info(
                        "type_change_recreating_elastic_rule",
                        rule_id=rule_id,
                        remote_type=remote_type,
                        new_type=compiled_type,
                    )
                    del_resp = client.delete_rule(rule_id)
                    if del_resp.status_code not in (200, 404):
                        del_resp.raise_for_status()
                    post_resp = client.create_rule(compiled)
                    if post_resp.status_code in (400, 409):
                        logger.error(
                            "recreate_elastic_rule_failed",
                            rule_id=rule_id,
                            status_code=post_resp.status_code,
                            error=post_resp.text,
                        )
                        continue
                    if post_resp.status_code in (401, 403):
                        raise RuntimeError(f"Tenant auth error: HTTP {post_resp.status_code}")
                    post_resp.raise_for_status()
                else:
                    # Same type: PUT
                    logger.info("updating_elastic_rule", rule_id=rule_id, name=rule.name)
                    put_resp = client.update_rule(compiled)
                    if put_resp.status_code in (400, 409):
                        logger.error(
                            "update_elastic_rule_failed",
                            rule_id=rule_id,
                            status_code=put_resp.status_code,
                            error=put_resp.text,
                        )
                        continue
                    if put_resp.status_code in (401, 403):
                        raise RuntimeError(f"Tenant auth error: HTTP {put_resp.status_code}")
                    put_resp.raise_for_status()

    def _deploy_bulk(
        self,
        batch: Any,
        client: ElasticClient,
        tenant_config: ConfigurationModels.Systems.Elastic.Tenant,
    ) -> None:
        """Deploy rules using Kibana's multipart NDJSON bulk _import endpoint."""
        suppression_warned: set[str] = set()
        setup = tenant_config.setup
        ndjson_lines: list[str] = []

        for rule in batch.rules:
            cfg = getattr(rule.configurations, "elastic", None) if rule.configurations else None
            if not cfg:
                continue

            rule_id = rule.metadata.uuid if rule.metadata else ""
            status = cfg.status or "STAGING"
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
                        logger.error("delete_elastic_rule_failed", rule_id=rule_id, error=str(exc))
                continue

            # Active deployment: PREVIEW, RELEASE, or DISABLEMENT
            if setup.suppression is False and cfg.suppression is not None:
                if rule_id not in suppression_warned:
                    logger.warning(
                        "suppression_omitted_basic_license",
                        rule=rule.name,
                        rule_id=rule_id,
                        tenant=tenant_config.name,
                    )
                    suppression_warned.add(rule_id)

            compiled = self.compile_deployment(rule, tenant_config=tenant_config)
            if strategy is StatusStrategy.DISABLEMENT:
                compiled["enabled"] = False
            else:
                compiled["enabled"] = True

            if "version" not in compiled:
                compiled["version"] = getattr(rule.metadata, "version", 1) if rule.metadata else 1

            ndjson_lines.append(json.dumps(compiled, sort_keys=True))

        if ndjson_lines:
            batch_size = 50
            for i in range(0, len(ndjson_lines), batch_size):
                chunk = ndjson_lines[i : i + batch_size]
                ndjson_payload = "\n".join(chunk)
                try:
                    resp = client.import_rules(ndjson_payload, overwrite=True)
                    success_count = resp.get("success_count", 0)
                    errors = resp.get("errors", [])
                    logger.info(
                        "bulk_import_batch_complete",
                        batch_index=i // batch_size + 1,
                        success_count=success_count,
                        error_count=len(errors),
                        tenant=tenant_config.name,
                    )
                    if errors:
                        for err in errors:
                            rid = err.get("rule_id") or err.get("id") or "unknown"
                            msg = err.get("error", {}).get("message") or err.get("message") or str(err)
                            logger.error("bulk_import_rule_error", rule_id=rid, error=msg)
                except Exception as exc:
                    status_code = getattr(getattr(exc, "response", None), "status_code", None)
                    if status_code in (401, 403):
                        raise
                    logger.error("bulk_import_batch_failed", error=str(exc), tenant=tenant_config.name)

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy detection rules using TideDeployment tenant batches."""
        deployment = TideDeployment(
            mdr_deployment, DetectionPlatforms.ELASTIC, deployment_plan
        )
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.Elastic.Tenant = batch.tenant
            client = ElasticClient(
                url=tenant.setup.url,
                elasticsearch_url=tenant.setup.elasticsearch_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
            )
            try:
                self.deploy_mdr(batch, client, tenant)
            except Exception as exc:
                logger.critical(
                    "elastic_tenant_deployment_failed",
                    tenant=tenant.name,
                    error=str(exc),
                )


def declare() -> ElasticDeploy:
    """Entry point declared in pyproject.toml."""
    return ElasticDeploy()
