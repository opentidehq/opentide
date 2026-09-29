"""Elastic Security detection rule deployer."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import structlog

from opentide.core.registry import DetectionPlatforms
from opentide.deployment import TideDeployment, check_status
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.elastic_security.client import ElasticSecurityClient
from opentide.platforms.elastic_security.compile import compile_rule

logger = structlog.get_logger(__name__)


class ElasticSecurityDeploy:
    """Deploy detection rules to Elastic Security / Kibana Detection Engine."""

    def compile_deployment(
        self,
        data: DetectionRule,
        tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant | None = None,
    ) -> dict[str, Any]:
        """Compile a detection rule into an Elastic Security rule payload."""
        return compile_rule(data, tenant_config=tenant_config)

    def deploy_mdr(
        self,
        batch: Any,
        client: ElasticSecurityClient,
        tenant_config: ConfigurationModels.Systems.ElasticSecurity.Tenant,
    ) -> None:
        """Process rules for one tenant: delete, disable, or import."""
        rules_to_import: list[dict[str, Any]] = []
        ndjson_lines: list[str] = []

        existing_rule_ids: set[str] | None = None
        try:
            raw_export = client.export_rules()
            if isinstance(raw_export, (bytes, str)):
                text = raw_export.decode("utf-8") if isinstance(raw_export, bytes) else raw_export
                existing_rule_ids = set()
                for line in text.splitlines():
                    if line.strip():
                        try:
                            obj = json.loads(line)
                            if isinstance(obj, dict) and "rule_id" in obj:
                                existing_rule_ids.add(str(obj["rule_id"]))
                        except Exception:
                            pass
        except Exception:
            existing_rule_ids = None

        for rule in batch.rules:
            cfg = getattr(rule.configurations, "elastic_security", None)
            if not cfg:
                continue

            rule_id = cfg.rule_id or (rule.metadata.uuid if rule.metadata else "")
            status_override = cfg.status or rule.status
            strategy = check_status(status_override)

            if strategy is StatusStrategy.DELETION:
                if existing_rule_ids is not None and rule_id not in existing_rule_ids:
                    continue
                logger.info("deleting_elastic_security_rule", rule_id=rule_id, name=rule.name)
                try:
                    client.delete_rule(rule_id)
                except Exception as exc:
                    # Treat 404 (rule not found) on delete as success
                    status_code = getattr(getattr(exc, "response", None), "status_code", None)
                    if status_code == 404:
                        logger.info(
                            "delete_elastic_security_rule_not_found_treated_as_success",
                            rule_id=rule_id,
                        )
                    else:
                        logger.error(
                            "delete_elastic_security_rule_failed",
                            rule_id=rule_id,
                            error=str(exc),
                        )
                        raise
                continue

            if strategy is StatusStrategy.DISABLEMENT:
                if existing_rule_ids is not None and rule_id not in existing_rule_ids:
                    # Rule not on cluster; fall through to compile and import with enabled: False
                    pass
                else:
                    logger.info("disabling_elastic_security_rule", rule_id=rule_id, name=rule.name)
                    try:
                        client.patch_rule({"rule_id": rule_id, "enabled": False})
                        continue
                    except Exception as exc:
                        status_code = getattr(getattr(exc, "response", None), "status_code", None)
                        if status_code == 404:
                            logger.info(
                                "disable_elastic_security_rule_not_found_will_import",
                                rule_id=rule_id,
                            )
                        else:
                            logger.error(
                                "disable_elastic_security_rule_failed",
                                rule_id=rule_id,
                                error=str(exc),
                            )
                            raise

            # Active deployment: compile and respect rule/cfg enabled setting
            # Bundle any inline/referenced exception lists first into the import NDJSON
            exc_lists = getattr(cfg, "exception_lists", None)
            if exc_lists:
                for exc_list in exc_lists:
                    list_dump = (
                        exc_list.model_dump(exclude_none=True)
                        if hasattr(exc_list, "model_dump")
                        else dict(exc_list)
                    )
                    items = list_dump.pop("items", None) or []
                    ndjson_lines.append(json.dumps(list_dump, sort_keys=True))
                    for it in items:
                        item_dump = (
                            it.model_dump(exclude_none=True)
                            if hasattr(it, "model_dump")
                            else dict(it)
                        )
                        item_dump.setdefault("list_id", list_dump.get("list_id"))
                        ndjson_lines.append(json.dumps(item_dump, sort_keys=True))

            compiled = self.compile_deployment(rule, tenant_config=tenant_config)
            compiled["enabled"] = cfg.enabled if cfg.enabled is not None else True
            rules_to_import.append(compiled)
            ndjson_lines.append(json.dumps(compiled, sort_keys=True))

        if rules_to_import or ndjson_lines:
            logger.info(
                "importing_elastic_security_rules",
                count=len(rules_to_import),
                tenant=tenant_config.name,
            )
            batch_size = 50
            all_errors: list[dict[str, Any]] = []
            for i in range(0, len(ndjson_lines), batch_size):
                chunk = ndjson_lines[i : i + batch_size]
                ndjson_payload = "\n".join(chunk)
                resp = client.import_rules(
                    ndjson_payload,
                    overwrite=True,
                    overwrite_exceptions=getattr(tenant_config.setup, "overwrite_exceptions", False),
                    overwrite_action_connectors=getattr(
                        tenant_config.setup, "overwrite_action_connectors", False
                    ),
                )
                if isinstance(resp, dict):
                    errors = resp.get("errors", [])
                    success = resp.get("success", True)
                    if errors or not success:
                        all_errors.extend(errors)

            if all_errors:
                still_failing: list[dict[str, Any]] = []
                retry_lines: dict[str, str] = {}
                for line in ndjson_lines:
                    if line.strip():
                        try:
                            parsed = json.loads(line)
                            if isinstance(parsed, dict) and "rule_id" in parsed:
                                retry_lines[str(parsed["rule_id"])] = line
                        except Exception:
                            pass

                for err in all_errors:
                    rid = str(err.get("rule_id") or err.get("id") or "")
                    if rid and rid in retry_lines:
                        try:
                            retry_resp = client.import_rules(
                                retry_lines[rid],
                                overwrite=True,
                                overwrite_exceptions=getattr(
                                    tenant_config.setup, "overwrite_exceptions", False
                                ),
                                overwrite_action_connectors=getattr(
                                    tenant_config.setup, "overwrite_action_connectors", False
                                ),
                            )
                            if isinstance(retry_resp, dict) and not retry_resp.get("errors"):
                                continue
                        except Exception:
                            pass
                    still_failing.append(err)
                all_errors = still_failing

            if all_errors:
                error_details = []
                for err in all_errors:
                    rid = err.get("rule_id") or err.get("id") or "unknown"
                    msg = err.get("error", {}).get("message") or err.get("message") or str(err)
                    error_details.append(f"rule '{rid}': {msg}")
                error_summary = (
                    "; ".join(error_details) if error_details else "Import reported failure"
                )
                logger.error("import_elastic_security_rules_failed", errors=all_errors)
                raise RuntimeError(f"Elastic Security rule import failed: {error_summary}")

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy detection rules using TideDeployment tenant batches."""
        deployment = TideDeployment(
            mdr_deployment, DetectionPlatforms.ELASTIC_SECURITY, deployment_plan
        )
        for batch in deployment.rule_deployment:
            tenant: ConfigurationModels.Systems.ElasticSecurity.Tenant = batch.tenant
            client = ElasticSecurityClient(
                kibana_url=tenant.setup.kibana_url,
                api_key=getattr(tenant.setup, "api_key", ""),
                space=getattr(tenant.setup, "space", "default"),
                verify_ssl=getattr(tenant.setup, "ssl", True),
                proxy=getattr(tenant.setup, "proxy", None),
            )
            self.deploy_mdr(batch, client, tenant)


def declare() -> ElasticSecurityDeploy:
    """Entry point declared in pyproject.toml."""
    return ElasticSecurityDeploy()
