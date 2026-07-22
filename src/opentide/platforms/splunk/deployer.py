from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import structlog

from opentide.core.debug import DebugEnvironment
from opentide.core.registry import DetectionPlatforms, OpenTide
from opentide.deployment import TideDeployment, check_status
from opentide.generation.framework import techniques_resolver
from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy
from opentide.models.rule import DetectionRule
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.plugins import RuleDeployer
from opentide.platforms.splunk.client import (
    SplunkConnection,
    connect_splunk,
    create_query,
    cron_to_timeframe,
    splunk_timerange,
)

logger = structlog.get_logger(__name__)


class SplunkDeploy(SplunkConnection, RuleDeployer):
    def __init__(self) -> None:
        super().__init__()
        self._SPLUNK_SCHEMA = self.SPLUNK_SUBSCHEMA

    def _should_enable_correlation_search(
        self,
        tenant_setup: ConfigurationModels.Systems.Splunk.Tenant.Setup,
        mdr_config,
    ) -> bool:
        if mdr_config.correlation_search is not None:
            return mdr_config.correlation_search
        if hasattr(tenant_setup, "enterprise_security"):
            return tenant_setup.enterprise_security
        return self.CORRELATION_SEARCHES

    def _is_action_allowed(
        self,
        action: str,
        tenant_setup: ConfigurationModels.Systems.Splunk.Tenant.Setup,
    ) -> bool:
        es_enabled = getattr(tenant_setup, "enterprise_security", False)
        if action in ("notable", "risk"):
            return es_enabled
        return True

    def config_mdr(
        self,
        data: DetectionRule,
        tenant_setup: ConfigurationModels.Systems.Splunk.Tenant.Setup,
    ) -> dict[str, Any]:
        """Build savedsearches.conf attributes from a typed DetectionRule."""
        config: dict[str, Any] = {}
        splunk_config = data.configurations.splunk
        if not splunk_config:
            raise ValueError("Missing Splunk configuration in MDR")

        name = data.name.strip()
        uuid = data.metadata.uuid

        if splunk_config.scheduling:
            sched = splunk_config.scheduling
            if sched.type:
                if sched.type.lower() == "real time":
                    config["dispatch.earliest_time"] = "rt"
                    config["dispatch.latest_time"] = "rt"
                else:
                    config["is_scheduled"] = 1
            if sched.expires:
                config["alert.expires"] = sched.expires
            if sched.schedule:
                schedule = sched.schedule
                if schedule.cron:
                    config["cron_schedule"] = schedule.cron
                elif schedule.frequency:
                    custom_time = schedule.custom_time
                    if custom_time:
                        config["cron_schedule"] = cron_to_timeframe(
                            schedule.frequency, mode="custom", custom_time=custom_time
                        )
                    else:
                        config["cron_schedule"] = cron_to_timeframe(
                            schedule.frequency, mode=self.TIMERANGE_MODE
                        )
            if sched.timerange:
                tr = sched.timerange
                if tr.lookback:
                    config["dispatch.earliest_time"] = splunk_timerange(
                        tr.lookback, skewing=self.SKEWING_VALUE, offset=self.OFFSET
                    )
                if tr.earliest:
                    config["dispatch.earliest_time"] = tr.earliest
                if tr.latest:
                    config["dispatch.latest_time"] = tr.latest

        if splunk_config.trigger:
            trig = splunk_config.trigger
            if trig.condition:
                config["counttype"] = trig.condition
            if trig.comparator:
                config["relation"] = trig.comparator
            if trig.threshold is not None:
                config["quantity"] = trig.threshold
            if trig.severity is not None:
                config["alert.severity"] = trig.severity
            if trig.custom_condition:
                config["alert_condition"] = trig.custom_condition
            if trig.type:
                config["alert.digest_mode"] = "true" if trig.type.lower() == "once" else "false"
            if trig.throttling:
                throt = trig.throttling
                if throt.duration:
                    config["alert.suppress.period"] = throt.duration
                    config["alert.suppress"] = "true"
                if throt.fields:
                    config["alert.suppress.fields"] = ", ".join(throt.fields)
                if throt.group_name:
                    config["alert.suppress.group_name"] = throt.group_name

        if "alert.severity" not in config and data.response:
            alert_severity = data.response.alert_severity
            if alert_severity:
                config["alert.severity"] = self.ALERT_SEVERITY_MAPPING.get(alert_severity, 3)

        if check_status(splunk_config.status) is StatusStrategy.DISABLEMENT:
            config["disabled"] = "true"
            logger.info("configuring_saved_search_as_disabled")

        enable_correlation = self._should_enable_correlation_search(tenant_setup, splunk_config)
        if enable_correlation:
            config["action.correlationsearch.enabled"] = "true"
            config["action.correlationsearch.label"] = name + " - Rule"
            techniques = techniques_resolver(uuid)
            if techniques:
                config["action.correlationsearch.annotations.mitre_attack"] = ", ".join(techniques)

        if splunk_config.actions:
            acts = splunk_config.actions
            if acts.notable and self._is_action_allowed("notable", tenant_setup):
                notable = acts.notable
                if notable.event:
                    if notable.event.title:
                        config["action.notable.param.rule_title"] = notable.event.title
                    if notable.event.description:
                        config["action.notable.param.rule_description"] = notable.event.description
                if notable.drilldown:
                    if notable.drilldown.name:
                        config["action.notable.param.drilldown_name"] = notable.drilldown.name
                    if notable.drilldown.search:
                        config["action.notable.param.drilldown_search"] = notable.drilldown.search
                if notable.security_domain:
                    config["action.notable.param.security_domain"] = notable.security_domain.lower()
            if acts.risk and self._is_action_allowed("risk", tenant_setup):
                risk = acts.risk
                risk_config_list: list[dict[str, Any]] = []
                if risk.risk_objects:
                    for ro in risk.risk_objects:
                        risk_config_list.append(
                            {
                                "risk_object_field": ro.field,
                                "risk_object_type": ro.type,
                                "risk_score": ro.score,
                            }
                        )
                if risk.threat_objects:
                    for to in risk.threat_objects:
                        risk_config_list.append(
                            {"threat_object_field": to.field, "threat_object_type": to.type}
                        )
                if risk_config_list:
                    config["action.risk.param._risk"] = json.dumps(risk_config_list)
                if risk.message:
                    config["action.risk.param._risk_message"] = risk.message
            if acts.email:
                email = acts.email
                if email.to:
                    config["action.email.to"] = email.to
                if email.cc:
                    config["action.email.cc"] = email.cc
                if email.bcc:
                    config["action.email.bcc"] = email.bcc
                if email.priority:
                    config["action.email.priority"] = email.priority
                if email.subject:
                    config["action.email.subject"] = email.subject
                if email.message:
                    config["action.email.message.alert"] = email.message
                if email.content_type:
                    config["action.email.content_type"] = email.content_type
                if email.send_csv is not None:
                    config["action.email.sendcsv"] = 1 if email.send_csv else 0
                if email.send_pdf is not None:
                    config["action.email.sendpdf"] = 1 if email.send_pdf else 0
                if email.inline_results is not None:
                    config["action.email.inline"] = 1 if email.inline_results else 0
                if email.include:
                    inc = email.include
                    if inc.results_link is not None:
                        config["action.email.include.results_link"] = 1 if inc.results_link else 0
                    if inc.search_string is not None:
                        config["action.email.include.search"] = 1 if inc.search_string else 0
                    if inc.trigger_condition is not None:
                        config["action.email.include.trigger"] = 1 if inc.trigger_condition else 0
                    if inc.trigger_time is not None:
                        config["action.email.include.trigger_time"] = 1 if inc.trigger_time else 0

        responders = (data.response.responders if data.response else None) or ""
        config["alert.managedBy"] = responders
        if splunk_config.advanced:
            for key, value in splunk_config.advanced.items():
                config[key] = str(value)
        config["description"] = data.description or ""
        return config

    def _apply_flat_modifiers(
        self,
        *,
        mdr_config: dict[str, Any],
        status: str,
        tenant_config: ConfigurationModels.Systems.Splunk.Tenant,
        flags: Sequence[str] | None = None,
    ) -> list[str]:
        """Apply flat savedsearches.conf modifiers with correct precedence.

        Default modifiers fill gaps only; status/tenant overrides always win.
        Returns the allowed actions list after processing ``allowed_actions``.
        """
        status_allowed_actions = list(self.SPLUNK_ACTIONS)
        default_attributes: dict[str, Any] = {}
        override_attributes: dict[str, Any] = {}

        modifiers = self.STATUS_MODIFIERS or []
        if isinstance(modifiers, dict):
            # Legacy dict-keyed modifiers: treat as unconditional status overrides.
            legacy = dict(modifiers.get(status) or {})
            if legacy:
                override_attributes.update(legacy)
        else:
            for mod in modifiers:
                match = False
                is_default = mod.conditions.default is True

                if is_default:
                    match = True
                if mod.conditions.status and status in mod.conditions.status:
                    match = True
                if mod.conditions.tenants:
                    match = tenant_config.name in mod.conditions.tenants
                if mod.conditions.flags:
                    if flags and [tag for tag in flags if tag in mod.conditions.flags]:
                        match = True
                    else:
                        match = False

                if match:
                    logger.info(
                        "modifier_matched",
                        name=mod.name or "unnamed",
                        conditions=str(mod.conditions),
                    )
                    modifications = dict(mod.modifications or {})
                    if is_default:
                        default_attributes.update(modifications)
                    else:
                        override_attributes.update(modifications)

        for attrs in (default_attributes, override_attributes):
            if "allowed_actions" in attrs:
                allowed_actions_config = attrs.pop("allowed_actions")
                if allowed_actions_config in [False, None]:
                    logger.info("mdr_actions_disabled_in_splunk", status=status)
                    status_allowed_actions = []
                elif isinstance(allowed_actions_config, list):
                    status_allowed_actions = list(allowed_actions_config)

        for key, value in default_attributes.items():
            if key not in mdr_config:
                mdr_config[key] = value

        if override_attributes:
            logger.info(
                "status_modifiers_applied", status=status, modifiers=str(override_attributes)
            )
            mdr_config.update(override_attributes)

        return status_allowed_actions

    def _build_actions_config(
        self,
        mdr_config: dict[str, Any],
        name: str,
        mdr: DetectionRule,
        status_allowed_actions: list[str],
    ) -> dict[str, Any]:
        actions_config: dict[str, Any] = {}
        if not self.SPLUNK_ACTIONS:
            return actions_config
        triggered_actions: list[str] = []
        for action in self.SPLUNK_ACTIONS:
            for param in mdr_config:
                if "action." + action in param and action in status_allowed_actions:
                    triggered_actions.append(action)
                    actions_config["action." + action] = 1
                    break
        if not triggered_actions:
            triggered_actions = [
                action for action in self.SPLUNK_DEFAULT_ACTIONS if action in status_allowed_actions
            ]
        if triggered_actions:
            actions_config["actions"] = ", ".join(triggered_actions)
            if "notable" in triggered_actions:
                if "action.notable.param.rule_title" not in mdr_config:
                    actions_config["action.notable.param.rule_title"] = name
                    actions_config["action.notable.param.rule_description"] = mdr.description or ""
                    if mdr.response:
                        actions_config["action.notable.param.severity"] = (
                            mdr.response.alert_severity.lower()
                        )
                if security_domain := mdr_config.get("action.notable.param.security_domain"):
                    mdr_config["action.notable.param.security_domain"] = security_domain.lower()
            if "risk" in triggered_actions:
                actions_config["action.risk.param._risk_score"] = 0
        else:
            actions_config["actions"] = ""
        return actions_config

    def _apply_saved_search(
        self,
        *,
        service: Any,
        name: str,
        status: str,
        query: str,
        mdr_config: dict[str, Any],
        actions_config: dict[str, Any],
    ) -> bool | None:
        deploy_config = (self.DEFAULT_CONFIG or {}).copy()
        deploy_config.update(mdr_config)
        deploy_config.update(actions_config)
        deploy_config["search"] = query
        logger.info(
            "compiled_splunk_configuration", config=json.dumps(deploy_config, sort_keys=True)
        )
        second_stage_attributes = ["alert.suppress", "is_scheduled", "actions", "search"]
        second_stage: dict[str, Any] = {}
        for attribute in second_stage_attributes:
            if attribute in deploy_config:
                second_stage[attribute] = deploy_config.pop(attribute)
        try:
            selected_search = service.saved_searches[name]
            logger.info("found_existing_saved_search", name=name)
        except Exception:
            if check_status(status) is StatusStrategy.DELETION:
                logger.info("saved_search_already_absent", name=name)
                return None
            logger.info("creating_new_saved_search", name=name)
            selected_search = service.saved_searches.create(name, search=query)
        if check_status(status) is StatusStrategy.DELETION:
            service.saved_searches.delete(name)
            logger.warning("splunk_alert_deleted", name=name)
            return None
        if self.DEBUG_STEP:
            for key, value in deploy_config.items():
                logger.info("updating_saved_search_value", key=key, value=value)
                selected_search.update(**{key: value})
            for key, value in second_stage.items():
                logger.info("updating_saved_search_value", key=key, value=value)
                selected_search.update(**{key: value})
        else:
            selected_search.update(**deploy_config)
            if second_stage:
                selected_search.update(**second_stage)
        logger.info("deployed_on_splunk", name=name)
        return True

    def deploy_mdr(
        self,
        data: DetectionRule,
        service: Any,
        tenant_config: ConfigurationModels.Systems.Splunk.Tenant,
    ) -> bool | None:
        """Deploy a single typed MDR to Splunk."""
        splunk_config = data.configurations.splunk
        if not splunk_config:
            logger.info("mdr_skipped", mdr_name=data.name, reason="no Splunk configuration")
            return None

        tenant_setup = tenant_config.setup
        mdr_config = self.config_mdr(data, tenant_setup)
        name = data.name.strip()
        status = splunk_config.status or ""
        query = create_query(data)

        if self._should_enable_correlation_search(tenant_setup, splunk_config):
            name += " - Rule"

        status_allowed_actions = self._apply_flat_modifiers(
            mdr_config=mdr_config,
            status=status,
            tenant_config=tenant_config,
            flags=splunk_config.flags,
        )
        actions_config = self._build_actions_config(mdr_config, name, data, status_allowed_actions)
        return self._apply_saved_search(
            service=service,
            name=name,
            status=status,
            query=query,
            mdr_config=mdr_config,
            actions_config=actions_config,
        )

    def deploy(
        self,
        mdr_deployment: Sequence[DetectionRule] | list[str],
        deployment_plan: DeploymentStrategy | None = None,
    ) -> None:
        """Deploy Splunk MDRs through TideDeployment tenant routing."""
        if not deployment_plan:
            raise ValueError("deployment_plan is required for Splunk deployment")

        self.configure_proxy()
        loaded_mdr: list[DetectionRule] = []
        for mdr in mdr_deployment:
            if isinstance(mdr, str):
                loaded_mdr.append(OpenTide.Rules[mdr])
            elif isinstance(mdr, DetectionRule):
                loaded_mdr.append(mdr)

        if not loaded_mdr:
            logger.info("no_mdrs_to_deploy_for_splunk")
            return

        tide_deployment = TideDeployment(
            deployment=loaded_mdr,
            system=DetectionPlatforms.SPLUNK,
            strategy=deployment_plan,
        )
        for tenant_deployment in tide_deployment.rule_deployment:
            tenant = tenant_deployment.tenant
            logger.info("currently_targeting_tenant", tenant=tenant.name)
            service = connect_splunk(
                host=tenant.setup.url,
                port=tenant.setup.port,
                token=tenant.setup.token,
                app=tenant.setup.app,
                ssl_enabled=tenant.setup.ssl,
            )
            for mdr in tenant_deployment.rules:
                logger.info("processing_rule", mdr_name=mdr.name, uuid=mdr.metadata.uuid)
                self.deploy_mdr(data=mdr, service=service, tenant_config=tenant)


def declare():
    return SplunkDeploy()


if __name__ == "__main__" and DebugEnvironment.ENABLED:
    SplunkDeploy().deploy(DebugEnvironment.MDR_DEPLOYMENT_TEST_UUIDS, DeploymentStrategy.DEBUG)
