import json
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

import requests
import structlog
import yaml

from opentide.core.debug import DebugEnvironment
from opentide.core.errors import Errors
from opentide.core.registry import Opentide
from opentide.models.system_config import ConfigurationModels
from opentide.platforms.transport import TenantSession, tenant_tls_verify

logger = structlog.get_logger("opentide.platforms.harfanglab.client")


class GlobalState(Enum):
    """HarfangLab global_state values"""

    ALERT = "alert"
    BACKEND_ALERT = "backend_alert"
    BLOCK = "block"
    DISABLED = "disabled"
    QUARANTINE = "quarantine"


class HLStatus(Enum):
    """HarfangLab hl_status (maturity) values"""

    EXPERIMENTAL = "experimental"
    TESTING = "testing"
    STABLE = "stable"


class ConfidenceLevel(Enum):
    """HarfangLab rule_confidence_override values"""

    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"


class LevelOverride(Enum):
    """HarfangLab rule_level_override values"""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def remove_none_values(data: dict) -> dict:
    """Recursively remove None values from dictionaries"""
    if isinstance(data, dict):
        return {k: remove_none_values(v) for k, v in data.items() if v is not None}
    elif isinstance(data, list):
        return [remove_none_values(v) for v in data if v is not None]
    else:
        return data


@dataclass
class SigmaRule:
    """
    Dataclass representing a HarfangLab Sigma rule for the API.
    Maps opentide's HarfangLab configuration to HarfangLab's API format.
    """

    name: str
    content: str
    source_id: str
    enabled: bool = True
    global_state: str = "alert"
    hl_status: str = "experimental"
    block_on_agent: bool = False
    quarantine_on_agent: bool = False
    rule_confidence_override: str | None = None
    rule_level_override: str | None = None
    overwrite: bool = False


@dataclass
class YaraRule:
    """
    Dataclass representing a HarfangLab YARA rule for the API.
    Simplified to match the working API payload structure.
    """

    name: str
    content: str
    source_id: str
    global_state: str = "alert"
    hl_status: str = "experimental"
    rule_confidence_override: str | None = None
    rule_level_override: str | None = None


#: Keep each scalar on one line, as a Sigma rule written by hand has it.
_NO_LINE_WRAP = 1 << 30


class _SigmaDumper(yaml.SafeDumper):
    """Writes Sigma rules as they are written by hand.

    Lists are indented under their key, and a multi-line string is a ``|``
    block.
    """

    def increase_indent(self, flow: bool = False, indentless: bool = False) -> None:
        return super().increase_indent(flow, False)


def _represent_str(dumper: yaml.SafeDumper, value: str) -> yaml.ScalarNode:
    style = "|" if "\n" in value else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)


_SigmaDumper.add_representer(str, _represent_str)


class SigmaRuleBuilder:
    """
    Builds a Sigma-compliant YAML string from opentide's selection-based format.
    Transforms the opentide format to standard Sigma format.
    """

    @staticmethod
    def build_sigma_yaml(
        title: str,
        description: str,
        rule_id: str,
        logsource_category: str,
        logsource_product: str,
        selections: list,
        condition: str,
        level: str = "medium",
        status: str = "experimental",
        tags: list | None = None,
        false_positives: list | None = None,
        author: str | None = None,
        references: list | None = None,
    ) -> str:
        """
        Build a Sigma-compliant YAML string from structured components.

        Args:
            title: Rule title
            description: Rule description
            rule_id: Unique rule identifier (UUID)
            logsource_category: Log source category (e.g., process_creation)
            logsource_product: Log source product (e.g., windows)
            selections: List of selection dictionaries with name, field, modifiers, value
            condition: Boolean condition combining selections
            level: Criticality level
            status: Rule status (experimental, testing, stable)
            tags: List of tags (MITRE ATT&CK, etc.)
            false_positives: List of known false positive scenarios
            author: Rule author
            references: List of reference URLs

        Returns:
            A Sigma-compliant YAML string
        """
        rule: dict[str, Any] = {"title": title, "id": rule_id}
        if description:
            rule["description"] = description
        if author:
            rule["author"] = author
        if references:
            rule["references"] = list(references)
        rule["status"] = status
        if tags:
            rule["tags"] = list(tags)
        rule["logsource"] = {"category": logsource_category, "product": logsource_product}
        detection: dict[str, Any] = {}
        for selection in selections:
            field_with_modifiers = "|".join(
                [selection.get("field", ""), *(selection.get("modifiers") or [])]
            )
            # Entries sharing a selection name are fields of that one selection.
            detection.setdefault(selection.get("name", "selection"), {})[field_with_modifiers] = (
                selection.get("value", [])
            )
        detection["condition"] = condition
        rule["detection"] = detection
        if false_positives:
            rule["falsepositives"] = list(false_positives)
        rule["level"] = level
        # Built by hand, a title such as "Mimikatz: sekurlsa" or a value with a
        # quote was invalid YAML, and the value yes read as true.
        return yaml.dump(
            rule,
            Dumper=_SigmaDumper,
            sort_keys=False,
            allow_unicode=True,
            indent=4,
            width=_NO_LINE_WRAP,
        )


class HarfangLabService:
    """
    Interface to connect and deploy MDRs to HarfangLab.
    Initialized on a single tenant basis.
    """

    def __init__(self, tenant_config: ConfigurationModels.Systems.HarfangLab.Tenant) -> None:
        self.DEBUG = DebugEnvironment.ENABLED
        self.DEPLOYER_IDENTIFIER = Opentide.Configurations.Systems.HarfangLab.platform.identifier
        self.tenant_config = tenant_config
        self.verify = tenant_tls_verify(
            tenant_config.setup.ssl, platform="harfanglab", tenant=tenant_config.name
        )
        base_url = self.tenant_config.setup.url.rstrip("/")
        self.SIGMA_RULES_ENDPOINT = f"{base_url}/api/data/threat_intelligence/SigmaRule/"
        self.YARA_RULES_ENDPOINT = f"{base_url}/api/data/threat_intelligence/YaraFile/"
        self.session = TenantSession(verify=self.verify)
        self.session.headers.update(
            {
                "Authorization": f"Token {self.tenant_config.setup.api_token}",
                "Content-Type": "application/json",
            }
        )

    def _http_errors(self, response: requests.Response, error):
        """Handle HTTP errors from HarfangLab API"""
        match response.status_code:
            case 400:
                logger.critical("received_code_400_invalid_request", detail=str(response.text))
                raise error
            case 401:
                logger.critical(
                    "received_code_401_unauthorized_access",
                    detail=str(response.text),
                    advice="Check your API token configuration",
                )
                raise Errors.TideTenantConfigurationMissingPermissions
            case 403:
                logger.critical(
                    "received_code_403_forbidden",
                    detail=str(response.text),
                    advice="Check your API permissions",
                )
                raise Errors.TideTenantConfigurationMissingPermissions
            case 404:
                logger.critical("fatal_error", detail=str(response.text))
                raise error
            case _:
                logger.critical(
                    "fatal_error",
                    detail=f"Unforeseen error with code [{response.status_code}]",
                    context=str(response.text),
                )
                raise error

    def create_sigma_rule(self, rule: SigmaRule) -> str:
        """
        Create a new Sigma rule in HarfangLab.

        Args:
            rule: SigmaRule dataclass with rule details

        Returns:
            The rule ID assigned by HarfangLab
        """
        rule_body = remove_none_values(asdict(rule))
        rule_body = json.dumps(rule_body)
        logger.info("creating_sigma_rule_in_harfanglab", detail=rule.name)
        response = self.session.post(
            url=self.SIGMA_RULES_ENDPOINT, data=rule_body, verify=self.verify
        )
        if response.status_code in [200, 201]:
            logger.info("step_completed", detail=f"Created Sigma rule: {rule.name}")
            try:
                response_data = response.json()
                rule_id = response_data.get("id") or response_data.get("source_id")
                return str(rule_id)
            except (KeyError, ValueError, json.JSONDecodeError) as e:
                logger.warning("could_not_extract_rule_id_from_response", detail=str(e))
                return rule.source_id
        else:
            self._http_errors(response, Errors.DetectionRuleCreationFailed)
            raise Errors.DetectionRuleCreationFailed

    def update_sigma_rule(self, rule: SigmaRule, rule_id: str) -> None:
        """
        Update an existing Sigma rule in HarfangLab.

        Args:
            rule: SigmaRule dataclass with updated rule details
            rule_id: The HarfangLab rule ID to update
        """
        rule_body = remove_none_values(asdict(rule))
        rule_body["overwrite"] = True
        rule_body = json.dumps(rule_body)
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        logger.info(
            "step_in_progress",
            detail=f"Updating Sigma rule {rule_id} in HarfangLab",
            context_1=rule.name,
        )
        response = self.session.put(url=endpoint, data=rule_body, verify=self.verify)
        if response.status_code == 200:
            logger.info(
                "step_completed", detail=f"Updated Sigma rule: {rule.name}", context=str(rule_id)
            )
        else:
            self._http_errors(response, Errors.DetectionRuleUpdateFailed)

    def delete_sigma_rule(self, rule_id: str) -> None:
        """
        Delete a Sigma rule from HarfangLab.

        Args:
            rule_id: The HarfangLab rule ID to delete
        """
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        logger.info("deleting_sigma_rule_from_harfanglab", detail=str(rule_id))
        response = self.session.delete(url=endpoint, verify=self.verify)
        if response.status_code in [200, 204]:
            logger.info("step_completed", detail=f"Deleted Sigma rule with ID {rule_id}")
        else:
            self._http_errors(response, Errors.DetectionRuleDeletionFailed)

    def disable_sigma_rule(self, rule_id: str) -> None:
        """
        Disable a Sigma rule in HarfangLab by setting global_state to disabled.

        Args:
            rule_id: The HarfangLab rule ID to disable
        """
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        update_body = json.dumps({"global_state": "disabled", "enabled": False})
        logger.info("disabling_sigma_rule_in_harfanglab", detail=str(rule_id))
        response = self.session.patch(url=endpoint, data=update_body, verify=self.verify)
        if response.status_code == 200:
            logger.info("step_completed", detail=f"Disabled Sigma rule with ID {rule_id}")
        else:
            self._http_errors(response, Errors.DetectionRuleDisablingFailed)

    @staticmethod
    def map_action_to_global_state(action: str) -> str:
        """
        Map opentide action values to HarfangLab global_state values.

        Args:
            action: opentide action string (Alert, Alert & Block, etc.)

        Returns:
            HarfangLab global_state value
        """
        action_mapping = {
            "Alert": "alert",
            "Alert & Block": "block",
            "Alert, Block & Quarantine": "quarantine",
        }
        return action_mapping.get(action, "alert")

    @staticmethod
    def map_maturity_to_hl_status(maturity: str) -> str:
        """
        Map opentide maturity values to HarfangLab hl_status values.

        Args:
            maturity: opentide maturity string (Stable, Testing, Experimental)

        Returns:
            HarfangLab hl_status value
        """
        maturity_mapping = {
            "Stable": "stable",
            "Testing": "testing",
            "Experimental": "experimental",
        }
        return maturity_mapping.get(maturity, "experimental")

    @staticmethod
    def map_confidence(confidence: str) -> str:
        """
        Map opentide confidence values to HarfangLab rule_confidence_override values.

        Args:
            confidence: opentide confidence string (Weak, Moderate, Strong)

        Returns:
            HarfangLab rule_confidence_override value
        """
        confidence_mapping = {"Weak": "weak", "Moderate": "moderate", "Strong": "strong"}
        return confidence_mapping.get(confidence, "moderate")

    @staticmethod
    def map_level(level: str) -> str:
        """
        Map alert severity to HarfangLab rule_level_override values.

        Args:
            level: Alert severity (Informational, Low, Medium, High, Critical)

        Returns:
            HarfangLab rule_level_override value
        """
        level_mapping = {
            "Informational": "informational",
            "Low": "low",
            "Medium": "medium",
            "High": "high",
            "Critical": "critical",
        }
        return level_mapping.get(level, "medium")

    def create_or_update_sigma_rule(self, rule: SigmaRule, rule_id: str) -> None:
        """
        Create or update a Sigma rule in HarfangLab using the MDR UUID as the rule ID.
        Uses PUT with overwrite=True to handle both create and update cases.

        Args:
            rule: SigmaRule dataclass with rule details
            rule_id: The MDR UUID to use as the rule identifier
        """
        rule_body = remove_none_values(asdict(rule))
        rule_body["overwrite"] = True
        rule_body = json.dumps(rule_body)
        logger.info(
            "creating_updating_sigma_rule_in_harfanglab", detail=rule.name, advice=str(rule_id)
        )
        endpoint = f"{self.SIGMA_RULES_ENDPOINT}{rule_id}/"
        response = self.session.put(url=endpoint, data=rule_body, verify=self.verify)
        if response.status_code == 200:
            logger.info(
                "step_completed", detail=f"Updated Sigma rule: {rule.name}", context=str(rule_id)
            )
            return
        if response.status_code == 404:
            response = self.session.post(
                url=self.SIGMA_RULES_ENDPOINT, data=rule_body, verify=self.verify
            )
            if response.status_code in [200, 201]:
                logger.info(
                    "step_completed",
                    detail=f"Created Sigma rule: {rule.name}",
                    context=str(rule_id),
                )
                return
        self._http_errors(response, Errors.DetectionRuleCreationFailed)

    def create_or_update_yara_rule(self, rule: YaraRule, rule_id: str) -> None:
        """
        Create or update a YARA rule in HarfangLab using the MDR UUID as the rule ID.

        Args:
            rule: YaraRule dataclass with rule details
            rule_id: The MDR UUID to use as the rule identifier
        """
        rule_body = asdict(rule)
        rule_body["overwrite"] = True
        logger.debug(
            "yara_api_request_body_excluding_content",
            detail=json.dumps({k: v for k, v in rule_body.items() if k != "content"}, indent=2),
        )
        logger.debug("yara_rule_content_preview", detail=rule_body.get("content", "")[:500])
        rule_body_json = json.dumps(rule_body)
        logger.info(
            "creating_updating_yara_rule_in_harfanglab", detail=rule.name, advice=str(rule_id)
        )
        logger.debug("post_to", detail=self.YARA_RULES_ENDPOINT)
        response = self.session.post(
            url=self.YARA_RULES_ENDPOINT, data=rule_body_json, verify=self.verify
        )
        logger.debug(
            "event",
            detail=f"POST response [{response.status_code}]:",
            context_1=response.text[:1000] if response.text else "empty",
        )
        if response.status_code in [200, 201]:
            logger.info(
                "step_completed",
                detail=f"Created/Updated YARA rule: {rule.name}",
                context=str(rule_id),
            )
            return
        self._http_errors(response, Errors.DetectionRuleCreationFailed)

    def delete_yara_rule(self, rule_id: str) -> None:
        """
        Delete a YARA rule from HarfangLab.

        Args:
            rule_id: The HarfangLab rule ID to delete
        """
        endpoint = f"{self.YARA_RULES_ENDPOINT}{rule_id}/"
        logger.info("deleting_yara_rule_from_harfanglab", detail=str(rule_id))
        response = self.session.delete(url=endpoint, verify=self.verify)
        if response.status_code in [200, 204]:
            logger.info("step_completed", detail=f"Deleted YARA rule with ID {rule_id}")
        else:
            self._http_errors(response, Errors.DetectionRuleDeletionFailed)
