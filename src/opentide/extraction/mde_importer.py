"""Import Defender for Endpoint custom detection rules into opentide YAML.

Run through ``opentide generate extract defender``. Importing this module has no
side effects: it used to build a Tenant with an empty ``deployment`` at module
scope, which raised ``KeyError: ''`` before the CLI could report anything.
"""

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger
from opentide.core.registry import Opentide
from opentide.platforms.defender_for_endpoint.client import DefenderForEndpointService
from opentide.platforms.enabled import enable_platform_command
from opentide.states.deployment import record_external_id

logger = get_logger(__name__)


class DefenderForEndpointImporter(DefenderForEndpointService):
    #: Seconds to wait for one page of the rule listing.
    LIST_TIMEOUT = 60

    def list_rules(self) -> list[dict[str, Any]]:
        """Every custom detection rule of the tenant, across all result pages.

        Graph pages the listing with ``@odata.nextLink``. An error answer is
        raised, not read as an empty listing.
        """
        rules: list[dict[str, Any]] = []
        url: str | None = self.DETECTION_RULES_ENDPOINT
        while url:
            response = self.session.get(url, timeout=self.LIST_TIMEOUT)
            if not 200 <= response.status_code < 300:
                raise RuntimeError(
                    "Listing Defender for Endpoint detection rules on tenant "
                    f"{self.tenant_config.name} failed with HTTP {response.status_code} "
                    f"{response.reason}"
                )
            page = response.json()
            rules.extend(page.get("value") or [])
            url = page.get("@odata.nextLink")
        return rules


template = """
name: {name}
#references:
  #public:
    #1: 
  #internal:
    #a: 

metadata:
  uuid: {uuid}
  schema: rule::1.0
  version: 1
  created: {created}
  modified: {modified}
  tlp: amber+strict
  author: {author}
  #contributors:
    #-

description: |
{description}
#detection_model: 

response:
  alert_severity: {alert_severity}
  #playbook: https://
  #responders: 
  #procedure:

configurations:
  defender_for_endpoint: 
    schema: defender_for_endpoint::2.0
    status: {status}
    {contributors}
    tenants:
      - {tenants}
    #flags:
      #-
    
    scheduling: {schedule}
    
    alert:
      #title: 
      category: {category}{techniques}
      #severity: 
      {alert_recommendation}
    
    {impacted_entities_flag}impacted_entities:
      {impacted_device}
      #mailbox: 
      {impacted_user} 
    
    #actions:
    
      #devices:
        #isolate_device: 
        #collect_investigation_package: true
        #run_antivirus_scan: true
        #initiate_investigation: true
        #restrict_app_execution: true
    
      #files:
        #allow_block:
          #action: 
          #column: 
          #groups:
            #selection: 
            #device_groups:
              #-
        #quarantine_file: 
    
    scope:
      selection: All
      #device_groups:
        #-
    
    query: |
{query}
"""

no_contributors_template = """
    #contributors:
      #-
"""

contributors_template = """
    contributors:
      - {contributor}
"""

no_recommendation_template = """
      #recommendation: |
        #Type Here
"""

recommendation_template = """
      recommendation: |
{recommendation}
"""

techniques_template = """
      techniques:
        {techniques_list}
"""


def add_space_before_uppercase(s: str) -> str:
    result = ""
    for i, char in enumerate(s):
        if (
            char.isupper() and i > 0
        ):  # Add a space before uppercase letters, except the first character
            result += " "
        result += char
    return result


def sanitize_filename(name: str) -> str:
    invalid_chars = '<>:"/\\|?*'
    sanitized_name = ""
    for char in name:
        if char in invalid_chars:
            sanitized_name += " "
        else:
            sanitized_name += char
    return sanitized_name


def fix_multiline(string: str, indentation: int) -> str:
    lines = string.splitlines()
    fixed_lines = []
    for line in lines:
        if line.strip():
            fixed_lines.append(" " * indentation + line.strip())
    return "\n".join(fixed_lines)


def _render_rule(rule: dict[str, Any], tenant_names: Sequence[str]) -> tuple[str, str]:
    """Return the file name and YAML body for one Defender custom detection.

    The rule targets *tenant_names*, every tenant it was listed from: one
    detection deployed to several tenants is one opentide rule.
    """
    rule_name = rule["displayName"]
    rule_uuid = rule["detectorId"]
    rule_created = rule["createdDateTime"].split("T")[0]
    rule_modified = rule["lastModifiedDateTime"].split("T")[0]
    rule_severity = rule["detectionAction"].get("alertTemplate", {}).get("severity")
    rule_author = rule["createdBy"]
    rule_description = rule["detectionAction"].get("alertTemplate", {}).get("description")
    rule_schedule = rule["schedule"]["period"] if rule["schedule"]["period"] != "0" else "NRT"
    rule_category = add_space_before_uppercase(
        rule["detectionAction"].get("alertTemplate", {}).get("category")
    )
    rule_query = rule["queryCondition"].get("queryText")
    rule_status = "PRODUCTION" if rule.get("isEnabled") else "DISABLED"

    # Contributors resolution
    if rule["lastModifiedBy"] != rule_author:
        contributors = contributors_template.format(contributor=rule["lastModifiedBy"]).strip()
    else:
        contributors = no_contributors_template.strip()

    # Techniques, if added
    techniques = ""
    if t := rule["detectionAction"].get("alertTemplate", {}).get("mitreTechniques"):
        techniques_list = "- " + "\n        - ".join(t)
        techniques = techniques_template.format(techniques_list=techniques_list).rstrip()

    # Recommended actions, if added
    if not rule["detectionAction"].get("alertTemplate", {}).get("recommendedActions"):
        alert_recommendation = no_recommendation_template.strip()
    else:
        rule_description += "\n\n---\nRecommended Actions : " + rule["detectionAction"].get(
            "alertTemplate", {}
        ).get("recommendedActions")
        alert_recommendation = recommendation_template.format(
            recommendation=fix_multiline(
                rule["detectionAction"].get("alertTemplate", {}).get("recommendedActions"), 8
            )
        ).strip()

    # Impacted Assets
    impacted_device = "#device:"
    impacted_user = "#user:"
    impacted_entities_flag = "#"
    for impacted_asset in rule["detectionAction"]["alertTemplate"]["impactedAssets"]:
        if impacted_asset["@odata.type"].endswith("impactedDeviceAsset"):
            identifier = impacted_asset["identifier"]
            impacted_device = f"device: {identifier[0].upper() + identifier[1:]}"
            impacted_entities_flag = ""
        if impacted_asset["@odata.type"].endswith("impactedUserAsset"):
            identifier = impacted_asset["identifier"]
            impacted_user = f"user: {identifier[0].upper() + identifier[1:]}"
            impacted_entities_flag = ""

    body = template.format(
        # A JSON string is a valid YAML double-quoted scalar, so a `"` or `\`
        # in a name or tenant cannot end the string early.
        name=json.dumps(rule_name, ensure_ascii=False),
        tenants="\n      - ".join(json.dumps(name, ensure_ascii=False) for name in tenant_names),
        uuid=rule_uuid,
        created=rule_created,
        modified=rule_modified,
        alert_severity=rule_severity.title(),
        alert_recommendation=alert_recommendation,
        impacted_device=impacted_device,
        impacted_user=impacted_user,
        impacted_entities_flag=impacted_entities_flag,
        author=rule_author,
        contributors=contributors,
        description=fix_multiline(rule_description, 2),
        schedule=rule_schedule,
        category=rule_category,
        techniques=techniques,
        query=fix_multiline(rule_query, 6),
        status=rule_status,
    ).strip()
    return sanitize_filename(rule_name), body


def _import_defender_rules() -> None:
    tenants = Opentide.Configurations.Systems.DefenderForEndpoint.tenants
    if not tenants:
        logger.critical(
            "defender_tenants_not_configured",
            detail=(
                "You must first have Defender for Endpoint tenants configured to initiate the "
                "import"
            ),
            advice=f"run '{enable_platform_command('defender_for_endpoint')}'",
        )
        raise RuntimeError("No Defender for Endpoint tenants are configured")
    destination = Path("Imported")
    destination.mkdir(exist_ok=True)
    # One detection deployed to several tenants shares its detectorId: it is
    # one rule targeting all of them, rendered from the first tenant's copy.
    listed: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for tenant in tenants:
        for rule in DefenderForEndpointImporter(tenant).list_rules():
            listed.setdefault(rule["detectorId"], []).append((tenant.name, rule))
            # The Graph id is per tenant: deployment state, not rule content (RFC 0010).
            record_external_id(rule["detectorId"], "defender_for_endpoint", tenant.name, rule["id"])
    # Display names are not unique in Defender; never overwrite a file from this run.
    written: set[str] = set()
    for detector_id, copies in listed.items():
        names = [name for name, _rule in copies]
        first = copies[0][1]
        if any(_content(rule) != _content(first) for _name, rule in copies[1:]):
            logger.warning(
                "defender_import_tenants_differ",
                rule=first["displayName"],
                uuid=detector_id,
                detail=f"Imported from {names[0]}; the copies in {', '.join(names[1:])} differ",
            )
        filename, body = _render_rule(first, names)
        if filename.lower() in written:
            filename = f"{filename} {detector_id[:8]}"
        written.add(filename.lower())
        (destination / f"{filename}.yaml").write_text(body, encoding="utf-8")
        logger.info("imported_defender_rule", detail=filename, tenants=names)


def _content(rule: Mapping[str, Any]) -> tuple[object, ...]:
    """What makes two tenants' copies of one detection the same rule."""
    return (
        rule.get("displayName"),
        rule.get("isEnabled"),
        rule.get("schedule"),
        rule.get("queryCondition"),
        rule.get("detectionAction"),
    )


def run() -> None:
    """Entry point used by ``opentide generate extract defender``."""
    _import_defender_rules()


if __name__ == "__main__":
    run()
