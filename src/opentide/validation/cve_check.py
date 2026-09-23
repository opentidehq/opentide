"""CVE validation against CIRCL Vulnerability-Lookup."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger
from opentide.validation.issues import ValidationIssue
from opentide.validation.scope import ValidationScope
from opentide.vulnerability_lookup import (
    VulnerabilityLookupClient,
    VulnerabilityLookupError,
    apply_cve_proxy_settings,
    load_cve_settings,
    normalize_identifiers,
    page_url_for,
)

logger = get_logger(__name__)

THREAT_MODEL_FIELD = "threat"


def check_cve_issues(
    index: Mapping[str, Any],
    scope: ValidationScope | None = None,
    *,
    client: VulnerabilityLookupClient | None = None,
) -> list[ValidationIssue]:
    """Validate CVE references on threat vectors in *index*."""
    scope = scope or ValidationScope.full()
    settings = load_cve_settings()
    apply_cve_proxy_settings(settings)
    lookup = client or VulnerabilityLookupClient(settings)

    issues: list[ValidationIssue] = []
    threats = index.get("objects", {}).get("threat", {})
    files_index = index.get("files", {})
    file_paths = index.get("file_paths", {})

    for threat_id, threat_data in threats.items():
        threat_uuid = str(threat_data.get("metadata", {}).get("uuid") or threat_id)
        file_name = files_index.get(threat_uuid)
        raw_path = file_paths.get(threat_uuid)
        file_path = Path(raw_path) if raw_path else None
        if not scope.includes_object(
            threat_uuid, "threat", file_name=file_name, file_path=file_path
        ):
            continue

        cve_list = normalize_identifiers(threat_data.get(THREAT_MODEL_FIELD, {}).get("cve"))
        if not cve_list:
            continue

        broken: list[str] = []
        for cve in cve_list:
            try:
                record = lookup.get(cve)
            except VulnerabilityLookupError as exc:
                logger.warning(
                    "cve_lookup_unavailable",
                    cve=cve,
                    threat=threat_uuid,
                    detail=str(exc),
                )
                continue
            if record is None:
                logger.warning(
                    "cve_not_found_in_vulnerability_lookup",
                    cve=cve,
                    threat=threat_uuid,
                    url=page_url_for(cve, settings),
                )
                broken.append(cve)
                continue
            logger.debug(
                "cve_found_in_vulnerability_lookup",
                cve=cve,
                url=record.page_url,
            )

        if broken:
            issues.append(
                ValidationIssue(
                    code="invalid_cve",
                    severity="error",
                    object_uuid=threat_uuid,
                    object_type="threat",
                    file_path=file_path,
                    field_path=(THREAT_MODEL_FIELD, "cve"),
                    message=f"Invalid CVE references: {', '.join(broken)}",
                    suggestion="Confirm each identifier on Vulnerability-Lookup (https://vulnerability.circl.lu).",
                    context={"threat_id": threat_id, "broken_cve": broken},
                )
            )

    return issues
