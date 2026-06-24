"""CVE validation against public vulnerability databases."""

from __future__ import annotations

import importlib
from collections.abc import Mapping
from typing import Any

from opentide.core.logging import get_logger
from opentide.validation.issues import ValidationIssue
from opentide.validation.scope import ValidationScope

logger = get_logger(__name__)

THREAT_MODEL_FIELD = "threat"


def _apply_cve_proxy_settings() -> None:
    from opentide.core.registry import OpenTide
    from opentide.deployment.utils import Proxy

    if OpenTide.Configurations.Documentation.cve.get("proxy"):
        Proxy.set_proxy()
    else:
        Proxy.unset_proxy()


def check_cve_issues(
    index: Mapping[str, Any],
    scope: ValidationScope | None = None,
) -> list[ValidationIssue]:
    """Validate CVE references on threat vectors in *index*."""
    try:
        crawler = importlib.import_module("mitrecve.crawler")
    except ImportError:
        logger.warning("cve_check_skipped", detail="mitrecve package not installed")
        return []

    scope = scope or ValidationScope.full()
    _apply_cve_proxy_settings()

    issues: list[ValidationIssue] = []
    threats = index.get("objects", {}).get("threat", {})
    files_index = index.get("files", {})

    for threat_id, threat_data in threats.items():
        threat_uuid = str(threat_data.get("metadata", {}).get("uuid") or threat_id)
        file_name = files_index.get(threat_uuid)
        if not scope.includes_object(threat_uuid, "threat", file_name=file_name):
            continue

        cve_list = threat_data.get(THREAT_MODEL_FIELD, {}).get("cve")
        if not cve_list:
            continue

        broken: list[str] = []
        for cve in cve_list:
            try:
                crawler.get_cve_detail(crawler.get_main_page(cve))
                logger.debug("cve_found_in_nvd", cve=cve)
            except Exception:
                logger.warning("cve_not_found_in_nvd", cve=cve, threat=threat_uuid)
                broken.append(str(cve))

        if broken:
            issues.append(
                ValidationIssue(
                    code="invalid_cve",
                    severity="error",
                    object_uuid=threat_uuid,
                    object_type="threat",
                    field_path=(THREAT_MODEL_FIELD, "cve"),
                    message=f"Invalid CVE references: {', '.join(broken)}",
                    context={"threat_id": threat_id, "broken_cve": broken},
                )
            )

    return issues
