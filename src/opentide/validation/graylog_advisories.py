"""``validate`` warnings for the Graylog advisories (graylog-1.0)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from opentide.validation.issues import ValidationIssue


def graylog_advisory_issues(
    body: Mapping[str, Any],
    *,
    object_uuid: str,
    object_type: str,
    file_path: Path | None,
) -> list[ValidationIssue]:
    """One warning per advisory of the rule's ``graylog`` block."""
    if object_type != "rule":
        return []
    configurations = body.get("configurations")
    if not isinstance(configurations, Mapping) or "graylog" not in configurations:
        return []
    from opentide.platforms.graylog.advisories import graylog_advisories

    return [
        ValidationIssue(
            code=advisory.code,
            severity="warning",
            object_uuid=object_uuid,
            object_type=object_type,
            file_path=file_path,
            field_path=advisory.field_path,
            message=advisory.message,
        )
        for advisory in graylog_advisories(body)
    ]
