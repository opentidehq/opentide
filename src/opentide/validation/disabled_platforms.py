"""Rule blocks for platforms the workspace has not enabled (#413).

Such a block is legal: rules travel between repositories, the platform model
still validates it, and deploy skips the platform (``system_disabled_for_deploy``).
``validate`` reports it so the author knows it will not deploy. The finding
does not fail ``--strict``, which the commit hook and generated CI run.
"""

from __future__ import annotations

from collections.abc import Mapping, Set
from typing import Any

from opentide.models.platform import PLATFORM_CONFIG_MODELS
from opentide.platforms.enabled import enable_platform_command
from opentide.validation.issues import ValidationIssue

PLATFORM_NOT_ENABLED = "platform_not_enabled"

#: Warning codes ``validate --strict`` reports without failing.
STRICT_EXEMPT_WARNINGS = frozenset({PLATFORM_NOT_ENABLED})


def platform_not_enabled_warnings(
    body: Mapping[str, Any],
    enabled: Set[str],
    *,
    object_uuid: str = "",
) -> list[ValidationIssue]:
    """One warning per registered platform block whose platform is not in *enabled*.

    An unknown key such as ``splnk`` is not a platform: the schema check fails it.
    """
    configurations = body.get("configurations")
    if not isinstance(configurations, Mapping):
        return []
    return [
        ValidationIssue(
            code=PLATFORM_NOT_ENABLED,
            severity="warning",
            object_uuid=object_uuid,
            object_type="rule",
            field_path=("configurations", platform),
            message=(
                f"{platform} is not enabled in this workspace, so this block will not "
                f"deploy until '{enable_platform_command(platform)}' enables it"
            ),
            context={"platform": platform},
        )
        for platform in configurations
        if platform in PLATFORM_CONFIG_MODELS and platform not in enabled
    ]
