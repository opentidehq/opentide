"""System information services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentide.cli.enums import DetectionPlatform
from opentide.core.registry import OpenTide
from opentide.platforms.enabled import enabled_systems

if TYPE_CHECKING:
    from opentide.cli.context import CliContext


def collect_info(
    ctx: CliContext,
    *,
    platform: DetectionPlatform | None = None,
    section: str | None = None,
    technique: str | None = None,
) -> dict[str, Any]:
    """Collect system information about the detection repository."""
    ctx.apply_environment()
    OpenTide.reload()
    enabled_platforms = set(enabled_systems())
    platforms_info = []
    for name, plat in OpenTide.Platforms.items():
        if platform is not None and name != platform.value:
            continue
        platforms_info.append(
            {
                "name": name,
                "enabled": name in enabled_platforms,
                "can_deploy": plat.can_deploy,
                "can_validate": plat.can_validate,
            }
        )
    payload: dict[str, Any] = {
        "version": _package_version(),
        "repo": str(ctx.repo),
        "counts": {
            "rules": len(OpenTide.Models.rules),
            "threats": len(OpenTide.Models.threats),
            "objectives": len(OpenTide.Models.objectives),
        },
        "platforms": platforms_info,
    }
    if section == "rules":
        payload["rules"] = list(OpenTide.Models.rules.keys())
    elif section == "threats":
        payload["threats"] = list(OpenTide.Models.threats.keys())
    elif section == "objectives":
        payload["objectives"] = list(OpenTide.Models.objectives.keys())
    elif section == "coverage" and technique:
        payload["coverage"] = _technique_coverage(technique)
    return payload


def _package_version() -> str:
    from opentide import __version__

    return __version__


def _technique_coverage(technique: str) -> dict[str, Any]:
    """Return rules referencing an ATT&CK technique."""
    matching: list[str] = []
    needle = technique.strip()
    for uuid, rule in OpenTide.Models.rules.items():
        body = rule if isinstance(rule, dict) else rule.model_dump(by_alias=True)
        if not isinstance(body, dict):
            continue
        tags = body.get("tags") if isinstance(body.get("tags"), dict) else {}
        techniques: list[Any] = []
        techniques.extend(body.get("techniques") or [])
        techniques.extend(tags.get("techniques") or [])
        techniques.extend(tags.get("attack") or [])
        if needle in {str(item) for item in techniques}:
            matching.append(uuid)
    return {"technique": needle, "rules": matching, "count": len(matching)}
