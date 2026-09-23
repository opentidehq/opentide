"""System information services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentide.cli.enums import DetectionPlatform, platform_label
from opentide.core.logging.config import get_stdout_console
from opentide.core.object_fields import matches_technique
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


def render_info(payload: dict[str, Any]) -> None:
    """Print the human view of :func:`collect_info`."""
    from rich.table import Table
    from rich.text import Text

    table = Table(title="OpenTide Info")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("Version", Text(str(payload["version"])))
    table.add_row("Rules", str(payload["counts"]["rules"]))
    table.add_row("Threats", str(payload["counts"]["threats"]))
    table.add_row("Objectives", str(payload["counts"]["objectives"]))
    for plat in payload["platforms"]:
        caps = []
        if plat["can_deploy"]:
            caps.append("deploy")
        if plat["can_validate"]:
            caps.append("validate")
        try:
            display_name = platform_label(DetectionPlatform(plat["name"]))
        except ValueError:
            display_name = plat["name"]
        table.add_row(
            Text(display_name),
            Text(f"enabled={plat['enabled']} [{', '.join(caps) or 'none'}]"),
        )
    get_stdout_console().print(table)


def _package_version() -> str:
    from opentide import __version__

    return __version__


def _technique_coverage(technique: str) -> dict[str, Any]:
    """Return rules referencing an ATT&CK technique."""
    needle = technique.strip()
    matching = [
        uuid for uuid, rule in OpenTide.Models.rules.items() if matches_technique(rule, needle)
    ]
    return {"technique": needle, "rules": matching, "count": len(matching)}
