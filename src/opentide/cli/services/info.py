"""System information services."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from opentide.cli.enums import DetectionPlatform, platform_label
from opentide.cli.ui.glyphs import glyph
from opentide.core.index_manager import IndexManager
from opentide.core.logging.config import get_stdout_console
from opentide.core.object_fields import as_body, matches_technique, object_platforms
from opentide.core.registry import Opentide
from opentide.platforms.enabled import enabled_systems
from opentide.registry.builder import parse_errors_reported_by_caller

if TYPE_CHECKING:
    from rich.table import Table

    from opentide.cli.context import CliContext

#: Human titles for the object sections, keyed by section and ``Opentide.Models`` family.
_SECTION_TITLES = {"rules": "Rules", "threats": "Threats", "objectives": "Objectives"}


def collect_info(
    ctx: CliContext,
    *,
    platform: DetectionPlatform | None = None,
    section: str | None = None,
    technique: str | None = None,
) -> dict[str, Any]:
    """Collect system information about the detection repository."""
    ctx.apply_environment()
    # Each unreadable file is counted in the table and the outcome line, and
    # `opentide validate` says why; logging it as well would say it twice.
    with parse_errors_reported_by_caller():
        Opentide.reload()
    parse_errors = list(IndexManager.load().get("parse_errors") or [])
    enabled_platforms = set(enabled_systems())
    platforms_info = []
    for name, plat in Opentide.Platforms.items():
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
            "rules": len(Opentide.Models.rules),
            "threats": len(Opentide.Models.threats),
            "objectives": len(Opentide.Models.objectives),
        },
        "parse_error_count": len(parse_errors),
        "platforms": platforms_info,
    }
    if section == "rules":
        payload["rules"] = list(Opentide.Models.rules.keys())
    elif section == "threats":
        payload["threats"] = list(Opentide.Models.threats.keys())
    elif section == "objectives":
        payload["objectives"] = list(Opentide.Models.objectives.keys())
    elif section == "coverage" and technique:
        payload["coverage"] = _technique_coverage(technique)
    return payload


#: Singular nouns of the counts on the outcome line, in order.
_COUNT_NOUNS = (("rules", "rule"), ("threats", "threat"), ("objectives", "objective"))


def info_summary(payload: dict[str, Any]) -> dict[str, int]:
    """Counts behind the outcome line: objects by family, and files that failed to load."""
    counts = payload.get("counts") or {}
    summary = {family: int(counts.get(family) or 0) for family, _ in _COUNT_NOUNS}
    summary["load_errors"] = int(payload.get("parse_error_count") or 0)
    return summary


def info_outcome(summary: dict[str, int]) -> str:
    """``1 rule · 1 threat · 1 objective · 0 load errors``."""

    def counted(count: int, noun: str) -> str:
        return f"{count} {noun}" if count == 1 else f"{count} {noun}s"

    parts = [counted(summary.get(family, 0), noun) for family, noun in _COUNT_NOUNS]
    parts.append(counted(summary.get("load_errors", 0), "load error"))
    return f" {glyph('separator')} ".join(parts)


def render_info(payload: dict[str, Any], *, section: str | None = None) -> None:
    """Print the human view of :func:`collect_info`: the section asked for, else the summary."""
    console = get_stdout_console()
    if section == "coverage":
        coverage = payload["coverage"]
        count = coverage["count"]
        console.print(
            f"Coverage for {coverage['technique']}: {count} rule{'' if count == 1 else 's'}",
            markup=False,
        )
        if coverage["rules"]:
            console.print(_objects_table("rules", coverage["rules"]))
    elif section in _SECTION_TITLES:
        uuids = payload[section]
        if uuids:
            console.print(_objects_table(section, uuids))
        else:
            console.print(f"No {section} found")
    else:
        console.print(_summary_table(payload))


def _summary_table(payload: dict[str, Any]) -> Table:
    from rich.table import Table
    from rich.text import Text

    table = Table(title="opentide Info")
    table.add_column("Key")
    table.add_column("Value")
    table.add_row("Version", Text(str(payload["version"])))
    for family, title in _SECTION_TITLES.items():
        table.add_row(title, str(payload["counts"][family]))
    table.add_row("Parse errors", str(payload.get("parse_error_count", 0)))
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
        # "enabled · deploy, validate": the reader's words, not a Python repr.
        state = "enabled" if plat["enabled"] else "disabled"
        separator = f" {glyph('separator', get_stdout_console().file)} "
        table.add_row(Text(display_name), Text(f"{state}{separator}{', '.join(caps) or 'none'}"))
    return table


def _objects_table(family: str, uuids: list[str]) -> Table:
    """UUID and name per object; rules also list the platforms they configure."""
    from rich.table import Table
    from rich.text import Text

    objects = getattr(Opentide.Models, family)
    table = Table(title=f"{_SECTION_TITLES[family]} ({len(uuids)})")
    table.add_column("UUID", no_wrap=True, min_width=36)
    table.add_column("Name", overflow="fold")
    if family == "rules":
        table.add_column("Platforms", overflow="fold")
    for uuid in uuids:
        body = as_body(objects.get(uuid))
        row = [Text(uuid), Text(str(body.get("name") or ""))]
        if family == "rules":
            row.append(Text(", ".join(sorted(object_platforms(body)))))
        table.add_row(*row)
    return table


def _package_version() -> str:
    from opentide import __version__

    return __version__


def _technique_coverage(technique: str) -> dict[str, Any]:
    """Return rules referencing an ATT&CK technique."""
    needle = technique.strip()
    matching = [
        uuid for uuid, rule in Opentide.Models.rules.items() if matches_technique(rule, needle)
    ]
    return {"technique": needle, "rules": matching, "count": len(matching)}
