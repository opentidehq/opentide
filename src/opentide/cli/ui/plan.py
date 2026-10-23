"""The deploy plan as a person reads it: a header, then one row per rule per tenant.

::

    Deploy plan · strategy PREVIEW · dry run, nothing is sent

    sentinel · 0 tenants
      + create or update  Sentinel KQL Rule  …000000000001  status STAGING

The tally that follows is the command's outcome line (``Plan: 1 to create, …``),
printed from its result. ``json`` and ``mcp`` never reach this module: the
result's ``changes`` carries the same rows.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from rich.console import Console, Group, RenderableType
from rich.padding import Padding
from rich.table import Table
from rich.text import Text

from opentide.cli.ui.glyphs import glyph
from opentide.cli.ui.progress import plural

#: Action → (glyph name, label, style).
_ROWS: dict[str, tuple[str, str, str]] = {
    "create": ("create", "create", "bold green"),
    "update": ("update", "update", "bold yellow"),
    "upsert": ("create", "create or update", "bold green"),
    "disable": ("disable", "disable", "bold magenta"),
    "delete": ("delete", "delete", "bold red"),
}


def _short_uuid(uuid: str) -> str:
    return f"…{uuid[-12:]}" if len(uuid) > 12 else uuid


def plan_view(
    changes: Sequence[Mapping[str, Any]],
    *,
    strategies: Sequence[str] = (),
    tenants: Mapping[str, Mapping[str, Sequence[str]]] | None = None,
    encoding: str = "utf-8",
) -> RenderableType:
    """The plan grouped by platform, then tenant. *changes* are ``PlannedChange.to_dict()`` rows."""
    separator = f" {glyph('separator', encoding=encoding)} "
    header = Text("Deploy plan", style="bold")
    if strategies:
        header.append(separator + "strategy ", style="dim")
        header.append(" ".join(strategies), style="bold")
    header.append(separator + "dry run, nothing is sent", style="dim")
    parts: list[RenderableType] = [header]
    platforms: dict[str, list[Mapping[str, Any]]] = {}
    for change in changes:
        platforms.setdefault(str(change["platform"]), []).append(change)
    for platform, rows in platforms.items():
        tenant_names = sorted({str(row["tenant"]) for row in rows if row.get("tenant")})
        configured = len((tenants or {}).get(platform, {})) or len(tenant_names)
        parts.append(Text())
        parts.append(
            Text.assemble(
                (platform, "bold"),
                (separator + plural(configured, "tenant"), "dim"),
            )
        )
        groups: dict[str | None, list[Mapping[str, Any]]] = {}
        for row in rows:
            groups.setdefault(row.get("tenant"), []).append(row)
        for tenant, members in groups.items():
            if tenant is not None:
                parts.append(Text.assemble(("  ", ""), (str(tenant), "bold")))
            grid = Table.grid(padding=(0, 2))
            grid.add_column(no_wrap=True)
            grid.add_column(style="bold")
            grid.add_column(style="dim", no_wrap=True)
            grid.add_column(style="dim", no_wrap=True)
            for row in members:
                name, label, style = _ROWS.get(str(row["action"]), _ROWS["upsert"])
                grid.add_row(
                    Text(f"{glyph(name, encoding=encoding)} {label}", style=style),
                    Text(str(row.get("name") or row["uuid"])),
                    _short_uuid(str(row["uuid"])),
                    f"status {row['status']}" if row.get("status") else "",
                )
            parts.append(Padding(grid, (0, 0, 0, 4 if tenant is not None else 2), expand=False))
    parts.append(Text())
    return Group(*parts)


def render_plan(console: Console, payload: Mapping[str, Any]) -> None:
    """Print the plan of a dry-run deploy result, when it planned anything."""
    changes = payload.get("changes")
    if not isinstance(changes, list) or not changes:
        return
    console.print(
        plan_view(
            changes,
            strategies=[str(item) for item in payload.get("strategies") or ()],
            tenants=payload.get("tenants") if isinstance(payload.get("tenants"), dict) else None,
            encoding=console.encoding or "utf-8",
        ),
        soft_wrap=True,
    )
