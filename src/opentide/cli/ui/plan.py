"""The deploy plan as a person reads it: a header, then one row per rule per tenant.

::

    Deploy plan · strategy PREVIEW · 1 platform, 0 tenants · dry run, nothing is sent

    sentinel · 0 tenants
      + create or update  Sentinel KQL Rule  …000000000001  status STAGING

A rule that would fail to deploy prints next, as ``error[code]: message`` and
its file. The tally that follows is the command's outcome line (``Plan: 1 to
create, …``), printed from its result. ``json`` and ``mcp`` never reach this
module: the result's ``changes`` and ``diagnostics`` carry the same rows.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

from rich.console import Console, Group, RenderableType
from rich.text import Text

from opentide.cli.ui.glyphs import can_encode, glyph
from opentide.cli.ui.layout import columns
from opentide.cli.ui.progress import plural

if TYPE_CHECKING:
    from opentide.cli.ui.diagnostics import Diagnostic

#: Action → (glyph name, label, style).
_ROWS: dict[str, tuple[str, str, str]] = {
    "create": ("create", "create", "bold green"),
    "update": ("update", "update", "bold yellow"),
    "upsert": ("create", "create or update", "bold green"),
    "disable": ("disable", "disable", "bold magenta"),
    "delete": ("delete", "delete", "bold red"),
}


def short_uuid(uuid: str, encoding: str = "utf-8") -> str:
    """The UUID's tail, after ``…`` (``...`` on a stream that cannot encode it)."""
    if len(uuid) <= 12:
        return uuid
    return ("…" if can_encode("…", encoding=encoding) else "...") + uuid[-12:]


def plan_view(
    changes: Sequence[Mapping[str, Any]],
    *,
    strategies: Sequence[str] = (),
    tenants: Mapping[str, Mapping[str, Sequence[str]]] | None = None,
    scope: str | None = None,
    encoding: str = "utf-8",
) -> RenderableType:
    """The plan grouped by platform, then tenant. *changes* are ``PlannedChange.to_dict()`` rows.

    *scope* (``1 platform, 1 tenant``) goes on the header, which keeps the
    tally that follows the plan within 100 columns.
    """
    separator = f" {glyph('separator', encoding=encoding)} "
    header = Text("Deploy plan", style="bold")
    if strategies:
        header.append(separator + "strategy ", style="dim")
        header.append(" ".join(strategies), style="bold")
    if scope:
        header.append(separator + scope, style="dim")
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
            rows = []
            for row in members:
                name, label, style = _ROWS.get(str(row["action"]), _ROWS["upsert"])
                if row.get("fails"):
                    # Its frame prints below; the row must not promise a create.
                    name, label, style = "failed", "would fail", "bold red"
                rows.append(
                    (
                        Text(f"{glyph(name, encoding=encoding)} {label}", style=style),
                        Text(str(row.get("name") or row["uuid"]), style="bold"),
                        Text(short_uuid(str(row["uuid"]), encoding), style="dim"),
                        Text(f"status {row['status']}" if row.get("status") else "", style="dim"),
                    )
                )
            parts.append(columns(rows, indent=4 if tenant is not None else 2))
    parts.append(Text())
    return Group(*parts)


def render_plan(console: Console, payload: Mapping[str, Any]) -> None:
    """Print the plan of a dry-run deploy result, when it planned anything."""
    changes = payload.get("changes")
    if not isinstance(changes, list) or not changes:
        return
    summary = payload.get("_summary")
    scope = None
    if isinstance(summary, Mapping) and "platforms" in summary and "tenants" in summary:
        from opentide.cli.services.deploy_plan import plan_scope

        scope = plan_scope(int(summary["platforms"]), int(summary["tenants"]))
    from rich.text import Text

    from opentide.cli.ui.render import print_block

    view = plan_view(
        changes,
        strategies=[str(item) for item in payload.get("strategies") or ()],
        tenants=payload.get("tenants") if isinstance(payload.get("tenants"), dict) else None,
        scope=scope,
        encoding=console.encoding or "utf-8",
    )
    # A row wider than the terminal continues under itself, between words (B44).
    from rich.console import Group

    for part in view.renderables if isinstance(view, Group) else [view]:
        if isinstance(part, Text):
            print_block(console, part, hang=4)
        else:
            console.print(part, soft_wrap=True)


def _quoted(text: str) -> str:
    """Markdown code spans (`response`) as every other frame quotes a name ('response')."""
    import re

    return re.sub(r"`([^`]+)`", r"'\1'", text)


def plan_diagnostic(diagnostic: Mapping[str, Any]) -> Diagnostic:
    """One rule a dry run could not compile, as the ``Diagnostic`` code frames print.

    The frame's location names the rule's file, so neither its name nor its
    UUID repeats; a rule with no file is named in a note instead.
    """
    from pathlib import Path

    from opentide.cli.ui.diagnostics import Diagnostic

    source, where = diagnostic.get("file_path"), diagnostic.get("path")
    severity = str(diagnostic.get("severity") or "error")
    notes: tuple[tuple[str, str], ...] = ()
    if not source and not where:
        notes = (("rule", str(diagnostic.get("name") or diagnostic.get("uuid") or "")),)
    return Diagnostic(
        code=str(diagnostic.get("code") or "compile_failed"),
        severity="warning" if severity == "warning" else "error",
        message=_quoted(str(diagnostic.get("message") or "")),
        path=str(where) if where else None,
        file_path=Path(str(source)) if source else None,
        help=_quoted(str(diagnostic["help"])) if diagnostic.get("help") else None,
        notes=notes,
        object_uuid=str(diagnostic["uuid"]) if diagnostic.get("uuid") else None,
    )


def render_plan_diagnostics(console: Console, payload: Mapping[str, Any]) -> None:
    """Print each rule a dry run could not compile as a code frame; the tally follows them."""
    diagnostics = payload.get("diagnostics")
    if not isinstance(diagnostics, list):
        return
    framed = [plan_diagnostic(item) for item in diagnostics if isinstance(item, Mapping)]
    if not framed:
        return
    from opentide.cli.ui.codeframe import render_diagnostics

    # Errors print under --quiet too: the tally that follows counts them.
    render_diagnostics(console, framed)
