"""One-line summaries and examples for every command's help.

Kept in one table, applied when a command loads (:func:`decorate`), so a
listing never shows a summary longer than :data:`MAX_SUMMARY` and every
``--help`` ends with an example to paste. ``tests/test_cli/test_help.py``
fails when a visible command has neither.
"""

from __future__ import annotations

from typing import Any

#: The longest summary a listing shows.
MAX_SUMMARY = 60

#: Rich help panels the root listing groups commands under.
PANEL_AUTHOR = "Author"
PANEL_SHIP = "Ship"
PANEL_WORKSPACE = "Workspace"
PANEL_AGENTS = "Agents and integrations"

#: Command path → the summary listings show, where the help's first sentence is too long.
SUMMARIES: dict[str, str] = {
    "lint": "Check file names and recommended metadata",
    "mcp": "Run the opentide MCP server for editors and agents",
    "mcp start": "Serve MCP on stdio until the host closes stdin",
    "setup": "Set up a detection repository and its tooling",
    "setup platforms": "Enable platform configuration files",
    "setup ci": "Write CI/CD pipeline files",
    "setup env": "Write .env.example and ignore .env",
    "setup hooks": "Validate objects on every commit",
    "setup vscode": "Write VS Code schemas and snippets (deprecated)",
    "setup skills": "Discover and install agent skills",
    "share": "Publish objects to intelligence platforms",
    "share preview": "Show what push would do, without a request",
    "share status": "Compare the local ledger with object versions",
    "share retract": "Unpublish or delete a shared event",
    "rules unreviewed": "List rules not reviewed within a window",
    "generate": "Generate schemas, templates, docs and exports",
    "generate explorer": "Write the explorer bundle and search index",
    "generate docs rules": "Generate rule documentation",
    "generate docs objectives": "Generate objective documentation",
    "generate docs threats": "Generate threat documentation",
    "generate docs index": "Generate the documentation index pages",
    "generate exports navigator": "Export the ATT&CK Navigator layer",
    "generate exports objects": "Export every object as one JSON file",
    "generate exports revisions": "Export the revisions snapshot",
    "generate extract sentinel": "Import Sentinel analytics rules",
    "generate extract defender": "Import Defender custom detections",
    "generate extract elastic": "Import Elastic Security detection rules",
    "generate inflight prune": "Remove inflight shards already on the default branch",
    "validate": "Validate objects and queries",
    "deploy": "Deploy rules to platform tenants",
    "deploy migrate-state": "Move vendor ids from rules into deployment state",
    "migrate": "Migrate legacy repository layouts",
    "migrate objects": "Move a legacy layout into objects/ and .opentide/",
    "migrate vocab-scope": "Re-prefix stage-scoped vocabulary values",
}

#: Command path → commands to paste, shown under ``Examples`` in its help.
EXAMPLES: dict[str, tuple[str, ...]] = {
    "": ("opentide setup", "opentide validate", "opentide --json validate"),
    "lint": ("opentide lint", "opentide lint --fix"),
    "info": ("opentide info", "opentide info --platform sentinel"),
    "mcp": ("opentide mcp start",),
    "mcp start": ("opentide mcp start",),
    "setup": (
        "opentide setup",
        'opentide setup --yes --name "Detections" --platform sentinel --ci github',
    ),
    "setup repo": ('opentide setup repo --yes --name "Detections" --platform sentinel',),
    "setup platforms": ("opentide setup platforms --sentinel --splunk --yes",),
    "setup ci": ("opentide setup ci github --yes",),
    "setup env": ("opentide setup env --yes",),
    "setup hooks": ("opentide setup hooks --yes",),
    "setup mcp": ("opentide setup mcp --vscode --yes",),
    "setup vscode": ("opentide setup vscode --settings",),
    "setup skills": ("opentide setup skills --claude-code --yes",),
    "setup skills discover": ("opentide setup skills discover --query sigma",),
    "setup skills show": ("opentide setup skills show <slug>",),
    "share": ("opentide share --dry-run", "opentide share --target misp-prod"),
    "share push": ("opentide share push --target misp-prod",),
    "share preview": ("opentide share preview",),
    "share status": ("opentide share status",),
    "share retract": ("opentide share retract --uuid <uuid>",),
    "share targets": ("opentide share targets",),
    "rules": ("opentide rules unreviewed --older-than 90d",),
    "rules unreviewed": ("opentide rules unreviewed --older-than 90d",),
    "generate": ("opentide generate", "opentide generate schemas templates"),
    "generate explorer": ("opentide generate explorer",),
    "generate docs": ("opentide generate docs", "opentide generate docs --changed"),
    "generate docs rules": ("opentide generate docs rules",),
    "generate docs objectives": ("opentide generate docs objectives",),
    "generate docs threats": ("opentide generate docs threats",),
    "generate docs index": ("opentide generate docs index",),
    "generate exports": ("opentide generate exports",),
    "generate exports navigator": ("opentide generate exports navigator",),
    "generate exports objects": ("opentide generate exports objects",),
    "generate exports revisions": ("opentide generate exports revisions",),
    "generate extract": ("opentide generate extract sentinel",),
    "generate extract sentinel": ("opentide generate extract sentinel",),
    "generate extract defender": ("opentide generate extract defender",),
    "generate extract elastic": ("opentide generate extract elastic --space default",),
    "generate inflight": ("opentide generate inflight",),
    "generate inflight prune": ("opentide generate inflight prune",),
    "validate": ("opentide validate", "opentide validate --strict --type rule"),
    "validate query": ("opentide validate query --platform sentinel --live",),
    "deploy": (
        "opentide deploy --strategy PREVIEW --all --dry-run",
        "opentide deploy --strategy RELEASE",
    ),
    "deploy migrate-state": ("opentide deploy migrate-state",),
    "migrate": ("opentide migrate objects", "opentide migrate objects --apply"),
    "migrate objects": ("opentide migrate objects", "opentide migrate objects --apply"),
    "migrate vocab-scope": ("opentide migrate vocab-scope", "opentide migrate vocab-scope --apply"),
}


def epilog(path: str) -> str | None:
    """The ``Examples`` block for *path*, as Typer's Rich help renders it."""
    examples = EXAMPLES.get(path)
    if not examples:
        return None
    from rich.markup import escape

    lines = "\n\n".join(f"  [bold]$ {escape(example)}[/bold]" for example in examples)
    return f"[dim]Examples[/dim]\n\n{lines}"


def decorate(command: Any, path: str) -> Any:
    """Give *command* and its subcommands their summary and examples, once."""
    summary = SUMMARIES.get(path)
    if summary is not None:
        command.short_help = summary
    if not getattr(command, "epilog", None):
        command.epilog = epilog(path)
    for name, child in (getattr(command, "commands", None) or {}).items():
        decorate(child, f"{path} {name}".strip())
    return command
