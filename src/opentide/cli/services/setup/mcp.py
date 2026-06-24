"""MCP server configuration for editors and agents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import structlog
import typer

from opentide.cli.enums import McpHost
from opentide.cli.services.setup.interactive import (
    MCP_LABELS,
    mcp_hosts_from_keys,
    parse_multi_select,
)
from opentide.cli.services.setup.templates import load_mcp_template

logger = structlog.get_logger("opentide.cli.services.setup.mcp")

MCP_OUTPUT_PATHS: dict[McpHost, str] = {
    McpHost.vscode: ".vscode/mcp.json",
    McpHost.cursor: ".cursor/mcp.json",
    McpHost.claude_code: ".mcp.json",
    McpHost.generic: "opentide.mcp.json",
}


@dataclass
class McpSetupOptions:
    """Non-interactive MCP setup configuration."""

    path: Path = Path(".")
    hosts: list[McpHost] = field(default_factory=list)
    yes: bool = False


def write_mcp_config(target: Path, host: McpHost) -> str:
    """Write MCP config for a host; returns relative path written."""
    rel = MCP_OUTPUT_PATHS[host]
    dest = target / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = load_mcp_template(host.value)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return rel


def run_mcp_setup(options: McpSetupOptions) -> dict[str, object]:
    """Write MCP configuration files for selected hosts."""
    if not options.hosts:
        raise typer.BadParameter(
            "Choose at least one MCP host (--vscode, --cursor, --claude-code, --generic)"
        )
    target = options.path.resolve()
    written: list[str] = []
    for host in options.hosts:
        written.append(write_mcp_config(target, host))
    logger.info("mcp_config_created", detail=str(target), files=written)
    result: dict[str, object] = {
        "message": "MCP configuration generated",
        "path": str(target),
        "files": written,
    }
    if McpHost.generic in options.hosts:
        result["note"] = (
            "Copy opentide.mcp.json into your editor MCP settings or run "
            "opentide setup mcp with a specific host flag."
        )
    return result


def run_interactive_mcp_setup(base_path: Path) -> dict[str, object]:
    """Prompt for MCP hosts and write configs."""
    from rich.prompt import Prompt

    print_labels = ", ".join(f"{key} ({label})" for key, label in MCP_LABELS.items())
    raw = Prompt.ask(
        f"MCP hosts (comma-separated: {print_labels})",
        default="vscode",
    )
    keys = parse_multi_select(raw, MCP_LABELS)
    if not keys:
        keys = ["vscode"]
    options = McpSetupOptions(path=base_path, hosts=mcp_hosts_from_keys(keys), yes=True)
    return run_mcp_setup(options)
