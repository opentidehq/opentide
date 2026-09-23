"""MCP server configuration for editors and agents."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import structlog
import typer
from rich.markup import escape

from opentide.cli.enums import McpHost
from opentide.cli.services.setup.interactive import (
    MCP_LABELS,
    ask_checkbox,
    ask_confirm,
    mcp_hosts_from_keys,
    require_interactive,
)
from opentide.cli.services.setup.templates import load_mcp_template
from opentide.core.logging.config import get_stdout_console

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
    logger.debug("mcp_config_created", detail=str(target), files=written)
    result: dict[str, object] = {
        "message": "MCP configuration generated",
        "path": str(target),
        "files": written,
    }
    if McpHost.generic in options.hosts:
        result["advice"] = (
            "Copy opentide.mcp.json into your editor MCP settings or run "
            "opentide setup mcp with a specific host flag."
        )
    # Every config points at `opentide-mcp`. Say so now rather than leaving the
    # user to debug a server their editor silently fails to start.
    from opentide.mcp_server.launcher import MCP_EXTRA, missing_requirements

    missing = missing_requirements()
    if missing:
        result["mcp_extra_installed"] = False
        warnings = list(result.get("warnings") or [])
        warnings.append(
            f"These configs launch opentide-mcp, which needs {MCP_EXTRA} "
            f"(missing: {', '.join(missing)}). Install it with: pip install '{MCP_EXTRA}'"
        )
        result["warnings"] = warnings
        logger.warning(
            "mcp_extra_not_installed",
            detail=", ".join(missing),
            advice=f"pip install '{MCP_EXTRA}'",
        )
    else:
        result["mcp_extra_installed"] = True
    return result


def run_interactive_mcp_setup(base_path: Path) -> dict[str, object]:
    """Prompt for MCP hosts and write configs."""
    require_interactive()
    keys = ask_checkbox(
        "MCP hosts",
        [(label, key) for key, label in MCP_LABELS.items()],
        require_selection=True,
    )
    get_stdout_console().print(
        f"[bold]Target:[/] {escape(str(base_path.resolve()))}\n"
        f"[bold]Hosts:[/] {escape(', '.join(keys))}"
    )
    if not ask_confirm("Write these MCP configurations?", default=True):
        return {"message": "MCP setup cancelled", "status": "skipped"}
    options = McpSetupOptions(path=base_path, hosts=mcp_hosts_from_keys(keys), yes=True)
    return run_mcp_setup(options)
