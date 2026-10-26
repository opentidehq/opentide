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


class McpConfigError(ValueError):
    """An existing MCP config that opentide's server cannot be merged into."""


def _merge_servers(dest: Path, template: dict[str, object]) -> dict[str, object]:
    """*dest*'s config with the template's server entries added or refreshed.

    Writing the template over the file dropped every other MCP server the
    user had configured there.
    """
    from opentide.cli.services.setup.vscode import _load_jsonc

    try:
        existing = _load_jsonc(dest)
    except ValueError as exc:
        raise McpConfigError(f"is not valid JSON ({exc})") from exc
    if not isinstance(existing, dict):
        raise McpConfigError("is not a JSON object")
    for key, servers in template.items():
        current = existing.get(key)
        if current is None:
            existing[key] = servers
        elif isinstance(current, dict) and isinstance(servers, dict):
            existing[key] = {**current, **servers}
        else:
            raise McpConfigError(f"has a {key!r} that is not a JSON object")
    return existing


def write_mcp_config(target: Path, host: McpHost) -> str:
    """Write or merge MCP config for a host; returns the relative path written.

    Raises :class:`McpConfigError` when an existing file cannot be merged; it
    is left unchanged.
    """
    rel = MCP_OUTPUT_PATHS[host]
    dest = target / rel
    payload = load_mcp_template(host.value)
    if dest.is_file():
        payload = _merge_servers(dest, payload)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return rel


def mcp_config_warning(host: McpHost, exc: McpConfigError) -> str:
    rel = MCP_OUTPUT_PATHS[host]
    return f"{rel} {exc}; left unchanged. Add the opentide server to it by hand."


def run_mcp_setup(options: McpSetupOptions) -> dict[str, object]:
    """Write MCP configuration files for selected hosts."""
    if not options.hosts:
        raise typer.BadParameter(
            "Choose at least one MCP host (--vscode, --cursor, --claude-code, --generic)"
        )
    target = options.path.resolve()
    written: list[str] = []
    skipped: list[str] = []
    warnings: list[str] = []
    for host in options.hosts:
        try:
            written.append(write_mcp_config(target, host))
        except McpConfigError as exc:
            skipped.append(MCP_OUTPUT_PATHS[host])
            warnings.append(mcp_config_warning(host, exc))
    logger.debug("mcp_config_created", detail=str(target), files=written)
    result: dict[str, object] = {
        "message": "MCP configuration generated",
        "path": str(target),
        "files": written,
    }
    if skipped:
        result["skipped"] = skipped
    if McpHost.generic in options.hosts:
        result["advice"] = (
            "Copy opentide.mcp.json into your editor MCP settings or run "
            "opentide setup mcp with a specific host flag."
        )
    # Every config runs `opentide mcp start`. Say so now rather than leaving the
    # user to debug a server their editor silently fails to start.
    from opentide.mcp_server.launcher import MCP_INSTALL_HINT, missing_requirements

    missing = missing_requirements()
    if missing:
        result["mcp_available"] = False
        warnings.append(
            f"These configs launch opentide mcp start, which cannot import "
            f"{', '.join(missing)} in this environment. Repair it with: {MCP_INSTALL_HINT}"
        )
        logger.warning(
            "mcp_server_unavailable",
            detail=", ".join(missing),
            advice=MCP_INSTALL_HINT,
        )
    else:
        result["mcp_available"] = True
    if warnings:
        result["warnings"] = warnings
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
