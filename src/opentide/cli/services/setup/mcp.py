"""MCP server configuration for editors and agents.

Every host but Claude Desktop reads a file in the repository. Claude Desktop
reads one file per user, outside it (:func:`claude_desktop_config_path`), and
has no project directory to expand, so its entry names the workspace and the
``opentide`` executable by absolute path (:func:`claude_desktop_server`).
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from collections.abc import Callable, Mapping
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

#: The file each host reads in the repository. Claude Desktop's is outside it:
#: :func:`claude_desktop_config_path`.
MCP_OUTPUT_PATHS: dict[McpHost, str] = {
    McpHost.vscode: ".vscode/mcp.json",
    McpHost.cursor: ".cursor/mcp.json",
    McpHost.claude_code: ".mcp.json",
    McpHost.generic: "opentide.mcp.json",
}

#: The host flags, named when none is given.
_HOST_FLAGS = "--vscode, --cursor, --claude-code, --claude-desktop, --generic"
CLAUDE_DESKTOP_CONFIG = "claude_desktop_config.json"
CLAUDE_DESKTOP_ADVICE = (
    "Restart Claude Desktop, or choose Developer → Reload MCP Configuration, "
    "to start the opentide server."
)


@dataclass
class McpSetupOptions:
    """Non-interactive MCP setup configuration."""

    path: Path = Path(".")
    hosts: list[McpHost] = field(default_factory=list)
    yes: bool = False
    #: ``--plan``: write nothing outside the repository. The plan runs the step
    #: in a copy of the repository, but Claude Desktop's file is not in it.
    plan: bool = False


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
        elif not isinstance(servers, dict):
            # A scalar such as the Agent Plugins `$schema`: the user's value stays.
            continue
        elif isinstance(current, dict):
            existing[key] = {**current, **servers}
        else:
            raise McpConfigError(f"has a {key!r} that is not a JSON object")
    return existing


def write_mcp_config(target: Path, host: McpHost) -> str:
    """Write or merge MCP config for a host; returns the relative path written.

    Raises :class:`McpConfigError` when an existing file cannot be merged; it
    is left unchanged. Claude Desktop's file is not in the repository:
    :func:`write_claude_desktop_config` writes it.
    """
    if host is McpHost.claude_desktop:
        raise ValueError("Claude Desktop's config is not in the repository")
    rel = MCP_OUTPUT_PATHS[host]
    dest = target / rel
    payload = load_mcp_template(host.value)
    if dest.is_file():
        payload = _merge_servers(dest, payload)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return rel


def claude_desktop_config_path(
    platform: str | None = None,
    environ: Mapping[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    """Where Claude Desktop reads its MCP servers on *platform* (``sys.platform``'s values).

    macOS: ``~/Library/Application Support/Claude``; Windows: ``%APPDATA%\\Claude``
    (``~/AppData/Roaming`` without ``APPDATA``); elsewhere ``$XDG_CONFIG_HOME/Claude``
    (``~/.config`` when it is unset or relative, as the XDG specification says).
    """
    platform = sys.platform if platform is None else platform
    environ = os.environ if environ is None else environ
    home = Path.home() if home is None else home
    if platform == "darwin":
        base = home / "Library" / "Application Support"
    elif platform == "win32":
        appdata = environ.get("APPDATA")
        base = Path(appdata) if appdata else home / "AppData" / "Roaming"
    else:
        xdg = environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg and Path(xdg).is_absolute() else home / ".config"
    return base / "Claude" / CLAUDE_DESKTOP_CONFIG


def opentide_command(
    executable: str | None = None,
    which: Callable[[str], str | None] = shutil.which,
    platform: str | None = None,
) -> tuple[str, list[str]]:
    """The absolute command and arguments that start this opentide's MCP server.

    Claude Desktop started from the Dock or the Start menu does not have the
    shell's ``PATH``, so a bare ``opentide`` fails there. In order: the
    ``opentide`` script installed beside the running interpreter (a virtual
    environment's, pipx's, uv tool's), the one on ``PATH``, and else the
    interpreter itself running ``-m opentide``.
    """
    executable = sys.executable if executable is None else executable
    platform = sys.platform if platform is None else platform
    args = ["mcp", "start"]
    if executable:
        name = "opentide.exe" if platform == "win32" else "opentide"
        beside = Path(executable).parent / name
        if beside.is_file():
            return str(beside.absolute()), args
    found = which("opentide")
    if found:
        return str(Path(found).absolute()), args
    if not executable:
        # No interpreter path to run either (an embedded Python): the bare name is all there is.
        return "opentide", args
    return str(Path(executable).absolute()), ["-m", "opentide", *args]


def claude_desktop_server(
    workspace: Path, command: tuple[str, list[str]] | None = None
) -> dict[str, object]:
    """The ``mcpServers`` document Claude Desktop needs to run opentide on *workspace*."""
    program, args = opentide_command() if command is None else command
    return {
        "mcpServers": {
            "opentide": {
                "command": program,
                "args": args,
                "env": {"OPENTIDE_REPO_ROOT": str(workspace)},
            }
        }
    }


def write_claude_desktop_config(
    target: Path, dest: Path | None = None, *, plan: bool = False
) -> tuple[Path, bool]:
    """Merge the opentide server for *target* into Claude Desktop's config.

    Returns the file and whether it existed. Other servers and settings stay;
    an ``opentide`` entry is replaced. With *plan*, the merge is worked out
    (so a file that cannot be merged still raises) and nothing is written.
    Raises :class:`McpConfigError` when the file cannot be merged; it is left
    unchanged.
    """
    from opentide.core.io import write_text_atomically

    dest = claude_desktop_config_path() if dest is None else dest
    payload = claude_desktop_server(target)
    existed = dest.is_file()
    if existed:
        payload = _merge_servers(dest, payload)
        # Written through a link (a dotfile manager's), not over it.
        dest = dest.resolve()
    if not plan:
        write_text_atomically(dest, json.dumps(payload, indent=2) + "\n")
    return dest, existed


def mcp_config_warning(host: McpHost, exc: McpConfigError) -> str:
    rel = (
        str(claude_desktop_config_path())
        if host is McpHost.claude_desktop
        else MCP_OUTPUT_PATHS[host]
    )
    return f"{rel} {exc}; left unchanged. Add the opentide server to it by hand."


def run_mcp_setup(options: McpSetupOptions) -> dict[str, object]:
    """Write MCP configuration files for selected hosts."""
    if not options.hosts:
        raise typer.BadParameter(f"Choose at least one MCP host ({_HOST_FLAGS})")
    target = options.path.resolve()
    written: list[str] = []
    skipped: list[str] = []
    warnings: list[str] = []
    #: ``--plan``: the files outside the repository the run would write.
    outside: list[dict[str, str]] = []
    desktop: Path | None = None
    for host in options.hosts:
        if host is McpHost.claude_desktop:
            config = claude_desktop_config_path()
            try:
                desktop, existed = write_claude_desktop_config(target, config, plan=options.plan)
            except (McpConfigError, OSError) as exc:
                # OSError: a folder outside the repository that this user cannot write.
                reason = (
                    exc
                    if isinstance(exc, McpConfigError)
                    else McpConfigError(f"could not be written ({exc.strerror or exc})")
                )
                warnings.append(mcp_config_warning(host, reason))
                if options.plan:
                    outside.append({"path": str(config), "action": "skip"})
                else:
                    skipped.append(str(config))
                continue
            if options.plan:
                outside.append({"path": str(desktop), "action": "merge" if existed else "create"})
            else:
                written.append(str(desktop))
            continue
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
    if outside:
        # Read by the plan, which sees only the files written in its copy of the repository.
        result["_outside"] = outside
    if McpHost.vscode in options.hosts:
        from opentide.cli.services.setup.vscode import EXTENSION_MCP_NOTE, recommends_extension

        if recommends_extension(target):
            # Not a warning: the file serves teammates without the extension.
            result["extension_mcp"] = True
            result["detail"] = EXTENSION_MCP_NOTE
    advice: list[str] = []
    if McpHost.generic in options.hosts:
        advice.append(
            "Copy opentide.mcp.json into your editor MCP settings or run "
            "opentide setup mcp with a specific host flag."
        )
    if desktop is not None:
        result["claude_desktop_config"] = str(desktop)
        advice.append(CLAUDE_DESKTOP_ADVICE)
    if advice:
        result["advice"] = " ".join(advice)
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
