"""Which detection workspace the MCP server serves when an Agent Plugin starts it (#431).

An Agent Plugins 1.0 client starts a plugin's stdio server in the plugin root.
For the opentide skills plugin that root is the skills package, not the user's
catalogue, and walking up from it would serve the skills checkout as an empty
workspace. When the server starts in a plugin root that is not itself a
workspace, it takes the host's project directory instead, and otherwise
refuses the catalogue tools with an error that says how to name the workspace.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from opentide.core.root import find_workspace_root, is_workspace_root

#: ``$schema`` prefix of an Agent Plugins manifest (``plugin.json``).
AGENT_PLUGINS_SCHEMA = "https://agent-plugins.org/schemas/"

#: Variables that name the workspace explicitly.
WORKSPACE_VARIABLES = ("OPENTIDE_REPO_ROOT", "OPENTIDE_TIDE_WORKSPACE")

#: Project directories hosts give the servers they start, most specific first.
#: ``PWD`` is the directory the host itself was started in, when its shell set it.
HOST_PROJECT_VARIABLES = ("CLAUDE_PROJECT_DIR", "PWD")

WORKSPACE_NOT_FOUND = "workspace_not_found"


@dataclass(frozen=True)
class PluginLaunch:
    """How the server found its workspace after starting in a plugin root."""

    plugin_root: Path
    #: The workspace taken from a host variable, or ``None`` when none was one.
    workspace: Path | None
    variable: str | None = None


def is_agent_plugin_root(path: Path) -> bool:
    """Whether *path* holds an Agent Plugins manifest (``plugin.json`` with its ``$schema``)."""
    manifest = path / "plugin.json"
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    schema = data.get("$schema") if isinstance(data, dict) else None
    return isinstance(schema, str) and schema.startswith(AGENT_PLUGINS_SCHEMA)


def resolve_plugin_launch(
    cwd: Path | None = None, env: Mapping[str, str] | None = None
) -> PluginLaunch | None:
    """``None`` unless the server starts in an Agent Plugin root that is no workspace.

    A workspace named by ``OPENTIDE_REPO_ROOT`` or ``OPENTIDE_TIDE_WORKSPACE``
    (or ``--repo``) wins, and a plugin that is also a detection workspace is
    served as one. Only a variable naming a workspace counts: the CLI exports
    both as the directory it resolved, which here is the plugin root.
    """
    env = os.environ if env is None else env
    for name in WORKSPACE_VARIABLES:
        value = env.get(name)
        if value and is_workspace_root(Path(value)):
            return None
    start = (cwd or Path.cwd()).resolve()
    if not is_agent_plugin_root(start) or is_workspace_root(find_workspace_root(start)):
        return None
    for name in HOST_PROJECT_VARIABLES:
        value = env.get(name)
        if not value:
            continue
        candidate = find_workspace_root(Path(value))
        if candidate != start and is_workspace_root(candidate):
            return PluginLaunch(start, candidate, name)
    return PluginLaunch(start, None)


def workspace_not_found_message(launch: PluginLaunch) -> str:
    return (
        f"{WORKSPACE_NOT_FOUND}: opentide was started in the Agent Plugin at "
        f"{launch.plugin_root}, which is not a detection workspace, and the host named "
        "no project that is one. Set OPENTIDE_REPO_ROOT to your detection repository "
        "in the host's MCP server settings, or add the server to the project with "
        "'opentide setup mcp'."
    )


#: Set by :func:`apply_plugin_launch` when the server has no workspace to serve.
_problem: str | None = None


def apply_plugin_launch(launch: PluginLaunch | None) -> None:
    """Serve *launch*'s workspace, or remember why there is none."""
    global _problem
    _problem = None
    if launch is None:
        return
    if launch.workspace is None:
        _problem = workspace_not_found_message(launch)
        return
    from opentide.core.root import get_repo_root

    # The CLI's root callback already exported (and cached) the plugin root.
    for name in WORKSPACE_VARIABLES:
        os.environ[name] = str(launch.workspace)
    get_repo_root.cache_clear()


def require_workspace() -> None:
    """Refuse a catalogue tool or resource when the server has no workspace."""
    if _problem is not None:
        from mcp.server.mcpserver.exceptions import ToolError

        raise ToolError(_problem)
