"""The opentidehq/skills Agent Plugin: skills and the MCP server in one install (#431).

The plugin's ``mcp.json`` starts ``opentide mcp start``, so one install gives an
agent the detection skills and the catalogue. Claude Code reads a project's
plugins from ``.claude/settings.json``: ``extraKnownMarketplaces`` names the
marketplace and ``enabledPlugins`` the plugin, and Claude Code offers both to
whoever opens the project. Other hosts install plugins from their own command
or menu, with no project file to write, so setup names their command instead.
"""

from __future__ import annotations

import json
from pathlib import Path

#: The marketplace and plugin name in opentidehq/skills' ``.claude-plugin/``.
MARKETPLACE = "opentide"
PLUGIN_ID = f"{MARKETPLACE}@{MARKETPLACE}"
MARKETPLACE_SOURCE: dict[str, str] = {"source": "github", "repo": "opentidehq/skills"}
CLAUDE_SETTINGS = ".claude/settings.json"

#: How each other host installs the plugin (opentidehq/skills README).
OTHER_HOSTS: dict[str, str] = {
    "cursor": "/add-plugin opentidehq/skills",
    "vscode": "Chat: Install Plugin From Source → opentidehq/skills (needs chat.plugins.enabled)",
    "copilot-cli": (
        "copilot plugin marketplace add opentidehq/skills && "
        "copilot plugin install opentide@opentide"
    ),
}


class PluginConfigError(ValueError):
    """An existing ``.claude/settings.json`` the plugin cannot be added to."""


def register_claude_code_plugin(target: Path) -> str:
    """Add the opentide marketplace and plugin to *target*'s Claude Code settings.

    Every other setting is kept. Returns the path written, relative to *target*.
    Raises :class:`PluginConfigError` and leaves the file unchanged when it is
    not a JSON object or holds either key as something other than an object.
    """
    from opentide.cli.services.setup.vscode import _load_jsonc

    dest = target / CLAUDE_SETTINGS
    settings: object = {}
    if dest.is_file():
        try:
            settings = _load_jsonc(dest)
        except ValueError as exc:
            raise PluginConfigError(f"is not valid JSON ({exc})") from exc
    if not isinstance(settings, dict):
        raise PluginConfigError("is not a JSON object")
    for key in ("extraKnownMarketplaces", "enabledPlugins"):
        if not isinstance(settings.setdefault(key, {}), dict):
            raise PluginConfigError(f"has a {key!r} that is not a JSON object")
    settings["extraKnownMarketplaces"][MARKETPLACE] = {"source": dict(MARKETPLACE_SOURCE)}
    settings["enabledPlugins"][PLUGIN_ID] = True
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(settings, indent=2) + "\n", encoding="utf-8")
    return CLAUDE_SETTINGS
