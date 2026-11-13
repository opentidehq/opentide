"""MCP Apps views: the interactive pages hosts render for coverage, validation and lineage.

MCP Apps (extension ``io.modelcontextprotocol/ui``) lets a tool name a ``ui://``
HTML resource in ``_meta.ui.resourceUri``; a host that supports it (Claude
Desktop, VS Code, Cursor, Goose, ...) renders that page in a sandboxed iframe
next to the tool result, and the page talks to the host over postMessage. A
host without it ignores the key and shows the tool's JSON as before, so the
tools return exactly what they always did.

The three views share one page, ``views/view.html``, served at a URI per view
with ``data-view`` set. The coverage page also carries a compact copy of the
bundled ATT&CK matrix (tactics, techniques and sub-techniques with their names),
so it can show gaps as well as covered techniques without another call. The
pages load nothing from the network.
"""

from __future__ import annotations

import json
from functools import cache
from importlib.resources import files
from typing import Any, Literal

from mcp.server.apps import APP_MIME_TYPE, Apps
from mcp.server.mcpserver.resources import FunctionResource

from opentide.core.logging import get_logger

logger = get_logger(__name__)

View = Literal["coverage", "validation", "lineage", "graph"]

#: The ``ui://`` resource of each view.
VIEW_URIS: dict[View, str] = {
    "coverage": "ui://opentide/coverage.html",
    "validation": "ui://opentide/validation-report.html",
    "lineage": "ui://opentide/lineage.html",
    "graph": "ui://opentide/graph.html",
}

VIEW_TITLES: dict[View, str] = {
    "coverage": "ATT&CK coverage",
    "validation": "Validation report",
    "lineage": "Threat, objective and rule lineage",
    "graph": "Detection graph",
}

#: Views with their own stylesheet and script in views/, injected into the shared page.
_VIEW_ASSETS: dict[View, tuple[str, str]] = {"graph": ("graph.css", "graph.js")}

#: Views that show technique names and tactics, and so carry the ATT&CK matrix.
_ATTACK_VIEWS: frozenset[View] = frozenset({"coverage", "graph"})

_VIEW_MARKER = "__OPENTIDE_VIEW__"
_ATTACK_MARKER = "__OPENTIDE_ATTACK__"
_STYLE_MARKER = "/*__OPENTIDE_VIEW_STYLE__*/"
_SCRIPT_MARKER = "/*__OPENTIDE_VIEW_SCRIPT__*/"


def ui_meta(view: View) -> dict[str, Any]:
    """The tool ``_meta`` that binds a tool to *view*."""
    return {"ui": {"resourceUri": VIEW_URIS[view]}}


def attack_matrix() -> dict[str, Any] | None:
    """Tactics in kill-chain order, each with its techniques and their sub-techniques.

    Built from the workspace's ``att&ck`` vocabulary; revoked or removed entries
    are left out. ``None`` when there is no such vocabulary or it cannot be
    read, and the coverage view then lists covered techniques only.
    """
    from opentide.mcp_server.resources import resource_vocabulary

    try:
        vocabulary = json.loads(resource_vocabulary("att&ck"))
    except Exception as error:  # the page still renders, without the matrix
        # resource_vocabulary loads the workspace first; a workspace that fails to
        # load must not take the coverage page down with it.
        logger.warning("attack_matrix_unavailable", error=str(error))
        return None
    # An unknown vocabulary comes back as {"error": ..., "available": [...]}.
    if not isinstance(vocabulary, dict) or "error" in vocabulary:
        return None
    metadata = vocabulary.get("metadata") or {}
    entries = vocabulary.get("entries") or {}
    if not isinstance(entries, dict) or not entries:
        return None

    subs: dict[str, list[dict[str, str]]] = {}
    parents: dict[str, dict[str, Any]] = {}
    for key, entry in entries.items():
        if not isinstance(entry, dict) or entry.get("removed"):
            continue
        technique = str((entry.get("extra") or {}).get("id") or key)
        name = str(entry.get("name") or technique)
        if "." in technique:
            parent = technique.split(".", 1)[0]
            # "Command and Scripting Interpreter: PowerShell": drop the parent's name.
            subs.setdefault(parent, []).append({"id": technique, "name": name.split(": ", 1)[-1]})
        else:
            parents[technique] = {
                "id": technique,
                "name": name,
                "link": str(entry.get("link") or ""),
                "stages": [str(stage) for stage in entry.get("tide.vocab.stages") or []],
            }

    tactics = []
    for stage in metadata.get("stages") or []:
        tactic = stage.get("name") if isinstance(stage, dict) else None
        if not tactic:
            continue
        techniques = [
            {
                "id": technique["id"],
                "name": technique["name"],
                "link": technique["link"],
                "subs": sorted(subs.get(technique["id"], []), key=lambda sub: sub["id"]),
            }
            for technique in sorted(parents.values(), key=lambda item: item["id"])
            if tactic in technique["stages"]
        ]
        tactics.append({"name": str(tactic), "techniques": techniques})
    if not any(tactic["techniques"] for tactic in tactics):
        return None
    version = (metadata.get("extra") or {}).get("source_version")
    return {"version": str(version) if version else "", "tactics": tactics}


def _script_json(value: Any) -> str:
    """*value* as JSON that is safe inside ``<script type="application/json">``."""
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    # "</script" (in any case) or "<!--" in a string would end or confuse the element.
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


@cache
def view_html(view: View) -> str:
    """The page for *view*, built once per process."""
    views = files("opentide.mcp_server.views")
    page = views.joinpath("view.html").read_text(encoding="utf-8")
    style, script = "", ""
    if view in _VIEW_ASSETS:
        css_name, js_name = _VIEW_ASSETS[view]
        style = views.joinpath(css_name).read_text(encoding="utf-8")
        script = views.joinpath(js_name).read_text(encoding="utf-8")
    attack = attack_matrix() if view in _ATTACK_VIEWS else None
    # The assets are this package's own files; the markers are replaced once, in order,
    # so nothing they contain is read as a marker.
    page = page.replace(_STYLE_MARKER, style, 1).replace(_SCRIPT_MARKER, script, 1)
    return page.replace(_VIEW_MARKER, view, 1).replace(_ATTACK_MARKER, _script_json(attack), 1)


def build_apps() -> Apps:
    """The MCP Apps extension with every view registered; pass it to ``MCPServer``.

    Each page is built when a host first reads it, not at server start.
    """
    apps = Apps()
    for view, uri in VIEW_URIS.items():
        apps.add_resource(
            FunctionResource(
                uri=uri,
                name=f"opentide-{view}-view",
                title=VIEW_TITLES[view],
                description=f"Interactive {VIEW_TITLES[view].lower()} view (MCP Apps).",
                mime_type=APP_MIME_TYPE,
                fn=lambda view=view: view_html(view),
            )
        )
    return apps
