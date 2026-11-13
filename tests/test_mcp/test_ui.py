"""MCP Apps views: tool bindings, the ``ui://`` pages and the ATT&CK matrix they carry."""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from mcp.server.apps import APP_MIME_TYPE, EXTENSION_ID

from opentide.mcp_server import ui
from opentide.mcp_server.server import mcp

BOUND_TOOLS = {
    "coverage": "ui://opentide/coverage.html",
    "validation_report": "ui://opentide/validation-report.html",
    "get_chaining": "ui://opentide/lineage.html",
    "graph": "ui://opentide/graph.html",
}


def _attack_json(html: str) -> object:
    match = re.search(
        r'<script type="application/json" id="attack">(.*?)</script>', html, re.DOTALL
    )
    assert match, "the page has no #attack element"
    return json.loads(match.group(1))


def test_server_advertises_the_apps_extension() -> None:
    options = mcp._lowlevel_server.create_initialization_options()
    extensions = options.capabilities.model_dump(by_alias=True, exclude_none=True)["extensions"]
    assert EXTENSION_ID in extensions


def test_bound_tools_name_a_registered_app_resource() -> None:
    tools = {tool.name: tool for tool in asyncio.run(mcp.list_tools())}
    resources = {str(resource.uri): resource for resource in asyncio.run(mcp.list_resources())}
    for name, uri in BOUND_TOOLS.items():
        assert tools[name].meta == {"ui": {"resourceUri": uri}}, name
        assert resources[uri].mime_type == APP_MIME_TYPE
    unbound = {name for name, tool in tools.items() if tool.meta and "ui" in tool.meta}
    assert unbound == set(BOUND_TOOLS)


@pytest.mark.parametrize("view", list(ui.VIEW_URIS))
def test_each_page_names_its_view_and_loads_nothing_remote(view: ui.View) -> None:
    html = asyncio.run(mcp.read_resource(ui.VIEW_URIS[view]))
    (content,) = list(html)
    assert content.mime_type == APP_MIME_TYPE
    page = content.content
    assert isinstance(page, str)
    assert f'data-view="{view}"' in page
    assert "__OPENTIDE_" not in page
    # The default MCP Apps CSP blocks every origin: no script, style, font or fetch from one.
    assert not re.search(r'(src|href)=["\']https?:', page)
    assert "fetch(" not in page and "XMLHttpRequest" not in page
    # Catalogue strings reach the DOM as text only.
    assert "innerHTML" not in page and "insertAdjacentHTML" not in page


def test_only_the_coverage_and_graph_pages_carry_the_attack_matrix() -> None:
    assert _attack_json(ui.view_html("validation")) is None
    assert _attack_json(ui.view_html("lineage")) is None
    for view in ("coverage", "graph"):
        matrix = _attack_json(ui.view_html(view))
        assert isinstance(matrix, dict) and matrix["version"], view


def test_the_graph_page_carries_its_own_style_and_script() -> None:
    page = ui.view_html("graph")
    assert "extraRenderers.graph = renderGraphView" in page
    assert ".g-canvas" in page
    # Other views get the shell alone.
    assert "renderGraphView" not in ui.view_html("coverage")
    assert "/*__OPENTIDE_VIEW_" not in page and "/*__OPENTIDE_VIEW_" not in ui.view_html("lineage")


def test_attack_matrix_follows_the_bundled_vocabulary() -> None:
    matrix = ui.attack_matrix()
    assert matrix is not None
    tactics = [tactic["name"] for tactic in matrix["tactics"]]
    assert tactics[0] == "Reconnaissance" and "Execution" in tactics
    execution = next(tactic for tactic in matrix["tactics"] if tactic["name"] == "Execution")
    t1059 = next(technique for technique in execution["techniques"] if technique["id"] == "T1059")
    assert t1059["name"] == "Command and Scripting Interpreter"
    assert t1059["link"].startswith("https://attack.mitre.org/")
    powershell = next(sub for sub in t1059["subs"] if sub["id"] == "T1059.001")
    # The parent's name is not repeated on its sub-techniques.
    assert powershell["name"] == "PowerShell"
    every_id = [
        technique["id"] for tactic in matrix["tactics"] for technique in tactic["techniques"]
    ]
    assert all("." not in technique for technique in every_id)


@pytest.mark.parametrize(
    "body",
    [
        {"error": "Unknown vocabulary 'att&ck'", "available": ["tlp"]},
        {"metadata": {"stages": [{"name": "Execution"}]}, "entries": {}},
        {"metadata": {"stages": []}, "entries": {"T1059": {"name": "x"}}},
    ],
)
def test_attack_matrix_is_none_without_techniques(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    # resource_vocabulary answers an unknown vocabulary with an error document, not
    # an exception; an empty matrix would hide every covered technique in the view.
    monkeypatch.setattr(
        "opentide.mcp_server.resources.resource_vocabulary", lambda name: json.dumps(body)
    )
    assert ui.attack_matrix() is None


def test_attack_matrix_is_none_when_the_workspace_fails_to_load(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def broken(name: str) -> str:
        raise RuntimeError("workspace configuration is invalid")

    monkeypatch.setattr("opentide.mcp_server.resources.resource_vocabulary", broken)
    assert ui.attack_matrix() is None


def test_attack_matrix_is_none_when_the_vocabulary_cannot_be_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unreadable(name: str) -> str:
        raise OSError(name)

    monkeypatch.setattr("opentide.mcp_server.resources.resource_vocabulary", unreadable)
    assert ui.attack_matrix() is None


@pytest.mark.parametrize("text", ["</script><script>alert(1)</script>", "<!-- x", "a & b"])
def test_script_json_cannot_close_or_comment_out_its_element(text: str) -> None:
    encoded = ui._script_json({"name": text})
    assert "<" not in encoded and ">" not in encoded and "&" not in encoded
    assert json.loads(encoded) == {"name": text}
