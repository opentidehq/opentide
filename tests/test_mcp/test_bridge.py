"""What the Rust MCP server compiles in of the Python server (``opentide.mcp_server.bridge``).

The Rust server (UC-3.7, #829; UC-6.0c, #841) says of itself what the Python
server says: its name, instructions, capabilities, tools and resources, from
the manifest these hold current. Its answers are held by the recorded
sessions (``cargo xtask mcp replay``).
"""

from __future__ import annotations

import json
from pathlib import Path

from opentide.mcp_server import bridge

ROOT = Path(__file__).resolve().parents[2]


def test_the_manifest_the_rust_server_compiles_in_is_current() -> None:
    """``scripts/build/mcp_manifest.py`` wrote it from the server as it is now."""
    committed = json.loads((ROOT / bridge.MANIFEST_PATH).read_text(encoding="utf-8"))
    assert committed == bridge.manifest(), (
        f"{bridge.MANIFEST_PATH} is stale: run uv run python scripts/build/mcp_manifest.py"
    )


def test_the_manifest_is_what_the_server_says_of_itself() -> None:
    from opentide.mcp_server.server import INSTRUCTIONS, TAGLINE, mcp

    manifest = bridge.manifest()
    assert manifest["name"] == "opentide"
    assert manifest["instructions"] == INSTRUCTIONS
    assert TAGLINE in manifest["instructions"]
    names = [tool["name"] for tool in manifest["tools"]]
    assert names == [tool.name for tool in mcp._tool_manager.list_tools()]
    for tool in manifest["tools"]:
        assert tool["inputSchema"]["type"] == "object", tool["name"]
    uris = {item["uri"] for item in manifest["resources"]}
    assert "opentide://index" in uris
    templates = {item["uriTemplate"] for item in manifest["resourceTemplates"]}
    assert "opentide://vocabularies/{+name}" in templates
    # An empty extensions map is not part of the handshake's capabilities.
    assert "extensions" not in manifest["capabilities"]
    assert manifest["protocolVersion"] == "2025-11-25"


def test_a_tool_description_is_the_same_on_every_python() -> None:
    """Python 3.10-3.12 keep a docstring's indentation; 3.13 strips it: agents read 3.13's."""
    from opentide.mcp_server.server import docstring, mcp

    def indented() -> None:
        pass

    # What 3.10-3.12 compile a docstring to, whatever Python runs the test.
    indented.__doc__ = "First line.\n\n    Details: one,\n      two.\n    "
    assert docstring(indented) == "First line.\n\nDetails: one,\n  two.\n"
    # Already 3.13's form: unchanged.
    indented.__doc__ = "First line.\n\nDetails: one,\n  two.\n"
    assert docstring(indented) == "First line.\n\nDetails: one,\n  two.\n"
    indented.__doc__ = None
    assert docstring(indented) is None
    for tool in mcp._tool_manager.list_tools():
        lines = tool.description.splitlines()[1:]
        assert not any(line.startswith("    ") for line in lines), tool.name
