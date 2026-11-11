"""``opentide.cli.rust``: what the launcher tells the Rust command line (UC-3.5c, #928)."""

from __future__ import annotations

import json

import pytest

from opentide.cli import rust
from opentide.cli.services.doctor import PLATFORM_SDKS


def test_doctor_gets_each_platform_module_import_status() -> None:
    modules = rust.python_modules(["--json", "doctor", "--offline"])
    assert modules is not None
    platforms = json.loads(modules)
    # Every platform, with its modules in the order the Python package lists them.
    assert {platform: [module for module, _ in pairs] for platform, pairs in platforms.items()} == {
        platform: list(names) for platform, names in PLATFORM_SDKS.items()
    }
    # ``requests`` is a dependency of opentide: it imports.
    assert ["requests", None] in platforms["elastic"]


def test_a_module_that_does_not_import_says_why(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.cli.services import doctor

    monkeypatch.setitem(doctor.PLATFORM_SDKS, "splunk", ("requests", "opentide_no_such_module"))
    platforms = json.loads(rust.python_modules(["doctor"]) or "{}")
    [first, second] = platforms["splunk"]
    assert first == ["requests", None]
    assert second[0] == "opentide_no_such_module"
    assert second[1].startswith("ModuleNotFoundError")


def test_other_commands_pay_for_no_imports() -> None:
    assert rust.python_modules(["info"]) is None
    assert rust.python_modules(["migrate", "vocab-scope"]) is None


def test_setup_mcp_gets_whether_the_mcp_server_can_start(monkeypatch: pytest.MonkeyPatch) -> None:
    from opentide.mcp_server import launcher

    monkeypatch.setattr(launcher, "missing_requirements", lambda: ["mcp.server.mcpserver"])
    for argv in (["setup", "mcp", "--vscode"], ["--json", "setup", "--mcp", "cursor", "--yes"]):
        server = json.loads(rust.mcp_server(argv) or "{}")
        assert server == {"missing": ["mcp.server.mcpserver"], "hint": launcher.MCP_INSTALL_HINT}
    monkeypatch.setattr(launcher, "missing_requirements", list)
    assert json.loads(rust.mcp_server(["setup", "mcp", "--generic"]) or "{}")["missing"] == []


def test_setup_without_mcp_pays_for_no_probe() -> None:
    assert rust.mcp_server(["setup", "env"]) is None
    assert rust.mcp_server(["info"]) is None
