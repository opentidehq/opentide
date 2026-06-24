"""Tests for bundled setup templates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from opentide.cli.services.setup.templates import (
    SetupTemplateError,
    copy_skill_pack,
    load_mcp_template,
    render_agent_entrypoint,
    setup_data_root,
)
from opentide.core.root import get_data_root


def test_setup_data_root_is_package_data() -> None:
    root = setup_data_root()
    assert root.is_dir()
    assert root == get_data_root() / "setup"


@pytest.mark.parametrize("host", ["vscode", "cursor", "claude-code", "generic"])
def test_load_mcp_template(host: str) -> None:
    payload = load_mcp_template(host)
    assert "mcpServers" in payload
    assert "opentide" in payload["mcpServers"]


def test_load_mcp_template_unknown_host() -> None:
    with pytest.raises(SetupTemplateError):
        load_mcp_template("unknown")


def test_copy_skill_pack_missing(tmp_path: Path) -> None:
    with pytest.raises(SetupTemplateError):
        copy_skill_pack("missing-pack", tmp_path / "pack")


def test_render_agent_entrypoint_missing(tmp_path: Path) -> None:
    with pytest.raises(SetupTemplateError):
        render_agent_entrypoint("missing.template", {})


def test_copy_skill_pack(tmp_path: Path) -> None:
    written = copy_skill_pack("detection-ops", tmp_path / "pack")
    assert written
    assert (tmp_path / "pack" / "SKILL.md").is_file()


def test_render_agent_entrypoint() -> None:
    text = render_agent_entrypoint(
        "AGENTS.md.template",
        {"name": "SOC", "org": "SecOps", "description": "Detections"},
    )
    assert "SOC" in text
    assert "SecOps" in text
    assert "Detections" in text


def test_mcp_templates_are_valid_json() -> None:
    for path in (setup_data_root() / "mcp").glob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))


def test_load_mcp_template_missing_file(monkeypatch) -> None:
    root = setup_data_root()
    monkeypatch.setattr(
        "opentide.cli.services.setup.templates.setup_data_root",
        lambda: root / "missing-mcp",
    )
    with pytest.raises(SetupTemplateError, match="MCP template missing"):
        load_mcp_template("vscode")


def test_copy_skill_pack_missing_directory(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.templates.setup_data_root",
        lambda: tmp_path / "setup-root",
    )
    with pytest.raises(SetupTemplateError, match="Skill pack missing"):
        copy_skill_pack("detection-ops", tmp_path / "dest")


def test_copy_skill_pack_skips_non_files(tmp_path: Path, monkeypatch) -> None:
    pack_root = tmp_path / "setup-root" / "skills" / "detection-ops"
    (pack_root / "nested").mkdir(parents=True)
    (pack_root / "SKILL.md").write_text("# skill\n", encoding="utf-8")
    monkeypatch.setattr(
        "opentide.cli.services.setup.templates.setup_data_root",
        lambda: tmp_path / "setup-root",
    )
    written = copy_skill_pack("detection-ops", tmp_path / "out")
    assert "SKILL.md" in written


def test_render_agent_entrypoint_missing_file(monkeypatch) -> None:
    monkeypatch.setattr(
        "opentide.cli.services.setup.templates.setup_data_root",
        lambda: Path("/nonexistent/setup"),
    )
    with pytest.raises(SetupTemplateError, match="Entrypoint template missing"):
        render_agent_entrypoint("AGENTS.md.template", {})


def test_load_yaml_schema_fragment_missing(monkeypatch) -> None:
    from opentide.cli.services.setup.templates import load_yaml_schema_fragment

    monkeypatch.setattr(
        "opentide.cli.services.setup.templates.setup_data_root",
        lambda: Path("/nonexistent/setup"),
    )
    with pytest.raises(SetupTemplateError, match="VS Code settings fragment missing"):
        load_yaml_schema_fragment()
