"""Load bundled client setup assets from package data."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from opentide.core.root import get_data_root

MCP_HOSTS = frozenset({"vscode", "cursor", "claude-code", "generic"})
SKILL_PACKS = frozenset({"detection-ops"})
ENTRYPOINT_TEMPLATES = frozenset(
    {"AGENTS.md.template", "CLAUDE.md.template", "copilot-instructions.md"}
)


class SetupTemplateError(Exception):
    """Missing or invalid bundled setup asset."""


def setup_data_root() -> Path:
    return get_data_root() / "setup"


def load_mcp_template(host: str) -> dict[str, object]:
    if host not in MCP_HOSTS:
        raise SetupTemplateError(f"Unknown MCP host: {host}")
    path = setup_data_root() / "mcp" / f"{host}.json"
    if not path.is_file():
        raise SetupTemplateError(f"MCP template missing: {path.name}")
    return json.loads(path.read_text(encoding="utf-8"))


def copy_skill_pack(pack: str, dest: Path) -> list[str]:
    if pack not in SKILL_PACKS:
        raise SetupTemplateError(f"Unknown skill pack: {pack}")
    src = setup_data_root() / "skills" / pack
    if not src.is_dir():
        raise SetupTemplateError(f"Skill pack missing: {pack}")
    written: list[str] = []
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(src)
        out = dest / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, out)
        written.append(str(rel))
    return written


def render_agent_entrypoint(template_name: str, context: dict[str, str]) -> str:
    if template_name not in ENTRYPOINT_TEMPLATES:
        raise SetupTemplateError(f"Unknown entrypoint template: {template_name}")
    path = setup_data_root() / "skills" / template_name
    if not path.is_file():
        raise SetupTemplateError(f"Entrypoint template missing: {template_name}")
    text = path.read_text(encoding="utf-8")
    for key, value in context.items():
        text = text.replace("{" + key + "}", value)
    return text


def load_yaml_schema_fragment() -> dict[str, object]:
    path = setup_data_root() / "vscode" / "settings.fragment.json"
    if not path.is_file():
        raise SetupTemplateError("VS Code settings fragment missing")
    return json.loads(path.read_text(encoding="utf-8"))
