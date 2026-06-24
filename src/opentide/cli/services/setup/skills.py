"""Agent skills and instruction file setup."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import structlog
import typer

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup.interactive import (
    SKILL_LABELS,
    parse_multi_select,
    skill_targets_from_keys,
)
from opentide.cli.services.setup.templates import copy_skill_pack, render_agent_entrypoint

logger = structlog.get_logger("opentide.cli.services.setup.skills")

DEFAULT_PACK = "detection-ops"


@dataclass
class SkillsSetupOptions:
    """Non-interactive agent skills setup configuration."""

    path: Path = Path(".")
    targets: list[SkillTarget] = field(default_factory=list)
    pack: str = DEFAULT_PACK
    name: str | None = None
    org: str | None = None
    description: str | None = None
    yes: bool = False


def _entrypoint_context(options: SkillsSetupOptions, target: Path) -> dict[str, str]:
    return {
        "name": options.name or target.name,
        "org": options.org or "Security Operations",
        "description": options.description or "Detection-as-code repository powered by OpenTide",
    }


def _install_cursor(target: Path, pack: str, _context: dict[str, str]) -> list[str]:
    written = copy_skill_pack(pack, target / ".cursor" / "skills" / f"opentide-{pack}")
    return [f".cursor/skills/opentide-{pack}/{item}" for item in written]


def _install_claude_code(target: Path, pack: str, context: dict[str, str]) -> list[str]:
    written: list[str] = []
    claude_md = render_agent_entrypoint("CLAUDE.md.template", context)
    (target / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    written.append("CLAUDE.md")
    pack_files = copy_skill_pack(pack, target / ".claude" / "skills" / f"opentide-{pack}")
    written.extend(f".claude/skills/opentide-{pack}/{item}" for item in pack_files)
    return written


def _install_generic(target: Path, pack: str, context: dict[str, str]) -> list[str]:
    written: list[str] = []
    agents_md = render_agent_entrypoint("AGENTS.md.template", context)
    (target / "AGENTS.md").write_text(agents_md, encoding="utf-8")
    written.append("AGENTS.md")
    pack_files = copy_skill_pack(pack, target / ".agents" / "skills" / f"opentide-{pack}")
    written.extend(f".agents/skills/opentide-{pack}/{item}" for item in pack_files)
    return written


def _install_github_copilot(target: Path, context: dict[str, str]) -> list[str]:
    content = render_agent_entrypoint("copilot-instructions.md", context)
    dest = target / ".github" / "copilot-instructions.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return [".github/copilot-instructions.md"]


def run_skills_setup(options: SkillsSetupOptions) -> dict[str, object]:
    """Install agent skills and entrypoints for selected targets."""
    if not options.targets:
        raise typer.BadParameter(
            "Choose at least one skills target "
            "(--cursor, --claude-code, --generic, --github-copilot)"
        )
    target = options.path.resolve()
    context = _entrypoint_context(options, target)
    written: list[str] = []
    for skill_target in options.targets:
        if skill_target is SkillTarget.cursor:
            written.extend(_install_cursor(target, options.pack, context))
        elif skill_target is SkillTarget.claude_code:
            written.extend(_install_claude_code(target, options.pack, context))
        elif skill_target is SkillTarget.generic:
            written.extend(_install_generic(target, options.pack, context))
        elif skill_target is SkillTarget.github_copilot:
            if SkillTarget.generic not in options.targets:
                written.extend(_install_generic(target, options.pack, context))
            written.extend(_install_github_copilot(target, context))
    logger.info("agent_skills_created", detail=str(target), files=written)
    return {
        "message": "Agent skills generated",
        "path": str(target),
        "pack": options.pack,
        "files": written,
    }


def run_interactive_skills_setup(base_path: Path) -> dict[str, object]:
    """Prompt for skill targets and install packs."""
    from rich.prompt import Prompt

    print_labels = ", ".join(f"{key} ({label})" for key, label in SKILL_LABELS.items())
    raw = Prompt.ask(
        f"Agent environments (comma-separated: {print_labels})",
        default="generic",
    )
    keys = parse_multi_select(raw, SKILL_LABELS)
    if not keys:
        keys = ["generic"]
    options = SkillsSetupOptions(
        path=base_path,
        targets=skill_targets_from_keys(keys),
        yes=True,
    )
    return run_skills_setup(options)
