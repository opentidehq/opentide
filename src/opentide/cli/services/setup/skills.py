"""Agent skills install from OpenTideHQ/skills."""

from __future__ import annotations

import shutil
import urllib.error
import urllib.request
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
from opentide.cli.services.setup.skills_registry import load_manifest
from opentide.cli.services.setup.templates import render_agent_entrypoint

logger = structlog.get_logger("opentide.cli.services.setup.skills")

_STARTER_SKILLS = ("opentide-detection-rule", "detection-engineering")
_RAW_TREE = "https://raw.githubusercontent.com/OpenTideHQ/skills/{ref}/skills/{slug}/"
_RAW_AGENTS = "https://raw.githubusercontent.com/OpenTideHQ/skills/{ref}/AGENTS.md"


@dataclass
class SkillsSetupOptions:
    """Non-interactive agent skills setup configuration."""

    path: Path = Path(".")
    targets: list[SkillTarget] = field(default_factory=list)
    skill_slugs: list[str] = field(default_factory=list)
    install_all: bool = False
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


def _fetch_bytes(url: str) -> bytes | None:
    try:
        return urllib.request.urlopen(url, timeout=20).read()
    except (urllib.error.URLError, OSError):
        return None


def _download_skill(slug: str, dest: Path, *, ref: str) -> list[str]:
    """Download skill tree from GitHub raw; copy references/ if present."""
    written: list[str] = []
    base_url = _RAW_TREE.format(ref=ref, slug=slug)
    skill_md = _fetch_bytes(f"{base_url}SKILL.md")
    if skill_md is None:
        raise typer.BadParameter(f"Could not download skill: {slug}")
    dest.mkdir(parents=True, exist_ok=True)
    skill_path = dest / "SKILL.md"
    skill_path.write_bytes(skill_md)
    written.append(str(skill_path.name))
    # Best-effort: fetch common reference files when present upstream
    for ref_name in ("Best-Practices.md", "Anti-Patterns.md"):
        payload = _fetch_bytes(f"{base_url}references/{ref_name}")
        if payload:
            ref_dir = dest / "references"
            ref_dir.mkdir(exist_ok=True)
            (ref_dir / ref_name).write_bytes(payload)
            written.append(f"references/{ref_name}")
    return written


def _resolve_skill_slugs(options: SkillsSetupOptions) -> list[str]:
    _, ref, entries = load_manifest()
    if options.install_all:
        return [e.slug for e in entries]
    if options.skill_slugs:
        return list(options.skill_slugs)
    return list(_STARTER_SKILLS)


def _install_skill_trees(target: Path, slugs: list[str]) -> list[str]:
    _, ref, _ = load_manifest()
    written: list[str] = []
    for slug in slugs:
        rel_files = _download_skill(slug, target / ".agents" / "skills" / slug, ref=ref)
        written.extend(f".agents/skills/{slug}/{name}" for name in rel_files)
    return written


def _install_cursor(target: Path, slugs: list[str]) -> list[str]:
    written: list[str] = []
    for slug in slugs:
        src = target / ".agents" / "skills" / slug
        dest = target / ".cursor" / "skills" / slug
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
            written.append(f".cursor/skills/{slug}/SKILL.md")
    return written


def _install_claude_code(target: Path, slugs: list[str], context: dict[str, str]) -> list[str]:
    written: list[str] = []
    claude_md = render_agent_entrypoint("CLAUDE.md.template", context)
    (target / "CLAUDE.md").write_text(claude_md, encoding="utf-8")
    written.append("CLAUDE.md")
    for slug in slugs:
        src = target / ".agents" / "skills" / slug
        dest = target / ".claude" / "skills" / slug
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
            written.append(f".claude/skills/{slug}/SKILL.md")
    return written


def _install_generic(target: Path, slugs: list[str], context: dict[str, str]) -> list[str]:
    written: list[str] = []
    _, ref, _ = load_manifest()
    agents_payload = _fetch_bytes(_RAW_AGENTS.format(ref=ref))
    if agents_payload:
        (target / "AGENTS.md").write_bytes(agents_payload)
    else:
        (target / "AGENTS.md").write_text(
            render_agent_entrypoint("AGENTS.md.template", context), encoding="utf-8"
        )
    written.append("AGENTS.md")
    written.extend(f".agents/skills/{slug}/SKILL.md" for slug in slugs)
    return written


def _install_github_copilot(target: Path, context: dict[str, str]) -> list[str]:
    content = render_agent_entrypoint("copilot-instructions.md", context)
    dest = target / ".github" / "copilot-instructions.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")
    return [".github/copilot-instructions.md"]


def run_skills_setup(options: SkillsSetupOptions) -> dict[str, object]:
    """Install agent skills and entrypoints for selected harnesses."""
    if not options.targets:
        raise typer.BadParameter(
            "Choose at least one skills target "
            "(--cursor, --claude-code, --generic, --github-copilot)"
        )
    target = options.path.resolve()
    slugs = _resolve_skill_slugs(options)
    context = _entrypoint_context(options, target)
    written = _install_skill_trees(target, slugs)
    for skill_target in options.targets:
        if skill_target is SkillTarget.cursor:
            written.extend(_install_cursor(target, slugs))
        elif skill_target is SkillTarget.claude_code:
            written.extend(_install_claude_code(target, slugs, context))
        elif skill_target is SkillTarget.generic:
            written.extend(_install_generic(target, slugs, context))
        elif skill_target is SkillTarget.github_copilot:
            if SkillTarget.generic not in options.targets:
                written.extend(_install_generic(target, slugs, context))
            written.extend(_install_github_copilot(target, context))
    logger.info("agent_skills_created", detail=str(target), files=written, skills=slugs)
    return {
        "message": "Agent skills installed",
        "path": str(target),
        "skills": slugs,
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
