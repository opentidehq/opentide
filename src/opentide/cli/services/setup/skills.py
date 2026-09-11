"""Agent skills install from OpenTideHQ/skills."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path

import structlog
import typer

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup.interactive import (
    SKILL_LABELS,
    ask_checkbox,
    ask_confirm,
    require_interactive,
    skill_targets_from_keys,
)
from opentide.cli.services.setup.skills_registry import (
    bundled_skill_dir,
    fetch_github_bytes,
    known_skill_slugs,
    load_manifest,
)
from opentide.cli.services.setup.templates import render_agent_entrypoint
from opentide.core.logging.config import get_stdout_console

logger = structlog.get_logger("opentide.cli.services.setup.skills")

_STARTER_SKILLS = ("opentide-detection-rule", "detection-engineering")


class SkillsDownloadError(RuntimeError):
    """Raised when a remote skill cannot be downloaded."""


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
        "org": options.org or "",
        "description": options.description or "",
    }


def _download_error(slug: str, *, source: str, ref: str) -> str:
    return (
        f"Could not download skill '{slug}' from {source}@{ref}. "
        "Check network access and that the skills repository is publicly reachable."
    )


def _copy_skill_tree(src: Path, dest: Path) -> list[str]:
    """Copy SKILL.md and optional references/ from a local skill tree."""
    dest.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skill_md = src / "SKILL.md"
    (dest / "SKILL.md").write_bytes(skill_md.read_bytes())
    written.append("SKILL.md")
    ref_dir = src / "references"
    if ref_dir.is_dir():
        for ref_path in sorted(ref_dir.iterdir()):
            if not ref_path.is_file():
                continue
            target_dir = dest / "references"
            target_dir.mkdir(exist_ok=True)
            (target_dir / ref_path.name).write_bytes(ref_path.read_bytes())
            written.append(f"references/{ref_path.name}")
    return written


def _skill_reachable(slug: str, *, source: str, ref: str) -> bool:
    if fetch_github_bytes(f"skills/{slug}/SKILL.md", source=source, ref=ref) is not None:
        return True
    return bundled_skill_dir(slug) is not None


def _download_skill(slug: str, dest: Path, *, source: str, ref: str) -> list[str]:
    """Download skill tree from GitHub raw; fall back to the packaged snapshot."""
    skill_md = fetch_github_bytes(f"skills/{slug}/SKILL.md", source=source, ref=ref)
    if skill_md is None:
        bundled = bundled_skill_dir(slug)
        if bundled is None:
            raise SkillsDownloadError(_download_error(slug, source=source, ref=ref))
        logger.warning("skills_download_fallback_bundled", slug=slug, source=source, ref=ref)
        return _copy_skill_tree(bundled, dest)
    dest.mkdir(parents=True, exist_ok=True)
    written: list[str] = []
    skill_path = dest / "SKILL.md"
    skill_path.write_bytes(skill_md)
    written.append(str(skill_path.name))
    for ref_name in ("Best-Practices.md", "Anti-Patterns.md"):
        payload = fetch_github_bytes(
            f"skills/{slug}/references/{ref_name}",
            source=source,
            ref=ref,
        )
        if payload:
            ref_dir = dest / "references"
            ref_dir.mkdir(exist_ok=True)
            (ref_dir / ref_name).write_bytes(payload)
            written.append(f"references/{ref_name}")
    return written


def _resolve_skill_slugs(options: SkillsSetupOptions) -> list[str]:
    manifest = load_manifest()
    if options.install_all:
        return [entry.slug for entry in manifest.entries]
    if options.skill_slugs:
        known = known_skill_slugs()
        unknown = [slug for slug in options.skill_slugs if slug not in known]
        if unknown:
            joined = ", ".join(unknown)
            raise typer.BadParameter(
                f"Unknown skill slug(s): {joined}. "
                "Run 'opentide setup skills discover' to list available skills."
            )
        return list(options.skill_slugs)
    return list(_STARTER_SKILLS)


def _install_skill_trees(target: Path, slugs: list[str]) -> list[str]:
    manifest = load_manifest()
    written: list[str] = []
    for slug in slugs:
        rel_files = _download_skill(
            slug,
            target / ".agents" / "skills" / slug,
            source=manifest.source,
            ref=manifest.ref,
        )
        written.extend(f".agents/skills/{slug}/{name}" for name in rel_files)
    return written


def unavailable_skills(options: SkillsSetupOptions) -> list[str]:
    """Return skill slugs that cannot be fetched before setup mutates files."""
    manifest = load_manifest()
    return [
        slug
        for slug in _resolve_skill_slugs(options)
        if not _skill_reachable(slug, source=manifest.source, ref=manifest.ref)
    ]


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
    manifest = load_manifest()
    agents_payload = fetch_github_bytes("AGENTS.md", source=manifest.source, ref=manifest.ref)
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
    also_applied: list[str] = []
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
                also_applied.append("generic")
            written.extend(_install_github_copilot(target, context))
    logger.debug("agent_skills_created", detail=str(target), files=written, skills=slugs)
    result: dict[str, object] = {
        "message": "Agent skills installed",
        "path": str(target),
        "skills": slugs,
        "files": written,
    }
    if also_applied:
        result["also_applied"] = also_applied
    return result


def run_interactive_skills_setup(base_path: Path) -> dict[str, object]:
    """Prompt for skill targets and install packs."""
    require_interactive()
    keys = ask_checkbox(
        "Agent environments",
        [(label, key) for key, label in SKILL_LABELS.items()],
        require_selection=True,
    )
    options = SkillsSetupOptions(
        path=base_path,
        targets=skill_targets_from_keys(keys),
        yes=True,
    )
    unavailable = unavailable_skills(options)
    if unavailable:
        raise RuntimeError("Agent skills unavailable: " + ", ".join(unavailable))
    get_stdout_console().print(
        f"[bold]Target:[/] {base_path.resolve()}\n[bold]Agent environments:[/] {', '.join(keys)}"
    )
    if not ask_confirm("Install these agent skills?", default=True):
        return {"message": "Agent skills setup cancelled", "status": "skipped"}
    return run_skills_setup(options)
