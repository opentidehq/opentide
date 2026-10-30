"""Agent skills install from the live opentidehq/skills catalogue."""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

import structlog
import typer
from rich.markup import escape

from opentide.cli.enums import SkillTarget
from opentide.cli.services.setup.interactive import (
    SKILL_LABELS,
    ask_checkbox,
    ask_confirm,
    require_interactive,
    skill_targets_from_keys,
)
from opentide.cli.services.setup.skills_registry import (
    BUNDLED_AUTHORING_SKILLS,
    GithubTree,
    fetch_github_bytes,
    known_skill_slugs,
    list_github_paths,
    load_manifest,
    slug_is_contained,
)
from opentide.cli.services.setup.templates import render_agent_entrypoint, setup_data_root
from opentide.core.logging.config import get_stdout_console

logger = structlog.get_logger("opentide.cli.services.setup.skills")

_STARTER_SKILLS = ("opentide-detection-rule", "detection-engineering")

#: ``BUNDLED_AUTHORING_SKILLS`` is defined in ``skills_registry`` alongside the
#: entries themselves, so the catalogue and the installer cannot disagree about
#: which skills ship in the wheel.


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
    #: Register the opentidehq/skills Agent Plugin for Claude Code (#431).
    plugin: bool = False
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


def _skill_reachable(slug: str, *, source: str, ref: str) -> bool:
    if slug in BUNDLED_AUTHORING_SKILLS:
        return (setup_data_root() / "skills" / "authoring" / slug / "SKILL.md").is_file()
    return fetch_github_bytes(f"skills/{slug}/SKILL.md", source=source, ref=ref) is not None


def _replace_tree(dest: Path, files: dict[str, bytes]) -> list[str]:
    """Swap *dest* for *files* only after every byte is on disk.

    A failed download must not delete the previous tree or leave a partial one
    beside it. The incoming directory is renamed into place, which replaces the
    old tree in one step on the same filesystem.
    """
    parent = dest.parent
    parent.mkdir(parents=True, exist_ok=True)
    staging = parent / f".{dest.name}.incoming"
    backup = parent / f".{dest.name}.previous"
    if staging.exists():
        shutil.rmtree(staging)
    try:
        for rel, payload in files.items():
            out = _contained_file(staging, rel)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(payload)
        if backup.exists():
            shutil.rmtree(backup)
        if dest.exists():
            dest.rename(backup)
        try:
            staging.rename(dest)
        except OSError:
            if backup.exists() and not dest.exists():
                backup.rename(dest)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return list(files)


def _contained_file(root: Path, relative: str) -> Path:
    """Resolve *relative* under *root*, refusing paths that climb out of the skill tree."""
    if not relative or relative.startswith(("/", "\\")) or "\\" in relative:
        raise SkillsDownloadError(f"Refusing skill path {relative!r}")
    parts = PurePosixPath(relative).parts
    if not parts or any(part in {".", ".."} for part in parts):
        raise SkillsDownloadError(f"Refusing skill path {relative!r}")
    destination = root.joinpath(*parts)
    root_resolved = root.resolve()
    if not destination.resolve().is_relative_to(root_resolved):
        raise SkillsDownloadError(f"Refusing skill path {relative!r}")
    return destination


def _require_slug(slug: str) -> str:
    if not slug_is_contained(slug):
        raise SkillsDownloadError(f"Refusing skill slug {slug!r}")
    return slug


def _install_bundled_skill(slug: str, dest: Path) -> list[str]:
    src = setup_data_root() / "skills" / "authoring" / slug
    skill_md = src / "SKILL.md"
    if not skill_md.is_file():
        raise SkillsDownloadError(f"Bundled authoring skill '{slug}' is missing from the package")
    files = {
        path.relative_to(src).as_posix(): path.read_bytes()
        for path in sorted(src.rglob("*"))
        if path.is_file()
    }
    return _replace_tree(dest, files)


def _download_skill(
    slug: str, dest: Path, *, source: str, ref: str, tree: GithubTree | None = None
) -> list[str]:
    """Install one skill tree.

    The four authoring skills come from the package. Every other skill is the
    full git tree under ``skills/<slug>/``, not a fixed pair of reference files.
    *tree* shares one listing of the repository between the skills of a run.
    """
    _require_slug(slug)
    if slug in BUNDLED_AUTHORING_SKILLS:
        return _install_bundled_skill(slug, dest)
    paths = list_github_paths(f"skills/{slug}", source=source, ref=ref, tree=tree)
    if not paths:
        raise SkillsDownloadError(_download_error(slug, source=source, ref=ref))
    prefix = f"skills/{slug}/"
    files: dict[str, bytes] = {}
    for path in paths:
        payload = fetch_github_bytes(path, source=source, ref=ref)
        if payload is None or not path.startswith(prefix):
            raise SkillsDownloadError(_download_error(slug, source=source, ref=ref))
        files[path[len(prefix) :]] = payload
    if "SKILL.md" not in files:
        raise SkillsDownloadError(_download_error(slug, source=source, ref=ref))
    return _replace_tree(dest, files)


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
    tree = GithubTree(source=manifest.source, ref=manifest.ref)
    written: list[str] = []
    for slug in slugs:
        _require_slug(slug)
        rel_files = _download_skill(
            slug,
            target / ".agents" / "skills" / slug,
            source=manifest.source,
            ref=manifest.ref,
            tree=tree,
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


@dataclass
class _Entrypoints:
    """Entrypoint files a run left alone, and why."""

    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def write(self, target: Path, rel: str, content: str) -> list[str]:
        """Write *content* to *rel* unless the file already exists.

        These are the repository's own agent instructions. Setup replaced
        them with the template and lost whatever the user had written.
        """
        dest = target / rel
        if dest.exists():
            self.skipped.append(rel)
            if dest.read_bytes() != content.encode("utf-8"):
                self.warnings.append(
                    f"Left {rel} unchanged because the file already exists; "
                    "point it at .agents/skills/ by hand, or delete it and re-run "
                    "to write opentide's template."
                )
            return []
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        return [rel]


def _install_claude_code(
    target: Path, slugs: list[str], context: dict[str, str], entrypoints: _Entrypoints
) -> list[str]:
    """CLAUDE.md, and the skills under ``.claude/skills/`` unless *slugs* is empty."""
    claude_md = render_agent_entrypoint("CLAUDE.md.template", context)
    written = entrypoints.write(target, "CLAUDE.md", claude_md)
    for slug in slugs:
        src = target / ".agents" / "skills" / slug
        dest = target / ".claude" / "skills" / slug
        if src.is_dir():
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(src, dest)
            written.append(f".claude/skills/{slug}/SKILL.md")
    return written


def _install_generic(target: Path, context: dict[str, str], entrypoints: _Entrypoints) -> list[str]:
    content = render_agent_entrypoint("AGENTS.md.template", context)
    return entrypoints.write(target, "AGENTS.md", content)


def _install_github_copilot(
    target: Path, context: dict[str, str], entrypoints: _Entrypoints
) -> list[str]:
    content = render_agent_entrypoint("copilot-instructions.md", context)
    return entrypoints.write(target, ".github/copilot-instructions.md", content)


def run_skills_setup(options: SkillsSetupOptions) -> dict[str, object]:
    """Install agent skills and entrypoints for selected harnesses."""
    if not options.targets and not options.plugin:
        raise typer.BadParameter(
            "Choose at least one skills target "
            "(--cursor, --claude-code, --generic, --github-copilot, --plugin)"
        )
    target = options.path.resolve()
    written: list[str] = []
    plugin_warnings: list[str] = []
    if options.plugin:
        from opentide.cli.services.setup.plugin import (
            CLAUDE_SETTINGS,
            PluginConfigError,
            register_claude_code_plugin,
        )

        try:
            written.append(register_claude_code_plugin(target))
        except PluginConfigError as exc:
            plugin_warnings.append(
                f"{CLAUDE_SETTINGS} {exc}; left unchanged. Install the plugin in Claude "
                "Code with /plugin marketplace add opentidehq/skills."
            )
    # With the plugin, Claude Code takes the skills from it: copying them into
    # .claude/skills/ as well would load every skill twice.
    copies = [t for t in options.targets if not (options.plugin and t is SkillTarget.claude_code)]
    slugs = _resolve_skill_slugs(options) if copies else []
    context = _entrypoint_context(options, target)
    if slugs:
        written.extend(_install_skill_trees(target, slugs))
    entrypoints = _Entrypoints()
    also_applied: list[str] = []
    for skill_target in options.targets:
        if skill_target is SkillTarget.cursor:
            written.extend(_install_cursor(target, slugs))
        elif skill_target is SkillTarget.claude_code:
            own = [] if options.plugin else slugs
            written.extend(_install_claude_code(target, own, context, entrypoints))
        elif skill_target is SkillTarget.generic:
            written.extend(_install_generic(target, context, entrypoints))
        elif skill_target is SkillTarget.github_copilot:
            if SkillTarget.generic not in options.targets:
                written.extend(_install_generic(target, context, entrypoints))
                also_applied.append("generic")
            written.extend(_install_github_copilot(target, context, entrypoints))
    logger.debug("agent_skills_created", detail=str(target), files=written, skills=slugs)
    result: dict[str, object] = {
        "message": "Agent skills installed",
        "path": str(target),
        "skills": slugs,
        "files": written,
    }
    if also_applied:
        result["also_applied"] = also_applied
    if entrypoints.skipped:
        result["skipped"] = entrypoints.skipped
    if options.plugin:
        from opentide.cli.services.setup.plugin import OTHER_HOSTS, PLUGIN_ID

        result["plugin"] = PLUGIN_ID
        result["advice"] = (
            "Claude Code offers the opentide plugin to whoever opens this project. "
            "The plugin starts opentide mcp start itself: other agents install it with "
            + "; ".join(f"{host}: {how}" for host, how in OTHER_HOSTS.items())
            + "."
        )
    warnings = plugin_warnings + entrypoints.warnings
    if warnings:
        result["warnings"] = warnings
    return result


def run_interactive_skills_setup(
    base_path: Path, given: SkillsSetupOptions | None = None
) -> dict[str, object]:
    """Prompt for skill targets and install packs.

    *given* carries the flags typed with the command (``--install``, ``--all``,
    ``--name``...); the wizard only asks for the targets. It used to receive
    the path alone and install the starter skills whatever was asked for.
    """
    require_interactive()
    keys = ask_checkbox(
        "Agent environments",
        [(label, key) for key, label in SKILL_LABELS.items()],
        require_selection=True,
    )
    options = replace(
        given or SkillsSetupOptions(),
        path=base_path,
        targets=skill_targets_from_keys(keys),
        yes=True,
    )
    unavailable = unavailable_skills(options)
    if unavailable:
        raise RuntimeError("Agent skills unavailable: " + ", ".join(unavailable))
    get_stdout_console().print(
        f"[bold]Target:[/] {escape(str(base_path.resolve()))}\n"
        f"[bold]Agent environments:[/] {escape(', '.join(keys))}"
    )
    if not ask_confirm("Install these agent skills?", default=True):
        return {"message": "Agent skills setup cancelled", "status": "skipped"}
    return run_skills_setup(options)
