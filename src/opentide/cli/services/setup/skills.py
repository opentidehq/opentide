"""Agent skills install from the live opentidehq/skills catalogue."""

from __future__ import annotations

import shutil
from collections.abc import Iterable
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
    CATALOGUE_FIRST_SKILLS,
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
        # Installed from the catalogue when it has the slug, else from the package.
        return (setup_data_root() / "skills" / "authoring" / slug / "SKILL.md").is_file()
    return fetch_github_bytes(f"skills/{slug}/SKILL.md", source=source, ref=ref) is not None


def _extra_files(dest: Path, shipped: Iterable[str]) -> list[str]:
    """Files under *dest*, relative to it, that are not in *shipped*: the user's own."""
    if dest.is_symlink() or not dest.is_dir():
        return []
    names = set(shipped)
    return sorted(
        rel
        for path in dest.rglob("*")
        if path.is_file() and (rel := path.relative_to(dest).as_posix()) not in names
    )


def _kept_warning(where: str, kept: list[str]) -> str:
    shown = ", ".join(kept[:5]) + (f" and {len(kept) - 5} more" if len(kept) > 5 else "")
    return (
        f"Kept {len(kept)} file(s) in {where} that the skill does not ship ({shown}); "
        "delete them by hand if they are left over from an older version."
    )


def _replace_tree(dest: Path, files: dict[str, bytes]) -> list[str]:
    """Swap *dest* for *files* only after every byte is on disk.

    A failed download must not delete the previous tree or leave a partial one
    beside it. The incoming directory is renamed into place, which replaces the
    old tree in one step on the same filesystem. ``.agents/skills/<slug>`` is
    opentide's copy of the skill, so a file an older version shipped goes; the
    harness copies made from it keep the user's files (:func:`_copy_skill`).
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


def _fetch_skill_files(
    slug: str, *, source: str, ref: str, tree: GithubTree | None
) -> dict[str, bytes] | None:
    """Every file under ``skills/<slug>/`` in the catalogue, or ``None`` if any is missing."""
    paths = list_github_paths(f"skills/{slug}", source=source, ref=ref, tree=tree)
    if not paths:
        return None
    prefix = f"skills/{slug}/"
    files: dict[str, bytes] = {}
    for path in paths:
        payload = fetch_github_bytes(path, source=source, ref=ref)
        if payload is None or not path.startswith(prefix):
            return None
        files[path[len(prefix) :]] = payload
    return files if "SKILL.md" in files else None


def _download_skill(
    slug: str,
    dest: Path,
    *,
    source: str,
    ref: str,
    tree: GithubTree | None = None,
    catalogued: bool = False,
    warnings: list[str] | None = None,
) -> list[str]:
    """Install one skill tree.

    Every skill is the full git tree under ``skills/<slug>/``, not a fixed pair of
    reference files. The four authoring skills also ship in the package and install
    from there, except a ``CATALOGUE_FIRST_SKILLS`` slug the catalogue lists
    (*catalogued*): it installs the catalogue's copy, which ``discover`` and ``show``
    describe. When that copy's files cannot be downloaded, an installed copy is kept
    and, with none, the package's is written; either way a line goes to *warnings*.
    *tree* shares one listing of the repository between the skills of a run.
    """
    _require_slug(slug)
    bundled = slug in BUNDLED_AUTHORING_SKILLS
    if bundled and not (catalogued and slug in CATALOGUE_FIRST_SKILLS):
        return _install_bundled_skill(slug, dest)
    files = _fetch_skill_files(slug, source=source, ref=ref, tree=tree)
    if files is not None:
        return _replace_tree(dest, files)
    if not bundled:
        raise SkillsDownloadError(_download_error(slug, source=source, ref=ref))
    where = f".agents/skills/{slug}"
    if (dest / "SKILL.md").is_file():
        logger.warning("skill_kept_installed_copy", slug=slug, source=source, ref=ref)
        if warnings is not None:
            warnings.append(
                f"Kept the installed {where}: its files could not be downloaded from "
                f"{source}@{ref}. Run the command again to update it."
            )
        return []
    logger.warning("skill_installed_from_package", slug=slug, source=source, ref=ref)
    if warnings is not None:
        warnings.append(
            f"Installed opentide's short packaged copy of {where}: the catalogue's "
            f"could not be downloaded from {source}@{ref}. Run the command again for "
            "the full skill."
        )
    return _install_bundled_skill(slug, dest)


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


def _install_skill_trees(
    target: Path, slugs: list[str], warnings: list[str] | None = None
) -> list[str]:
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
            catalogued=slug in manifest.catalogue_slugs,
            warnings=warnings,
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


def _copy_skill(src: Path, dest: Path, where: str, warnings: list[str], *, target: Path) -> None:
    """Copy the skill *src* over *dest*, keeping the files in *dest* it does not ship.

    The folder used to be deleted first, and with it whatever the user had
    put there (team notes, local edits to a file the skill does not ship).

    Nothing is written through a link: a link at a path the skill ships (a file
    or a folder) is replaced by the skill's own, with a warning, and a *dest*
    that resolves outside *target* (a skills folder shared between repositories)
    is left as it is, with a warning.
    """
    if dest.exists() and dest.resolve() == src.resolve():
        # ``.claude/skills`` links to ``.agents/skills`` (or this skill's folder
        # does): the skill is already there, and copying it onto itself would
        # delete it.
        return
    if not dest.resolve().is_relative_to(target.resolve()):
        warnings.append(
            f"Left {where} as it is: it links outside this repository, to "
            f"{dest.resolve()}. Copy the skill there by hand if that folder should have it."
        )
        return
    shipped = sorted(path.relative_to(src).as_posix() for path in src.rglob("*") if path.is_file())
    kept = _extra_files(dest, shipped)
    replaced: list[str] = []
    # Resolved: a dangling link to a folder inside the repository gets that folder.
    dest.resolve().mkdir(parents=True, exist_ok=True)
    for rel in shipped:
        out = dest
        parts = rel.split("/")
        for depth, part in enumerate(parts):
            out = out / part
            if out.is_symlink():
                out.unlink()
                replaced.append("/".join(parts[: depth + 1]))
            if depth < len(parts) - 1:
                out.mkdir(exist_ok=True)
        shutil.copy2(src / rel, out)
    if replaced:
        shown = ", ".join(replaced[:5]) + (
            f" and {len(replaced) - 5} more" if len(replaced) > 5 else ""
        )
        warnings.append(
            f"Replaced {len(replaced)} link(s) in {where} with the skill's own files "
            f"({shown}), rather than write through them."
        )
    if kept:
        warnings.append(_kept_warning(where, kept))


def _install_cursor(target: Path, slugs: list[str], warnings: list[str]) -> list[str]:
    written: list[str] = []
    for slug in slugs:
        src = target / ".agents" / "skills" / slug
        dest = target / ".cursor" / "skills" / slug
        if src.is_dir():
            _copy_skill(src, dest, f".cursor/skills/{slug}", warnings, target=target)
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
            _copy_skill(src, dest, f".claude/skills/{slug}", entrypoints.warnings, target=target)
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
    entrypoints = _Entrypoints()
    download_warnings: list[str] = []
    if slugs:
        written.extend(_install_skill_trees(target, slugs, download_warnings))
    also_applied: list[str] = []
    for skill_target in options.targets:
        if skill_target is SkillTarget.cursor:
            written.extend(_install_cursor(target, slugs, entrypoints.warnings))
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
    warnings = plugin_warnings + download_warnings + entrypoints.warnings
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
