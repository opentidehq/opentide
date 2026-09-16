"""Resolve OpenTide explorer source and run build/dev/serve."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import structlog

from opentide.core.logging.console import emit_section
from opentide.core.root import get_repo_root
from opentide.export.explorer_export import export_explorer_bundle

logger = structlog.get_logger("opentide.cli.services.explorer")

DEFAULT_EXPLORER_GIT = "https://github.com/OpenTideHQ/explorer.git"
DEFAULT_EXPLORER_REF = "main"
_BUILD_SCRIPT = Path("bin") / "build.mjs"
_REQUIRED_EXPORT = "explorer.bundle.json"
_OPTIONAL_EXPORTS = (
    "explorer.search.json",
    "explorer.coverage.json",
    "attack-navigator.json",
    "vocab.att&ck.json",
    "explorer.graph.json",
)


@dataclass(frozen=True)
class ExplorerSourceOptions:
    """Inputs that select which explorer checkout to run."""

    explorer_path: Path | None = None
    explorer_git: str | None = None
    explorer_ref: str | None = None
    version: str | None = None
    repo_root: Path | None = None
    cache_dir: Path | None = None


def default_explorer_cache() -> Path:
    """Default clone destination: ``~/.cache/opentide/explorer-src``."""
    xdg = os.environ.get("XDG_CACHE_HOME")
    base = Path(xdg) if xdg else Path.home() / ".cache"
    return base / "opentide" / "explorer-src"


def is_explorer_source(path: Path) -> bool:
    """True when *path* looks like the explorer git checkout."""
    return path.is_dir() and (path / _BUILD_SCRIPT).is_file()


def default_exports_dir(repo_root: Path | None = None) -> Path:
    """Corpus export directory consumed by ``bin/build.mjs``."""
    root = repo_root or get_repo_root()
    return root / ".opentide" / "exports"


def generate_explorer_exports(export_dir: Path | None = None) -> tuple[Path, Path]:
    """Write ``explorer.bundle.json`` and ``explorer.search.json``."""
    emit_section("Explorer export generation")
    return export_explorer_bundle(export_dir)


def resolve_explorer_source(options: ExplorerSourceOptions | None = None) -> Path:
    """Resolve explorer source in the order documented by OpenTideHQ/explorer.

    1. ``EXPLORER_GIT_URL`` / ``--explorer-git``
    2. ``OPENTIDE_EXPLORER_PATH`` / ``--explorer-path``
    3. Sibling ``../explorer`` next to the corpus repo
    4. ``EXPLORER_VERSION`` / ``--version`` (treated as a git ref)
    5. Shallow-clone ``OpenTideHQ/explorer`` into the cache directory
    """
    opts = options or ExplorerSourceOptions()
    git_url = opts.explorer_git or os.environ.get("EXPLORER_GIT_URL")
    ref = opts.explorer_ref or os.environ.get("EXPLORER_GIT_REF") or DEFAULT_EXPLORER_REF
    path_value = opts.explorer_path
    if path_value is None:
        env_path = os.environ.get("OPENTIDE_EXPLORER_PATH")
        if env_path:
            path_value = Path(env_path)
    version = opts.version or os.environ.get("EXPLORER_VERSION")
    cache = opts.cache_dir or default_explorer_cache()
    repo_root = (opts.repo_root or get_repo_root()).resolve()

    if git_url:
        return _clone_explorer(git_url, ref, cache)
    if path_value is not None:
        resolved = path_value.expanduser().resolve()
        if not is_explorer_source(resolved):
            raise FileNotFoundError(f"Explorer source at {resolved} is missing {_BUILD_SCRIPT}")
        return resolved
    sibling = repo_root.parent / "explorer"
    if is_explorer_source(sibling):
        return sibling
    if version:
        return _clone_explorer(DEFAULT_EXPLORER_GIT, version, cache)
    return _clone_explorer(DEFAULT_EXPLORER_GIT, ref, cache)


def run_explorer_build(
    *,
    output: Path | None = None,
    base_path: str = "",
    exports_dir: Path | None = None,
    schemas_dir: Path | None = None,
    skip_install: bool = False,
    source_options: ExplorerSourceOptions | None = None,
) -> dict[str, object]:
    """Generate explorer exports and run ``node bin/build.mjs build``."""
    opts = source_options or ExplorerSourceOptions()
    repo_root = (opts.repo_root or get_repo_root()).resolve()
    exports = (exports_dir or default_exports_dir(repo_root)).resolve()
    generate_explorer_exports(exports)
    bundle = exports / _REQUIRED_EXPORT
    if not bundle.is_file():
        raise FileNotFoundError(f"Missing required export: {bundle}")
    source = resolve_explorer_source(
        ExplorerSourceOptions(
            explorer_path=opts.explorer_path,
            explorer_git=opts.explorer_git,
            explorer_ref=opts.explorer_ref,
            version=opts.version,
            repo_root=repo_root,
            cache_dir=opts.cache_dir,
        )
    )
    _ensure_node_modules(source, skip_install=skip_install)
    dest = (output or (repo_root / "out" / "explorer")).resolve()
    node = _require_cmd("node", "node is required for opentide explorer build (Node ≥ 20.19)")
    schemas = schemas_dir or (repo_root / ".opentide" / "schemas")
    cmd = [
        node,
        str(source / _BUILD_SCRIPT),
        "build",
        "--exports-dir",
        str(exports),
        "--output",
        str(dest),
    ]
    if base_path:
        cmd.extend(["--base-path", base_path])
    if schemas.is_dir():
        cmd.extend(["--schemas-dir", str(schemas)])
    emit_section("Explorer static build")
    _run(cmd, cwd=source, what="Explorer build")
    logger.info("explorer_build_complete", output=str(dest), source=str(source))
    return {
        "message": "Explorer static site built",
        "output": str(dest),
        "source": str(source),
        "exports": str(exports),
    }


def run_explorer_dev(
    *,
    exports_dir: Path | None = None,
    skip_install: bool = False,
    source_options: ExplorerSourceOptions | None = None,
) -> dict[str, object]:
    """Sync exports into explorer ``public/data`` and run ``pnpm dev``."""
    opts = source_options or ExplorerSourceOptions()
    repo_root = (opts.repo_root or get_repo_root()).resolve()
    exports = (exports_dir or default_exports_dir(repo_root)).resolve()
    generate_explorer_exports(exports)
    source = resolve_explorer_source(
        ExplorerSourceOptions(
            explorer_path=opts.explorer_path,
            explorer_git=opts.explorer_git,
            explorer_ref=opts.explorer_ref,
            version=opts.version,
            repo_root=repo_root,
            cache_dir=opts.cache_dir,
        )
    )
    _sync_exports_into_public_data(exports, source)
    _ensure_node_modules(source, skip_install=skip_install)
    pnpm = _require_cmd("pnpm", "pnpm is required for opentide explorer dev (pnpm 9+)")
    emit_section("Explorer dev server")
    _run([pnpm, "dev"], cwd=source, what="Explorer dev")
    return {"message": "Explorer dev server stopped", "source": str(source)}


def run_explorer_serve(
    *,
    output: Path | None = None,
    port: int = 4173,
    source_options: ExplorerSourceOptions | None = None,
) -> dict[str, object]:
    """Serve a previously built static explorer directory."""
    opts = source_options or ExplorerSourceOptions()
    repo_root = (opts.repo_root or get_repo_root()).resolve()
    dest = (output or (repo_root / "out" / "explorer")).resolve()
    if not dest.is_dir():
        raise FileNotFoundError(
            f"Explorer output not found: {dest}. Run `opentide explorer build` first."
        )
    python = _require_cmd("python3", "python3 is required for opentide explorer serve")
    emit_section(f"Explorer static server :{port}")
    _run(
        [python, "-m", "http.server", str(port), "--directory", str(dest)],
        cwd=dest,
        what="Explorer serve",
    )
    return {"message": "Explorer static server stopped", "output": str(dest), "port": port}


def _sync_exports_into_public_data(exports_dir: Path, explorer_src: Path) -> None:
    data_dir = explorer_src / "public" / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    required = exports_dir / _REQUIRED_EXPORT
    if not required.is_file():
        raise FileNotFoundError(f"Missing required export: {required}")
    shutil.copy2(required, data_dir / _REQUIRED_EXPORT)
    for name in _OPTIONAL_EXPORTS:
        src = exports_dir / name
        if src.is_file():
            shutil.copy2(src, data_dir / name)


def _ensure_node_modules(source: Path, *, skip_install: bool) -> None:
    if skip_install or (source / "node_modules").is_dir():
        return
    pnpm = _require_cmd(
        "pnpm",
        "pnpm is required to install explorer dependencies (pnpm 9+)",
    )
    _run([pnpm, "install", "--frozen-lockfile"], cwd=source, what="Explorer pnpm install")


def _clone_explorer(url: str, ref: str, dest: Path) -> Path:
    git = _require_cmd("git", "git is required to fetch the OpenTide explorer source")
    dest.parent.mkdir(parents=True, exist_ok=True)
    if (dest / ".git").is_dir() or (dest / ".git").is_file():
        _run(
            [git, "-C", str(dest), "fetch", "--depth", "1", "origin", ref],
            cwd=dest,
            what="Explorer git fetch",
        )
        _run(
            [git, "-C", str(dest), "checkout", "FETCH_HEAD"], cwd=dest, what="Explorer git checkout"
        )
    else:
        if dest.exists() and not is_explorer_source(dest):
            shutil.rmtree(dest)
        clone = [git, "clone", "--depth", "1", "--branch", ref, url, str(dest)]
        try:
            _run(clone, cwd=dest.parent, what="Explorer git clone")
        except RuntimeError:
            _run([git, "clone", url, str(dest)], cwd=dest.parent, what="Explorer git clone")
            _run([git, "-C", str(dest), "checkout", ref], cwd=dest, what="Explorer git checkout")
    if not is_explorer_source(dest):
        raise FileNotFoundError(f"Explorer source at {dest} is missing {_BUILD_SCRIPT}")
    return dest


def _require_cmd(name: str, message: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(message)
    return path


def _run(cmd: list[str], *, cwd: Path, what: str) -> None:
    logger.info("explorer_subprocess", command=cmd, cwd=str(cwd), step=what)
    try:
        subprocess.run(cmd, cwd=cwd, check=True)
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"{what} failed (exit {exc.returncode})") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(f"{what} failed: {exc}") from exc
