"""Data path resolution and enabled systems."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.core.files import resolve_configurations, resolve_paths
from opentide.core.root import find_repo_root, find_workspace_root, get_data_root, get_repo_root
from opentide.platforms.enabled import enabled_systems


@pytest.fixture(autouse=True)
def _clear_root_caches() -> None:
    get_data_root.cache_clear()
    get_repo_root.cache_clear()
    yield
    get_data_root.cache_clear()
    get_repo_root.cache_clear()


def test_resolve_configurations_includes_bundled_platforms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    configs = resolve_configurations()
    systems = configs.get("systems", {})
    assert "sentinel" in systems
    assert systems["sentinel"]["platform"]["identifier"] == "sentinel"


def test_resolve_paths_uses_bundled_vocabulary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    paths = resolve_paths()
    assert paths["vocabularies"] == get_data_root() / "vocabulary"
    assert paths["resources"] == get_data_root() / "external"
    assert paths["platform_configs"] == get_data_root() / "configurations" / "platforms"


def test_enabled_systems_reads_merged_config(monkeypatch: pytest.MonkeyPatch) -> None:
    repo = Path(__file__).resolve().parents[2]
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    systems = enabled_systems()
    assert isinstance(systems, list)


def test_find_repo_root_detects_git_directory(tmp_path: Path) -> None:
    nested = tmp_path / "nested" / "project"
    nested.mkdir(parents=True)
    (tmp_path / ".git").mkdir()
    assert find_repo_root(nested) == tmp_path


def test_find_repo_root_falls_back_to_start_when_no_git(tmp_path: Path) -> None:
    nested = tmp_path / "only" / "here"
    nested.mkdir(parents=True)
    assert find_repo_root(nested) == nested


def _dirs(base: Path, *relative: str) -> None:
    for rel in relative:
        (base / rel).mkdir(parents=True, exist_ok=True)


def test_find_repo_root_is_the_checkout_not_a_nested_workspace(tmp_path: Path) -> None:
    """Git operations need the work tree root even when a workspace sits below it."""
    base = tmp_path.resolve()
    _dirs(base, ".git", "detections/.opentide", "detections/objects/rules")
    assert find_repo_root(base / "detections" / "objects" / "rules") == base


@pytest.mark.parametrize(
    "start",
    [".", "objects", "objects/rules", ".opentide/configurations/platforms", "docs"],
)
def test_find_workspace_root_walks_up_a_scaffold_outside_git(tmp_path: Path, start: str) -> None:
    """#294: from ``objects/rules`` the cwd itself was the root, and 0 objects validated."""
    scaffold = tmp_path.resolve() / "scaffold"
    _dirs(scaffold, ".opentide/configurations/platforms", "objects/rules", "docs")
    assert find_workspace_root(scaffold / start) == scaffold


@pytest.mark.parametrize("start", ["detections", "detections/objects/rules"])
def test_find_workspace_root_prefers_a_workspace_nested_in_a_checkout(
    tmp_path: Path, start: str
) -> None:
    """#294: a workspace below the git root resolved to the git root, which holds no objects."""
    mono = tmp_path.resolve() / "monorepo"
    _dirs(mono, ".git", "detections/.opentide", "detections/objects/rules")
    assert find_workspace_root(mono / start) == mono / "detections"


@pytest.mark.parametrize("start", [".", "docs/guides"])
def test_find_workspace_root_keeps_the_git_root_when_nothing_is_marked(
    tmp_path: Path, start: str
) -> None:
    mono = tmp_path.resolve() / "monorepo"
    _dirs(mono, ".git/objects", "docs/guides")
    assert find_workspace_root(mono / start) == mono


def test_find_workspace_root_does_not_climb_out_of_the_checkout(tmp_path: Path) -> None:
    """Markers above the enclosing git root belong to another tree."""
    base = tmp_path.resolve()
    _dirs(base, ".opentide", "objects", "checkout/.git", "checkout/src")
    assert find_workspace_root(base / "checkout" / "src") == base / "checkout"


def test_find_workspace_root_ignores_the_git_object_store(tmp_path: Path) -> None:
    """``.git/objects`` is git's object store, not a catalogue."""
    repo = tmp_path.resolve() / "repo"
    _dirs(repo, ".git/objects/pack", ".git/hooks")
    assert find_workspace_root(repo / ".git") == repo
    assert find_workspace_root(repo / ".git" / "hooks") == repo
    assert find_workspace_root(repo / ".git" / "objects" / "pack") == repo


def test_find_workspace_root_ignores_a_python_package_named_objects(tmp_path: Path) -> None:
    """OpenTide's own ``src/opentide/documentation/objects`` is source, not a catalogue."""
    repo = tmp_path.resolve() / "repo"
    _dirs(repo, ".git", ".opentide", "src/pkg/objects")
    (repo / "src" / "pkg" / "objects" / "__init__.py").write_text("", encoding="utf-8")
    assert find_workspace_root(repo / "src" / "pkg") == repo
    assert find_workspace_root(repo / "src" / "pkg" / "objects") == repo


def test_find_workspace_root_nearest_marker_wins(tmp_path: Path) -> None:
    outer = tmp_path.resolve() / "outer"
    _dirs(outer, ".git", ".opentide", "objects", "team/objects/rules", "other/.opentide/schemas")
    assert find_workspace_root(outer / "team" / "objects" / "rules") == outer / "team"
    assert find_workspace_root(outer / "other" / ".opentide" / "schemas") == outer / "other"
    assert find_workspace_root(outer / "objects") == outer
    assert find_workspace_root(outer) == outer


@pytest.mark.parametrize("marker", [".opentide", "objects"])
def test_find_workspace_root_accepts_either_marker(tmp_path: Path, marker: str) -> None:
    workspace = tmp_path.resolve() / "workspace"
    _dirs(workspace, marker, "notes/drafts")
    assert find_workspace_root(workspace / "notes" / "drafts") == workspace


def test_find_workspace_root_stops_at_a_git_file(tmp_path: Path) -> None:
    """Submodules and linked worktrees mark their root with a ``.git`` file."""
    base = tmp_path.resolve()
    _dirs(base, ".opentide", "sub/pkg")
    (base / "sub" / ".git").write_text("gitdir: ../.git/modules/sub\n", encoding="utf-8")
    assert find_workspace_root(base / "sub" / "pkg") == base / "sub"


def test_find_workspace_root_falls_back_to_start_outside_git(tmp_path: Path) -> None:
    nested = tmp_path.resolve() / "only" / "here"
    nested.mkdir(parents=True)
    assert find_workspace_root(nested) == nested
