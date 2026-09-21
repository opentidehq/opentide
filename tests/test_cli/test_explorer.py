"""Explorer source resolution and CLI build/dev/serve services."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.cli.services import explorer as explorer_svc
from opentide.cli.services.explorer import ExplorerSourceOptions, resolve_explorer_source


@pytest.fixture(autouse=True)
def _clear_explorer_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "EXPLORER_GIT_URL",
        "EXPLORER_GIT_REF",
        "OPENTIDE_EXPLORER_PATH",
        "EXPLORER_VERSION",
    ):
        monkeypatch.delenv(key, raising=False)


def _fake_explorer(root: Path) -> Path:
    src = root / "explorer"
    (src / "bin").mkdir(parents=True)
    (src / "bin" / "build.mjs").write_text("// explorer build", encoding="utf-8")
    return src


def test_resolve_prefers_explicit_git_over_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _clone(url: str, ref: str, dest: Path) -> Path:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "bin").mkdir(exist_ok=True)
        (dest / "bin" / "build.mjs").write_text("//", encoding="utf-8")
        assert url == "https://example.com/explorer.git"
        assert ref == "feature"
        return dest

    monkeypatch.setattr(explorer_svc, "_clone_explorer", _clone)
    local = _fake_explorer(tmp_path)
    result = resolve_explorer_source(
        ExplorerSourceOptions(
            explorer_git="https://example.com/explorer.git",
            explorer_ref="feature",
            explorer_path=local,
            repo_root=tmp_path / "library",
            cache_dir=tmp_path / "cache" / "explorer-src",
        )
    )
    assert result == (tmp_path / "cache" / "explorer-src")


def test_resolve_uses_explicit_path(tmp_path: Path) -> None:
    src = _fake_explorer(tmp_path)
    result = resolve_explorer_source(
        ExplorerSourceOptions(explorer_path=src, repo_root=tmp_path / "library")
    )
    assert result == src.resolve()


def test_resolve_explicit_path_missing_build_script(tmp_path: Path) -> None:
    empty = tmp_path / "not-explorer"
    empty.mkdir()
    with pytest.raises(FileNotFoundError, match="missing bin/build.mjs"):
        resolve_explorer_source(
            ExplorerSourceOptions(explorer_path=empty, repo_root=tmp_path / "library")
        )


def test_resolve_sibling_checkout(tmp_path: Path) -> None:
    library = tmp_path / "library"
    library.mkdir()
    src = _fake_explorer(tmp_path)
    result = resolve_explorer_source(ExplorerSourceOptions(repo_root=library))
    assert result == src.resolve()


def test_resolve_env_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_explorer(tmp_path)
    monkeypatch.setenv("OPENTIDE_EXPLORER_PATH", str(src))
    result = resolve_explorer_source(ExplorerSourceOptions(repo_root=tmp_path / "library"))
    assert result == src.resolve()


def test_resolve_version_clones_default_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, str, Path]] = []

    def _clone(url: str, ref: str, dest: Path) -> Path:
        seen.append((url, ref, dest))
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "bin").mkdir(exist_ok=True)
        (dest / "bin" / "build.mjs").write_text("//", encoding="utf-8")
        return dest

    monkeypatch.setattr(explorer_svc, "_clone_explorer", _clone)
    cache = tmp_path / "cache" / "explorer-src"
    result = resolve_explorer_source(
        ExplorerSourceOptions(
            version="v1.2.3",
            repo_root=tmp_path / "library",
            cache_dir=cache,
        )
    )
    assert seen == [(explorer_svc.DEFAULT_EXPLORER_GIT, "v1.2.3", cache)]
    assert result == cache


def test_run_explorer_build_invokes_node(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_explorer(tmp_path)
    (src / "node_modules").mkdir()
    repo = tmp_path / "library"
    exports = repo / ".opentide" / "exports"
    exports.mkdir(parents=True)
    (exports / "explorer.bundle.json").write_text("{}", encoding="utf-8")
    (repo / ".opentide" / "schemas").mkdir(parents=True)
    output = tmp_path / "out" / "explorer"
    calls: list[list[str]] = []

    monkeypatch.setattr(
        explorer_svc, "generate_explorer_exports", lambda export_dir: (export_dir, export_dir)
    )
    monkeypatch.setattr(explorer_svc, "_require_cmd", lambda name, message: f"/usr/bin/{name}")
    monkeypatch.setattr(
        explorer_svc,
        "_run",
        lambda cmd, cwd, what: calls.append(list(cmd)),
    )

    result = explorer_svc.run_explorer_build(
        output=output,
        base_path="/library",
        exports_dir=exports,
        skip_install=True,
        source_options=ExplorerSourceOptions(explorer_path=src, repo_root=repo),
    )
    assert result["output"] == str(output.resolve())
    assert calls
    cmd = calls[0]
    assert cmd[0] == "/usr/bin/node"
    assert "build" in cmd
    assert "--exports-dir" in cmd
    assert "--output" in cmd
    assert "--base-path" in cmd
    assert "/library" in cmd


def test_run_explorer_build_requires_node(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_explorer(tmp_path)
    repo = tmp_path / "library"
    exports = repo / ".opentide" / "exports"
    exports.mkdir(parents=True)
    (exports / "explorer.bundle.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        explorer_svc, "generate_explorer_exports", lambda export_dir: (export_dir, export_dir)
    )
    monkeypatch.setattr(
        explorer_svc,
        "_require_cmd",
        lambda name, message: (_ for _ in ()).throw(RuntimeError(message)),
    )
    with pytest.raises(RuntimeError, match="node is required"):
        explorer_svc.run_explorer_build(
            skip_install=True,
            source_options=ExplorerSourceOptions(explorer_path=src, repo_root=repo),
            exports_dir=exports,
        )


def test_run_explorer_serve_requires_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "library"
    repo.mkdir()
    with pytest.raises(FileNotFoundError, match="Explorer output not found"):
        explorer_svc.run_explorer_serve(
            output=repo / "out" / "explorer",
            source_options=ExplorerSourceOptions(repo_root=repo),
        )


def test_run_explorer_dev_syncs_exports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = _fake_explorer(tmp_path)
    (src / "node_modules").mkdir()
    repo = tmp_path / "library"
    exports = repo / ".opentide" / "exports"
    exports.mkdir(parents=True)
    (exports / "explorer.bundle.json").write_text("{}", encoding="utf-8")
    (exports / "explorer.search.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(
        explorer_svc, "generate_explorer_exports", lambda export_dir: (export_dir, export_dir)
    )
    monkeypatch.setattr(explorer_svc, "_require_cmd", lambda name, message: f"/usr/bin/{name}")
    monkeypatch.setattr(explorer_svc, "_run", lambda cmd, cwd, what: None)
    explorer_svc.run_explorer_dev(
        exports_dir=exports,
        skip_install=True,
        source_options=ExplorerSourceOptions(explorer_path=src, repo_root=repo),
    )
    copied = src / "public" / "data" / "explorer.bundle.json"
    assert copied.is_file()
    assert (src / "public" / "data" / "explorer.search.json").is_file()
