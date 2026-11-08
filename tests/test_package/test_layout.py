"""Repository layout and bundled configuration sanity checks."""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest

from opentide.core.files import tomllib

ROOT = Path(__file__).resolve().parents[2]

FORBIDDEN_ROOT_DIRS = {
    "Configurations",
    "Engines",
    "External",
    "Framework",
    "Orchestration",
    "Pipelines",
}

REQUIRED_ROOT_DIRS = {
    "src",
    "tests",
    "docs",
}

FORBIDDEN_WORKFLOW_TOKENS = (
    "opentidehq/CoreTide",
    "coretide/Orchestration",
    "TIDE_CORE_REPO",
    "Engines/requirements.txt",
)


def test_no_legacy_root_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir() and not p.name.startswith(".")}
    assert FORBIDDEN_ROOT_DIRS.isdisjoint(present), present & FORBIDDEN_ROOT_DIRS


def test_required_layout_directories() -> None:
    present = {p.name for p in ROOT.iterdir() if p.is_dir()}
    assert present >= REQUIRED_ROOT_DIRS


def test_package_workflows_have_no_coretide_dependencies() -> None:
    workflows = ROOT / ".github" / "workflows"
    if not workflows.is_dir():
        return
    for workflow in workflows.glob("*.yml"):
        text = workflow.read_text(encoding="utf-8")
        for token in FORBIDDEN_WORKFLOW_TOKENS:
            assert token not in text, f"{workflow.name} references legacy CoreTide CI: {token}"


def test_no_legacy_client_pipeline_directory() -> None:
    assert not (ROOT / ".github" / "pipelines").exists()


def test_paths_toml_is_the_only_bundled_layout() -> None:
    configurations = ROOT / "src/opentide/data/configurations"
    assert not (configurations / "global.toml").exists()
    assert not (configurations / "schema.toml").exists()
    text = (configurations / "paths.toml").read_text(encoding="utf-8")
    assert 'objects = ["threat", "objective", "rule"]' in text
    assert "recomposition" not in text
    assert "Framework/Vocabulary" not in text


def test_engines_package_absorbed() -> None:
    assert not (ROOT / "src" / "Engines").exists()


def _ignored(paths: list[str]) -> set[str]:
    """The paths .gitignore hides, whether or not they exist (hatchling leaves
    the same ones out of the sdist)."""
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin"],
        cwd=ROOT,
        input="\n".join(paths),
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert result.returncode in (0, 1), result.stderr
    return set(result.stdout.split())


def test_gitignore_hides_no_source_named_like_a_tool_output() -> None:
    """language-server's unanchored `coverage` rule hid any file or directory of that
    name, such as a Rust module crates/<crate>/src/coverage/, from git and the sdist."""
    sources = [
        "crates/opentide-workspace/src/coverage/mod.rs",
        "crates/opentide-analysis/src/coverage.rs/x",
        "src/opentide/coverage/__init__.py",
        "data/catalogs/coverage/techniques.toml",
        "data/catalogs/tide/generated/fields.json",
        "highlights/generated/kql.tmLanguage.json",
    ]
    assert _ignored(sources) == set()
    outputs = ["coverage/index.html", "lcov.info", "htmlcov/index.html", "target/debug/x"]
    assert _ignored(outputs) == set(outputs)


def _engine_release_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "engine_release", ROOT / "scripts" / "engine" / "release.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_gitignore_keeps_every_file_cargo_package_needs() -> None:
    """`scripts/engine/release.py vendor` copies each engine crate's assets and
    legal files into the crate, and `cargo package` leaves out what .gitignore
    hides: opentide's `generated/` rule dropped
    assets/data/catalogs/tide/generated/fields.json from opentide-highlight."""
    release = _engine_release_script()
    root = ROOT.resolve()
    vendored: list[str] = []
    for package in release.publishable_crates():
        crate = Path(package["manifest_path"]).resolve().parent.relative_to(root)
        vendored += [(crate / name).as_posix() for name in release.LEGAL]
        for rel in release.crate_assets(package):
            source = root / rel
            files = [source] if source.is_file() else sorted(source.rglob("*"))
            vendored += [
                (crate / "assets" / path.relative_to(root)).as_posix()
                for path in files
                if path.is_file()
            ]
    assert len(vendored) > 100
    assert sorted(_ignored(vendored)) == []


def test_engine_release_script_loads_without_tomllib(monkeypatch: pytest.MonkeyPatch) -> None:
    """The test above loads release.py on every Python opentide supports, 3.10
    included, which has no tomllib: the script falls back to tomli there."""
    monkeypatch.setitem(sys.modules, "tomllib", None)  # `import tomllib` fails, as on 3.10
    release = _engine_release_script()
    assert release.tomllib.__name__ == "tomli"
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    assert release.workspace_version() == workspace["workspace"]["package"]["version"]


def test_gitignore_hides_no_tracked_file() -> None:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--ignored", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    assert result.stdout.split() == []


def test_the_wheel_ships_every_licence_notice_cites() -> None:
    """NOTICE names the licence and notice files of the data the engine embeds
    (Apache-2.0 4(a) and 4(d)): each ships beside it in the wheel's licenses/."""
    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    cited = set(re.findall(r"data/catalogs/[\w/-]+/(?:LICENSE[\w.-]*|NOTICE)\b", notice))
    assert cited, "NOTICE cites the catalogs' licence files"
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    shipped = set(pyproject["project"]["license-files"])
    assert {"LICENSE", "NOTICE"} <= shipped
    assert cited <= shipped, sorted(cited - shipped)
    assert all((ROOT / path).is_file() for path in shipped)


def test_only_the_engine_release_publishes_the_engine() -> None:
    """The engine's crates and npm packages publish from engine-release.yml, which
    runs on `engine-v*` tags (and Run workflow) only: `v*` tags are opentide's own
    releases (tests/test_ci/test_one_ci.py checks every workflow's triggers)."""
    publishing = sorted(
        workflow.name
        for workflow in (ROOT / ".github" / "workflows").glob("*.yml")
        if re.search(r"cargo publish|release\.py publish|npm publish", workflow.read_text("utf-8"))
    )
    assert publishing == ["engine-release.yml"]
    text = (ROOT / ".github" / "workflows" / "engine-release.yml").read_text(encoding="utf-8")
    assert '  push:\n    tags:\n      - "engine-v*"\n  workflow_dispatch:' in text
