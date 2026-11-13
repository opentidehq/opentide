"""Repository layout and bundled configuration sanity checks."""

from __future__ import annotations

import fnmatch
import importlib.util
import re
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

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


def _publish_dry_run_rules() -> ModuleType:
    """The dry-run workflow's own tests parse publish commands (every spelling npm
    accepts, options before the command, `npx npm@x publish`) and tell a dry run apart."""
    spec = importlib.util.spec_from_file_location(
        "publish_dry_run_rules", ROOT / "tests" / "test_ci" / "test_publish_dry_run_workflow.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_only_the_release_train_publishes() -> None:
    """The crates, the npm packages and the wheels publish from publish.yml, the
    release train (#840), which runs from Run workflow (and the resume
    dispatch) only: no tag starts it (tests/test_ci/test_one_ci.py checks every
    workflow's triggers). The engine's own engine-release.yml retired into it.

    Any other `cargo publish` or `npm publish` (in any spelling npm accepts) in an
    active workflow is a dry run: publish-dry-run.yml rehearses the publishes, and
    its own tests (tests/test_ci/test_publish_dry_run_workflow.py) keep it unable to
    publish."""
    rules = _publish_dry_run_rules()
    seen = 0
    for workflow in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        if workflow.name == "publish.yml":
            continue
        data = yaml.safe_load(workflow.read_text(encoding="utf-8")) or {}
        for job in (data.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                for command in rules._publishes(str(step.get("run", ""))):
                    seen += 1
                    assert rules._is_dry_run(command), (workflow.name, " ".join(command))
    assert seen, "the dry-run workflow's rehearsals are found, so the check reads the commands"
    assert not (ROOT / ".github" / "workflows" / "engine-release.yml").exists()
    release = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert re.search(r"release\.py publish", release)
    assert re.search(r"npm publish", release)
    assert "\non:\n  workflow_dispatch:\n" in release
    assert "\n  push:" not in release.split("\njobs:\n", 1)[0]


# Cargo's explicit target tables, with the folder and file name a target takes
# when its table gives no `path`.
_TARGET_TABLES = {
    "bin": ("src/bin", "main.rs"),
    "test": ("tests", "main.rs"),
    "example": ("examples", "main.rs"),
    "bench": ("benches", "main.rs"),
}


def _sdist_excludes() -> list[str]:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return list(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["exclude"])


def _excluded(relative: str, patterns: list[str]) -> bool:
    """Whether hatchling leaves *relative* (a `/`-separated path from the root)
    out of the sdist: an anchored pattern names a path or a folder above it,
    each `*` standing for one path segment."""
    parts = relative.split("/")
    for pattern in patterns:
        wanted = pattern.strip("/").split("/")
        if len(wanted) <= len(parts) and all(
            fnmatch.fnmatchcase(part, glob)
            for part, glob in zip(parts[: len(wanted)], wanted, strict=True)
        ):
            return True
    return False


def _declared_target_files(member: str, manifest: dict[str, object]) -> list[str]:
    """The source files *member*'s manifest names in its explicit `[lib]`,
    `[[bin]]`, `[[test]]`, `[[example]]` and `[[bench]]` tables: cargo reads
    them whenever it parses the manifest."""
    files: list[str] = []
    lib = manifest.get("lib")
    if isinstance(lib, dict):
        files.append(f"{member}/{lib.get('path', 'src/lib.rs')}")
    for table, (folder, main) in _TARGET_TABLES.items():
        for target in manifest.get(table, []) or []:
            assert isinstance(target, dict), (member, table, target)
            if "path" in target:
                files.append(f"{member}/{target['path']}")
                continue
            name = target["name"]
            single = f"{member}/{folder}/{name}.rs"
            files.append(
                single if (ROOT / single).is_file() else f"{member}/{folder}/{name}/{main}"
            )
    return files


def test_the_sdist_ships_every_target_a_workspace_manifest_names() -> None:
    """A `[[test]]` table naming a file under `crates/*/tests`, which the sdist
    leaves out, stopped every build from the sdist: cargo would not parse the
    manifest (#963). Cargo discovers a crate's tests by itself; a table may name
    only a file the sdist ships."""
    root = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    patterns = _sdist_excludes()
    problems: list[str] = []
    for member in root["workspace"]["members"]:
        manifest = tomllib.loads((ROOT / member / "Cargo.toml").read_text(encoding="utf-8"))
        for relative in _declared_target_files(member, manifest):
            if not (ROOT / relative).is_file():
                problems.append(f"{member}/Cargo.toml names {relative}, which does not exist")
            elif _excluded(relative, patterns):
                problems.append(f"{member}/Cargo.toml names {relative}, which the sdist leaves out")
    assert problems == []


def test_the_target_check_sees_a_test_table_the_sdist_leaves_out() -> None:
    patterns = _sdist_excludes()
    manifest: dict[str, object] = {
        "test": [{"name": "api"}, {"name": "absent"}],
        "bench": [{"name": "x", "path": "b.rs"}],
    }
    files = _declared_target_files("crates/opentide", manifest)
    assert files == [
        "crates/opentide/tests/api.rs",
        "crates/opentide/tests/absent/main.rs",
        "crates/opentide/b.rs",
    ]
    assert _excluded("crates/opentide/tests/api.rs", patterns)
    assert _excluded("crates/opentide/tests/api/main.rs", patterns)
    assert not _excluded("crates/opentide/examples/validate.rs", patterns)
    assert not _excluded("crates/opentide/src/lib.rs", patterns)
