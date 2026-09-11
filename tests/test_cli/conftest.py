"""Shared CLI test fixtures and helpers."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.setup import skills_registry as skills_registry_mod
from opentide.cli.services.setup.skills_registry import SkillEntry
from opentide.core.io import load_toml

ROOT = Path(__file__).resolve().parents[2]
TIDE_CORPUS_ROOT = ROOT / "tests/fixtures/tide_corpus/current"
TIDE_CORPUS_MANIFEST = ROOT / "tests/fixtures/tide_corpus/manifest.toml"


@pytest.fixture
def cli_runner() -> CliRunner:
    return CliRunner()


def default_remote_skill_entries() -> list[SkillEntry]:
    """Minimal live-catalogue stand-in used by setup tests."""
    return [
        SkillEntry(
            name="OpenTide Detection Rule",
            slug="opentide-detection-rule",
            description="Authors OpenTide Detection Rule YAML",
        ),
        SkillEntry(
            name="Detection Engineering",
            slug="detection-engineering",
            description="Detection engineering lifecycle",
        ),
        SkillEntry(
            name="Kusto Query Language",
            slug="kusto-query-language",
            description="KQL patterns",
        ),
    ]


def stub_remote_skills_manifest(
    monkeypatch: pytest.MonkeyPatch,
    entries: list[SkillEntry] | None = None,
    *,
    ref: str = "main",
) -> list[SkillEntry]:
    """Point catalogue discovery at a fake remote manifest (no packaged fallback)."""
    resolved = list(entries) if entries is not None else default_remote_skill_entries()
    monkeypatch.setattr(
        skills_registry_mod,
        "_fetch_remote_manifest",
        lambda **_: ("OpenTideHQ/skills", ref, resolved),
    )
    skills_registry_mod.clear_manifest_cache()
    return resolved


@pytest.fixture
def mock_skill_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid network calls when tests install skills from OpenTideHQ/skills."""

    def _fake(slug: str, dest: Path, *, source: str, ref: str) -> list[str]:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "SKILL.md").write_text(f"# {slug} ({source}@{ref})\n", encoding="utf-8")
        return ["SKILL.md"]

    stub_remote_skills_manifest(monkeypatch)
    monkeypatch.setattr("opentide.cli.services.setup.skills._download_skill", _fake)
    monkeypatch.setattr(
        "opentide.cli.services.setup.skills.fetch_github_bytes",
        lambda path, **_: None,
    )


@pytest.fixture
def tide_corpus_root() -> Path:
    return TIDE_CORPUS_ROOT


def _symlink_dir(link: Path, target: Path) -> None:
    """Point ``link`` at directory ``target``, copying when symlinks are unavailable."""
    if link.exists() or link.is_symlink():
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    rel = Path(os.path.relpath(target.resolve(), link.parent.resolve()))
    try:
        link.symlink_to(rel, target_is_directory=True)
    except OSError:
        # Windows rejects symlink creation without Developer Mode or elevation.
        shutil.copytree(target, link)


def _migrate_tide_corpus_layout(dest: Path) -> None:
    """Adapt legacy tide_corpus fixture to greenfield ``.opentide/`` layout."""
    opentide = dest / ".opentide"
    opentide.mkdir(exist_ok=True)

    legacy_configs = dest / "Configurations"
    if legacy_configs.is_dir():
        shutil.copytree(legacy_configs, opentide / "configurations", dirs_exist_ok=True)

    object_links = {
        "objects/threats": "Objects/Threat Vectors",
        "objects/objectives": "Objects/Detection Objectives",
        "objects/rules": "Objects/Detection Rules",
    }
    for link_rel, target_rel in object_links.items():
        _symlink_dir(dest / link_rel, dest / target_rel)

    opentide.joinpath("schemas").mkdir(exist_ok=True)
    opentide.joinpath("templates").mkdir(exist_ok=True)
    opentide.joinpath("exports").mkdir(exist_ok=True)
    opentide.joinpath("inflight").mkdir(exist_ok=True)


def _clear_runtime_caches() -> None:
    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import OpenTide
    from opentide.core.root import get_data_root, get_repo_root

    get_repo_root.cache_clear()
    get_data_root.cache_clear()
    IndexManager._cache = None
    OpenTide._initialised = False
    OpenTide._objects_loaded = False
    OpenTide._index = None
    OpenTide._rules = {}
    OpenTide._threats = {}
    OpenTide._objectives = {}


@pytest.fixture
def tide_corpus_repo(
    tide_corpus_root: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """Copy tide_corpus into an isolated repo and wire OpenTide path env vars."""
    dest = tmp_path / "corpus"
    shutil.copytree(tide_corpus_root, dest)
    _migrate_tide_corpus_layout(dest)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(dest))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(dest))
    monkeypatch.setenv("DEPLOYMENT_PLAN", "FULL")
    monkeypatch.setenv("CI", "true")
    _clear_runtime_caches()
    yield dest
    _clear_runtime_caches()


def parse_cli_json(result: Result) -> dict[str, Any]:
    text = result.stdout.strip()
    assert text, "expected JSON on stdout"
    payload = json.loads(text)
    assert isinstance(payload, dict)
    return payload


def assert_json_ok(result: Result) -> dict[str, Any]:
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = parse_cli_json(result)
    if "ok" in payload:
        assert payload["ok"] is True
    return payload


@pytest.fixture
def invoke_cli(cli_runner: CliRunner, tide_corpus_repo: Path) -> Callable[..., Result]:
    def _invoke(
        *args: str,
        repo: Path | None = None,
        json_output: bool = True,
        extra_env: dict[str, str] | None = None,
        **kwargs: Any,
    ) -> Result:
        cmd: list[str] = []
        if json_output:
            cmd.append("--json")
        if repo is not None:
            cmd.extend(["--repo", str(repo)])
        else:
            cmd.extend(["--repo", str(tide_corpus_repo)])
        cmd.extend(args)
        env = kwargs.pop("env", None)
        if env is None:
            repo_path = str(repo if repo is not None else tide_corpus_repo)
            env = {
                "OPENTIDE_REPO_ROOT": repo_path,
                "OPENTIDE_TIDE_WORKSPACE": repo_path,
                "DEPLOYMENT_PLAN": "FULL",
            }
            if "PATH" in os.environ:
                env["PATH"] = os.environ["PATH"]
        if extra_env:
            env = {**env, **extra_env}
        _clear_runtime_caches()
        return cli_runner.invoke(app, cmd, env=env, **kwargs)

    return _invoke


def load_corpus_manifest() -> dict[str, Any]:
    return load_toml(TIDE_CORPUS_MANIFEST)


def manifest_slices(*, status: str | None = None) -> list[dict[str, Any]]:
    manifest = load_corpus_manifest()
    slices = manifest.get("slices", [])
    if status is None:
        return slices
    return [slice_info for slice_info in slices if slice_info.get("status") == status]


@pytest.fixture
def corpus_rule_uuids() -> dict[str, str]:
    return {
        "sentinel": "00000000-0000-4000-8003-000000000001",
        "defender_for_endpoint": "00000000-0000-4000-8003-000000000002",
        "splunk": "00000000-0000-4000-8003-000000000003",
        "sentinel_one": "00000000-0000-4000-8003-000000000004",
        "carbon_black_cloud": "00000000-0000-4000-8003-000000000005",
        "crowdstrike": "00000000-0000-4000-8003-000000000006",
        "harfanglab": "00000000-0000-4000-8003-000000000007",
    }


@pytest.fixture
def mock_query_validators(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid live API calls during validate query E2E tests."""

    class _NoOpValidator:
        def validate(self, **kwargs: object) -> None:
            return None

    validators = {
        platform: _NoOpValidator()
        for platform in (
            "sentinel",
            "defender_for_endpoint",
            "splunk",
            "sentinel_one",
            "carbon_black_cloud",
        )
    }

    class _MockDeployTide:
        @property
        def query_validation(self) -> dict[str, _NoOpValidator]:
            return validators

    monkeypatch.setattr("opentide.platforms.plugins.DeployTide", _MockDeployTide)


@pytest.fixture
def query_validation_matrix() -> Sequence[tuple[str, bool]]:
    return (
        ("sentinel", True),
        ("defender_for_endpoint", True),
        ("splunk", True),
        ("sentinel_one", True),
        ("carbon_black_cloud", True),
        ("crowdstrike", False),
        ("harfanglab", False),
    )
