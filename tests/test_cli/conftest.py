"""Shared CLI test fixtures and helpers."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import (
    TIDE_CORPUS_MANIFEST,
    TIDE_CORPUS_ROOT,
    clear_runtime_caches,
    load_corpus_manifest,
    manifest_slices,
    migrate_tide_corpus_layout,
)
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.setup import skills_registry as skills_registry_mod
from opentide.cli.services.setup.skills_registry import SkillEntry

ROOT = Path(__file__).resolve().parents[2]

__all__ = [
    "TIDE_CORPUS_MANIFEST",
    "TIDE_CORPUS_ROOT",
    "clear_runtime_caches",
    "load_corpus_manifest",
    "manifest_slices",
    "migrate_tide_corpus_layout",
]


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
        clear_runtime_caches()
        return cli_runner.invoke(app, cmd, env=env, **kwargs)

    return _invoke


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
