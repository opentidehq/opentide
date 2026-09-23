"""Deployment plan resolution for local CLI (issues #164, #300)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches

from opentide.models.deployment_enums import DeploymentStrategy


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An empty workspace the registry resolves ``objects/rules`` against."""
    from opentide.core.registry import OpenTide

    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    clear_runtime_caches()
    OpenTide.reload()
    yield tmp_path
    clear_runtime_caches()


def test_load_from_environment_defaults_to_full_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DEPLOYMENT_PLAN", raising=False)
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.FULL


def test_load_from_environment_defaults_to_full_when_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "  ")
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.FULL


def test_load_from_environment_accepts_named_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "staging")
    assert DeploymentStrategy.load_from_environment() is DeploymentStrategy.STAGING


def test_load_from_environment_rejects_python_none_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "None")
    with pytest.raises(ValueError, match="Unsupported deployment plan"):
        DeploymentStrategy.load_from_environment()


def test_load_from_environment_rejects_unknown_plan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPLOYMENT_PLAN", "CANARY")
    with pytest.raises(ValueError, match="CANARY"):
        DeploymentStrategy.load_from_environment()


def test_local_rule_files_without_rules_folder_is_empty(workspace: Path) -> None:
    from opentide.deployment.git_repo import local_rule_files

    assert not (workspace / "objects" / "rules").exists()
    assert local_rule_files() == []


def test_local_rule_files_lists_only_rule_yaml_under_the_folder(workspace: Path) -> None:
    """``.gitkeep`` was parsed as a rule, and a subfolder raised ``[Errno 21]``."""
    from opentide.deployment.git_repo import local_rule_files

    rules = workspace / "objects" / "rules"
    (rules / "nested").mkdir(parents=True)
    (rules / "folder.yaml").mkdir()
    for name in ("b.yml", "a.yaml", ".gitkeep", "README.md", "nested/c.yaml"):
        (rules / name).write_text("", encoding="utf-8")
    assert local_rule_files() == [rules / "a.yaml", rules / "b.yml"]


@pytest.mark.parametrize(
    "plan",
    [DeploymentStrategy.FULL, DeploymentStrategy.STAGING, DeploymentStrategy.PRODUCTION],
    ids=lambda plan: plan.name,
)
@pytest.mark.parametrize("rules_folder", ["missing", "gitkeep-only"])
def test_make_deploy_plan_with_no_rules_is_empty(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan: DeploymentStrategy,
    rules_folder: str,
) -> None:
    """FULL listed ``objects/rules`` directly: ``[Errno 2]`` when it was absent (#300)."""
    from opentide.deployment import make_deploy_plan

    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    if rules_folder == "gitkeep-only":
        rules = workspace / "objects" / "rules"
        rules.mkdir(parents=True)
        (rules / ".gitkeep").touch()
    assert make_deploy_plan(plan) == {}


def test_debug_promotion_without_rules_folder_promotes_nothing(
    workspace: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The VS Code (``DEBUG``) branch re-listed ``objects/rules`` with ``os.listdir``."""
    from opentide.mutation import promotion

    monkeypatch.setattr(promotion, "DEBUG", True)
    monkeypatch.setattr(promotion, "PROMOTION_ENABLED", True)
    edited: list[Path] = []
    monkeypatch.setattr(
        promotion.PromoteMDR,
        "edit_mdr_statuses",
        lambda self, mdr_path, status_to_promote: edited.append(mdr_path),
    )
    promotion.PromoteMDR().promote([])
    assert edited == []
