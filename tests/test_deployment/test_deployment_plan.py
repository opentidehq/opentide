"""Deployment plan resolution for local CLI (issues #164, #300, #312)."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import (
    CORPUS_RULE_UUIDS,
    INERT_RULE_UUID,
    SUBFOLDER_RULE_UUIDS,
    add_unplanned_rules,
    classify_deploy_scope,
    clear_runtime_caches,
    materialise_corpus,
    real_rules_folder,
)

from opentide.models.deployment_enums import DeploymentStrategy, StatusStrategy

CI_VARIABLES = ("CI", "GITHUB_ACTIONS", "TF_BUILD")
LoggedEvent = tuple[str, str, dict[str, object]]


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


@pytest.fixture
def catalogue(
    request: pytest.FixtureRequest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """The corpus, run locally, plus rules in subfolders and an ``INERT`` one.

    Parametrise indirectly with ``"symlinked"`` to keep the corpus's
    ``objects/rules`` symlink instead of a real folder.
    """
    from opentide.core.registry import OpenTide

    repo = materialise_corpus(tmp_path / "corpus")
    if getattr(request, "param", "plain") == "plain":
        real_rules_folder(repo)
    add_unplanned_rules(repo / "objects" / "rules")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    clear_runtime_caches()
    OpenTide.reload()
    yield repo
    clear_runtime_caches()


@pytest.fixture
def plan_log(monkeypatch: pytest.MonkeyPatch) -> list[LoggedEvent]:
    """What ``make_deploy_plan`` logs, as ``(level, event, fields)``.

    Recorded at the logger: loggers cached on first use bypass ``capture_logs``.
    """
    from opentide.deployment import utils

    events: list[LoggedEvent] = []

    class _Recorder:
        def __getattr__(self, level: str):
            return lambda event, **fields: events.append((level, event, fields))

    monkeypatch.setattr(utils, "logger", _Recorder())
    return events


def _skipped_subfolder_logs(events: list[LoggedEvent]) -> list[tuple[str, dict[str, object]]]:
    return [
        (level, fields) for level, event, fields in events if event == "deploy_nested_rules_skipped"
    ]


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


def test_local_rule_scope_splits_top_level_and_subfolder_files(workspace: Path) -> None:
    from opentide.deployment.git_repo import RuleScope, local_rule_scope

    rules = workspace / "objects" / "rules"
    for name in (
        "a.yaml",
        "b.yml",
        ".gitkeep",
        "team-a/x.yaml",
        "team-a/deep/y.yml",
        "team-a/notes.md",
    ):
        (rules / name).parent.mkdir(parents=True, exist_ok=True)
        (rules / name).write_text("", encoding="utf-8")
    assert local_rule_scope() == RuleScope(
        files=(rules / "a.yaml", rules / "b.yml"),
        nested=("objects/rules/team-a/deep/y.yml", "objects/rules/team-a/x.yaml"),
    )


@pytest.mark.parametrize(
    ("plan", "planned"),
    [
        pytest.param(DeploymentStrategy.FULL, True, id="FULL"),
        pytest.param(DeploymentStrategy.STAGING, True, id="STAGING"),
        pytest.param(DeploymentStrategy.PRODUCTION, False, id="PRODUCTION"),
    ],
)
def test_make_deploy_plan_names_the_rule_files_in_subfolders(
    catalogue: Path, plan_log: list[LoggedEvent], plan: DeploymentStrategy, planned: bool
) -> None:
    """#312: a nested rule was left out of every plan without a word."""
    from opentide.deployment import make_deploy_plan

    warnings: list[str] = []
    deploy_plan = make_deploy_plan(plan, warnings=warnings)
    nested = [
        "objects/rules/team-a/deep/rule-0001-sentinel-kql.yaml",
        "objects/rules/team-a/rule-0101-subfolder.yaml",
    ]
    assert warnings == [
        "2 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/OpenTideHQ/opentide/issues/312): "
        + ", ".join(nested)
    ]
    assert _skipped_subfolder_logs(plan_log) == [
        (
            "info",
            {
                "count": 2,
                "files": nested,
                "issue": "https://github.com/OpenTideHQ/opentide/issues/312",
            },
        )
    ]
    planned_uuids = {uuid for uuids in deploy_plan.values() for uuid in uuids}
    assert planned_uuids.isdisjoint(SUBFOLDER_RULE_UUIDS.values())
    assert (CORPUS_RULE_UUIDS["sentinel"] in planned_uuids) is planned


def test_make_deploy_plan_without_a_warnings_list_logs_a_warning(
    catalogue: Path, plan_log: list[LoggedEvent]
) -> None:
    """Callers that cannot report the message (``validate query --live``) still see it."""
    from opentide.deployment import make_deploy_plan

    make_deploy_plan(DeploymentStrategy.FULL)
    assert [level for level, _ in _skipped_subfolder_logs(plan_log)] == ["warning"]


def test_subfolder_warning_caps_the_file_list(workspace: Path, plan_log: list[LoggedEvent]) -> None:
    from opentide.deployment import make_deploy_plan

    team = workspace / "objects" / "rules" / "team-a"
    team.mkdir(parents=True)
    for index in range(1, 8):
        (team / f"r{index}.yaml").write_text("", encoding="utf-8")
    warnings: list[str] = []
    assert make_deploy_plan(DeploymentStrategy.FULL, warnings=warnings) == {}
    assert warnings == [
        "7 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/OpenTideHQ/opentide/issues/312): "
        "objects/rules/team-a/r1.yaml, objects/rules/team-a/r2.yaml, "
        "objects/rules/team-a/r3.yaml, objects/rules/team-a/r4.yaml, "
        "objects/rules/team-a/r5.yaml, +2 more"
    ]
    ((_, fields),) = _skipped_subfolder_logs(plan_log)
    assert fields["files"] == [f"objects/rules/team-a/r{index}.yaml" for index in range(1, 8)]


@pytest.mark.parametrize(
    "plan", [DeploymentStrategy.STAGING, DeploymentStrategy.PRODUCTION], ids=lambda p: p.name
)
def test_ci_diff_plan_names_only_the_changed_subfolder_files(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan_log: list[LoggedEvent],
    plan: DeploymentStrategy,
) -> None:
    """In CI the plan is the git diff, so an unchanged nested rule is not news."""
    from opentide.deployment import git_repo, make_deploy_plan

    rules = workspace / "objects" / "rules"
    for name in ("team-a/changed.yaml", "team-b/unchanged.yaml"):
        (rules / name).parent.mkdir(parents=True, exist_ok=True)
        (rules / name).write_text("", encoding="utf-8")
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CI", "true")
    diff = [
        "objects/rules/team-a/changed.yaml",
        "objects/rules/team-a/notes.md",
        "objects/rules-archive/team-a/old.yaml",
        "objects/threats/team-a/threat.yaml",
        "docs/rules/team-a/page.yaml",
    ]
    monkeypatch.setattr(git_repo, "diff_calculation", lambda requested: diff)
    warnings: list[str] = []
    assert make_deploy_plan(plan, warnings=warnings) == {}
    assert warnings == [
        "1 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/OpenTideHQ/opentide/issues/312): "
        "objects/rules/team-a/changed.yaml"
    ]
    assert len(_skipped_subfolder_logs(plan_log)) == 1


@pytest.mark.parametrize("catalogue", ["plain", "symlinked"], indirect=True)
def test_full_plan_accounts_for_every_indexed_rule(catalogue: Path) -> None:
    """#312 guard: an indexed rule is planned, excluded by status, or named in a warning."""
    from opentide.core.registry import OpenTide
    from opentide.deployment import make_deploy_plan

    warnings: list[str] = []
    deploy_plan = make_deploy_plan(DeploymentStrategy.FULL, warnings=warnings)
    scope = classify_deploy_scope(
        catalogue,
        OpenTide.Models.rules,
        deploy_plan,
        warnings,
        excluded=frozenset({StatusStrategy.INERT}),
    )
    assert scope["silent"] == set()
    assert set(CORPUS_RULE_UUIDS.values()) <= scope["planned"]
    assert scope["status"] == {INERT_RULE_UUID}
    assert scope["warned"] == set(SUBFOLDER_RULE_UUIDS.values())
