"""Run strategies, rule selection and tenant resolution for deploy (#164, #300, #312)."""

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

from opentide.deployment.git_repo import DiffSource
from opentide.models.deployment_enums import (
    DEPLOYABLE_STRATEGIES,
    REMOVED_PLAN_ENV,
    StatusStrategy,
    deployed_by,
    deploys,
    parse_strategies,
    removed_plan_message,
)

CI_VARIABLES = ("CI", "GITHUB_ACTIONS", "TF_BUILD")
LoggedEvent = tuple[str, str, dict[str, object]]


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """An empty workspace the registry resolves ``objects/rules`` against."""
    from opentide.core.registry import Opentide

    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(tmp_path))
    clear_runtime_caches()
    Opentide.reload()
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
    from opentide.core.registry import Opentide

    repo = materialise_corpus(tmp_path / "corpus")
    if getattr(request, "param", "plain") == "plain":
        real_rules_folder(repo)
    add_unplanned_rules(repo / "objects" / "rules")
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    clear_runtime_caches()
    Opentide.reload()
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


S = StatusStrategy
BOTH = DEPLOYABLE_STRATEGIES

#: ``deploys(rule, run)``: which run strategy acts on a rule whose status maps to each strategy.
_DEPLOYS = {
    S.PREVIEW: {S.PREVIEW},
    S.RELEASE: {S.RELEASE},
    S.UNIVERSAL: {S.PREVIEW, S.RELEASE},
    S.DISABLEMENT: {S.RELEASE},
    S.DELETION: {S.RELEASE},
    S.INERT: set(),
}


def test_deployable_strategies_are_preview_then_release() -> None:
    assert DEPLOYABLE_STRATEGIES == (S.PREVIEW, S.RELEASE)


@pytest.mark.parametrize("run", list(StatusStrategy), ids=lambda s: f"run-{s.name}")
@pytest.mark.parametrize("rule", list(StatusStrategy), ids=lambda s: f"rule-{s.name}")
def test_deploys_truth_table(rule: StatusStrategy, run: StatusStrategy) -> None:
    """Only PREVIEW and RELEASE runs deploy anything; INERT is never deployed."""
    assert deploys(rule, run) is (run in _DEPLOYS[rule])


@pytest.mark.parametrize(
    ("rule", "runs"),
    [
        (S.PREVIEW, (S.PREVIEW,)),
        (S.RELEASE, (S.RELEASE,)),
        (S.UNIVERSAL, (S.PREVIEW, S.RELEASE)),
        (S.DISABLEMENT, (S.RELEASE,)),
        (S.DELETION, (S.RELEASE,)),
        (S.INERT, ()),
    ],
    ids=lambda value: value.name if isinstance(value, StatusStrategy) else None,
)
def test_deployed_by_lists_the_runs_in_deployable_order(
    rule: StatusStrategy, runs: tuple[StatusStrategy, ...]
) -> None:
    assert deployed_by(rule) == runs


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (["PREVIEW"], (S.PREVIEW,)),
        (["release"], (S.RELEASE,)),
        ([" Preview "], (S.PREVIEW,)),
        (["RELEASE", "PREVIEW"], BOTH),
        (["release,preview"], BOTH),
        (["PREVIEW", "preview", "PREVIEW,"], (S.PREVIEW,)),
        ([], ()),
        ([" , "], ()),
    ],
)
def test_parse_strategies_reads_preview_and_release(
    values: list[str], expected: tuple[StatusStrategy, ...]
) -> None:
    """Case-insensitive, comma lists, repeats folded, always in DEPLOYABLE_STRATEGIES order."""
    assert parse_strategies(values) == expected


def test_parse_strategies_refuses_an_unknown_name_with_the_allowed_ones() -> None:
    with pytest.raises(ValueError) as raised:
        parse_strategies(["PREVIEW", "canary"])
    assert (
        str(raised.value)
        == "--strategy 'canary' is not a deployable strategy. Use PREVIEW or RELEASE"
    )


@pytest.mark.parametrize(
    ("name", "replacement"), [("STAGING", "PREVIEW"), ("production", "RELEASE")]
)
def test_parse_strategies_answers_an_old_plan_name_with_its_strategy(
    name: str, replacement: str
) -> None:
    with pytest.raises(ValueError) as raised:
        parse_strategies([name])
    assert str(raised.value) == (
        f"--strategy {name!r} is not a deployable strategy. Use PREVIEW or RELEASE. "
        f"{name.upper()} was a deployment plan, removed in 0.17.0: pass {replacement}"
    )


@pytest.mark.parametrize(
    ("name", "hint"),
    [
        (
            "UNIVERSAL",
            "UNIVERSAL is a status strategy that both PREVIEW and RELEASE runs deploy; "
            "pass PREVIEW or RELEASE",
        ),
        (
            "DISABLEMENT",
            "a RELEASE run disables the changed rules whose status maps to DISABLEMENT; "
            "pass RELEASE",
        ),
        (
            "deletion",
            "a RELEASE run deletes the changed rules whose status maps to DELETION; pass RELEASE",
        ),
        ("INERT", "rules whose status maps to INERT are never deployed"),
        (
            "FULL",
            "deployment plans were removed in 0.17.0; pass --strategy PREVIEW --strategy "
            "RELEASE --all to deploy every rule",
        ),
        (
            "ALWAYS",
            "deployment plans were removed in 0.17.0; a tenant lists the strategies it "
            "accepts in 'strategies'",
        ),
        (
            "MANUAL",
            "deployment plans were removed in 0.17.0; a tenant that only takes the rules "
            "naming it sets 'manual = true'",
        ),
        ("DEBUG", "deployment plans were removed in 0.17.0; pass PREVIEW or RELEASE"),
    ],
)
def test_parse_strategies_explains_names_that_are_not_run_strategies(name: str, hint: str) -> None:
    with pytest.raises(ValueError) as raised:
        parse_strategies([name])
    assert str(raised.value) == (
        f"--strategy {name!r} is not a deployable strategy. Use PREVIEW or RELEASE. {hint}"
    )


@pytest.mark.parametrize(
    ("name", "hint"),
    [
        (
            "DEVELOPMENT",
            "DEVELOPMENT is also a configured status name; it maps to PREVIEW, which a "
            "PREVIEW run deploys",
        ),
        (
            "DISABLED",
            "DISABLED is also a configured status name; it maps to DISABLEMENT, which a "
            "RELEASE run deploys",
        ),
        (
            "DESIGN",
            "DESIGN is also a configured status name; it maps to INERT, which no run deploys",
        ),
        (
            "SHARED",
            "SHARED is also a configured status name; it maps to UNIVERSAL, which a PREVIEW "
            "or RELEASE run deploys",
        ),
    ],
)
def test_parse_strategies_answers_a_status_name_with_the_strategy_it_maps_to(
    name: str, hint: str
) -> None:
    statuses = {
        "DEVELOPMENT": S.PREVIEW,
        "DISABLED": S.DISABLEMENT,
        "DESIGN": S.INERT,
        "SHARED": S.UNIVERSAL,
    }
    with pytest.raises(ValueError) as raised:
        parse_strategies([name.lower()], statuses=statuses)
    assert str(raised.value) == (
        f"--strategy {name.lower()!r} is not a deployable strategy. Use PREVIEW or RELEASE. {hint}"
    )


def test_parse_strategies_gives_a_status_named_like_a_plan_both_hints() -> None:
    """The default ``STAGING`` status maps to PREVIEW, as the old STAGING plan deployed."""
    with pytest.raises(ValueError) as raised:
        parse_strategies(["STAGING"], statuses={"STAGING": S.PREVIEW})
    assert str(raised.value) == (
        "--strategy 'STAGING' is not a deployable strategy. Use PREVIEW or RELEASE. "
        "STAGING was a deployment plan, removed in 0.17.0: pass PREVIEW. "
        "STAGING is also a configured status name; it maps to PREVIEW, which a PREVIEW run deploys"
    )


def test_parse_strategies_names_its_source() -> None:
    with pytest.raises(ValueError, match=r"^splunk tenant 'A' strategies: 'nope' is not"):
        parse_strategies(["nope"], source="splunk tenant 'A' strategies:")


@pytest.mark.parametrize(
    ("value", "replacement"),
    [
        ("STAGING", "--strategy PREVIEW"),
        ("production", "--strategy RELEASE"),
        ("FULL", "--strategy PREVIEW --strategy RELEASE --all"),
        ("ALWAYS", "--strategy PREVIEW or --strategy RELEASE"),
        (None, "--strategy PREVIEW or --strategy RELEASE"),
    ],
)
def test_removed_plan_message_names_the_replacement(value: str | None, replacement: str) -> None:
    assert REMOVED_PLAN_ENV == "DEPLOYMENT_PLAN"
    assert removed_plan_message(value) == (
        "DEPLOYMENT_PLAN was removed in 0.17.0: a run now says which status strategy it "
        f"deploys. Use {replacement}. Unset DEPLOYMENT_PLAN. See 'opentide deploy --help'."
    )
    assert removed_plan_message(value, option=True) == (
        "--plan was removed in 0.17.0: a run now says which status strategy it "
        f"deploys. Use {replacement}. See 'opentide deploy --help'."
    )


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


_RUNS = [
    pytest.param(BOTH, id="PREVIEW+RELEASE"),
    pytest.param((S.PREVIEW,), id="PREVIEW"),
    pytest.param((S.RELEASE,), id="RELEASE"),
]


@pytest.mark.parametrize("strategies", _RUNS)
@pytest.mark.parametrize("rules_folder", ["missing", "gitkeep-only"])
def test_make_deploy_plan_with_no_rules_is_empty(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    strategies: tuple[StatusStrategy, ...],
    rules_folder: str,
) -> None:
    """``--all`` listed ``objects/rules`` directly: ``[Errno 2]`` when it was absent (#300)."""
    from opentide.deployment import make_deploy_plan

    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        monkeypatch.delenv(name, raising=False)
    if rules_folder == "gitkeep-only":
        rules = workspace / "objects" / "rules"
        rules.mkdir(parents=True)
        (rules / ".gitkeep").touch()
    assert make_deploy_plan(strategies, all_files=True) == {}


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
    ("strategies", "planned"),
    [
        pytest.param(BOTH, True, id="PREVIEW+RELEASE"),
        pytest.param((S.PREVIEW,), True, id="PREVIEW"),
        pytest.param((S.RELEASE,), False, id="RELEASE"),
    ],
)
def test_make_deploy_plan_names_the_rule_files_in_subfolders(
    catalogue: Path,
    plan_log: list[LoggedEvent],
    strategies: tuple[StatusStrategy, ...],
    planned: bool,
) -> None:
    """#312: a nested rule was left out of every run without a word.

    The corpus Sentinel rule is ``STAGING``, which maps to ``PREVIEW``.
    """
    from opentide.deployment import make_deploy_plan

    warnings: list[str] = []
    deploy_plan = make_deploy_plan(strategies, warnings=warnings, all_files=True)
    nested = [
        "objects/rules/team-a/deep/rule-0001-sentinel-kql.yaml",
        "objects/rules/team-a/rule-0101-subfolder.yaml",
    ]
    assert warnings == [
        "2 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/opentidehq/opentide/issues/312): "
        + ", ".join(nested)
    ]
    assert _skipped_subfolder_logs(plan_log) == [
        (
            "info",
            {
                "count": 2,
                "files": nested,
                "issue": "https://github.com/opentidehq/opentide/issues/312",
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

    make_deploy_plan(BOTH, all_files=True)
    assert [level for level, _ in _skipped_subfolder_logs(plan_log)] == ["warning"]


def test_subfolder_warning_caps_the_file_list(workspace: Path, plan_log: list[LoggedEvent]) -> None:
    from opentide.deployment import make_deploy_plan

    team = workspace / "objects" / "rules" / "team-a"
    team.mkdir(parents=True)
    for index in range(1, 8):
        (team / f"r{index}.yaml").write_text("", encoding="utf-8")
    warnings: list[str] = []
    assert make_deploy_plan(BOTH, warnings=warnings, all_files=True) == {}
    assert warnings == [
        "7 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/opentidehq/opentide/issues/312): "
        "objects/rules/team-a/r1.yaml, objects/rules/team-a/r2.yaml, "
        "objects/rules/team-a/r3.yaml, objects/rules/team-a/r4.yaml, "
        "objects/rules/team-a/r5.yaml, +2 more"
    ]
    ((_, fields),) = _skipped_subfolder_logs(plan_log)
    assert fields["files"] == [f"objects/rules/team-a/r{index}.yaml" for index in range(1, 8)]


@pytest.mark.parametrize("strategies", _RUNS)
def test_ci_diff_names_only_the_changed_subfolder_files(
    workspace: Path,
    monkeypatch: pytest.MonkeyPatch,
    plan_log: list[LoggedEvent],
    strategies: tuple[StatusStrategy, ...],
) -> None:
    """Without ``--all`` the run reads the git diff, so an unchanged nested rule is not news."""
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
    monkeypatch.setattr(git_repo, "diff_calculation", lambda source: diff)
    warnings: list[str] = []
    assert make_deploy_plan(strategies, warnings=warnings) == {}
    assert warnings == [
        "1 rule file(s) in subfolders of objects/rules are not deployed (deploy reads only "
        "files directly in objects/rules; see https://github.com/opentidehq/opentide/issues/312): "
        "objects/rules/team-a/changed.yaml"
    ]
    assert len(_skipped_subfolder_logs(plan_log)) == 1


@pytest.mark.parametrize("source", [DiffSource.CHANGE_REQUEST, DiffSource.PUSH, None])
def test_ci_diff_includes_changed_top_level_rules(
    workspace: Path, monkeypatch: pytest.MonkeyPatch, source: DiffSource | None
) -> None:
    """#318: the CI pattern was built from the absolute rules folder, so a changed
    ``objects/rules/*.yaml`` never matched a repo-relative git path."""
    from opentide.deployment import git_repo

    rules = workspace / "objects" / "rules"
    (rules / "team-a").mkdir(parents=True)
    (rules / "added.yaml").write_text("name: Added\n", encoding="utf-8")
    (rules / "team-a" / "skipped.yaml").write_text("", encoding="utf-8")
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CI", "true")
    diff = [
        "objects/rules/added.yaml",
        "objects/rules/team-a/skipped.yaml",
        "README.md",
    ]
    asked: list[DiffSource] = []
    monkeypatch.setattr(
        git_repo, "diff_calculation", lambda requested: asked.append(requested) or diff
    )

    scope = git_repo.modified_rule_scope(source)

    # No source: the CI context picks it, a push here (CI=true, no merge request).
    assert asked == [source or DiffSource.PUSH]

    assert scope.files == (rules / "added.yaml",)
    assert scope.nested == ("objects/rules/team-a/skipped.yaml",)


def test_ci_rule_selection_keeps_top_level_files_out_of_the_subfolder_list(
    workspace: Path,
) -> None:
    """Every changed rule file is either planned from the rules folder or named as nested."""
    from opentide.deployment.git_repo import split_changed_rule_paths

    changed = [
        "objects/rules/added.yaml",
        "objects/rules/also.yml",
        "/repo/objects/rules/absolute.yaml",
        "objects/rules/team-a/nested.yaml",
        "objects/rules/team-a/deep/nested.yml",
        "objects/rules-archive/team-a/old.yaml",
        "objects/threats/team-a/threat.yaml",
        "docs/rules/team-a/page.yaml",
        "objects/rules/notes.md",
        "README.md",
    ]

    top, nested = split_changed_rule_paths(changed)

    assert top == [
        "objects/rules/added.yaml",
        "objects/rules/also.yml",
        "/repo/objects/rules/absolute.yaml",
    ]
    assert nested == [
        "objects/rules/team-a/deep/nested.yml",
        "objects/rules/team-a/nested.yaml",
    ]
    assert set(top).isdisjoint(nested)


@pytest.mark.parametrize("catalogue", ["plain", "symlinked"], indirect=True)
def test_every_rule_run_accounts_for_every_indexed_rule(catalogue: Path) -> None:
    """#312 guard: an indexed rule is planned, excluded by status, or named in a warning."""
    from opentide.core.registry import Opentide
    from opentide.deployment import make_deploy_plan

    warnings: list[str] = []
    deploy_plan = make_deploy_plan(BOTH, warnings=warnings, all_files=True)
    scope = classify_deploy_scope(
        catalogue,
        Opentide.Models.rules,
        deploy_plan,
        warnings,
        excluded=frozenset({StatusStrategy.INERT}),
    )
    assert scope["silent"] == set()
    assert set(CORPUS_RULE_UUIDS.values()) <= scope["planned"]
    assert scope["status"] == {INERT_RULE_UUID}
    assert scope["warned"] == set(SUBFOLDER_RULE_UUIDS.values())


GATED_RULE_UUID = "00000000-0000-4000-8003-000000000414"
_GATED_RULE = """\
name: Gated Rule
metadata:
  uuid: {uuid}
  schema: rule::1.0
configurations:
  {platform}:
    enabled: true
    status: {status}
    query: index=main | head 1
"""
_SPLUNK_PLATFORM = """\
[platform]
enabled = {enabled}
identifier = "splunk"
name = "Splunk Enterprise"
description = "Splunk"

[[tenants]]
name = "Default"
description = "Default Splunk deployment target"
[tenants.setup]
url = "https://splunk.example"
port = "8089"
token = "token"
app = "search"
"""


def _write_gated_rule(
    root: Path, *, status: str, splunk_enabled: bool, platform: str = "splunk"
) -> None:
    """One rule whose own block says ``enabled: true``, and a Splunk toml with a tenant.

    Only the workspace ``enabled`` flag differs between the gated and planned cases.
    """
    rules = root / "objects" / "rules"
    rules.mkdir(parents=True, exist_ok=True)
    (rules / "gated.yaml").write_text(
        _GATED_RULE.format(uuid=GATED_RULE_UUID, platform=platform, status=status),
        encoding="utf-8",
    )
    config = root / ".opentide" / "configurations" / "platforms" / "splunk.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        _SPLUNK_PLATFORM.format(enabled=str(splunk_enabled).lower()), encoding="utf-8"
    )


def _disabled_skips(events: list[LoggedEvent]) -> list[dict[str, object]]:
    return [fields for _, event, fields in events if event == "system_disabled_for_deploy"]


#: Each run with a status it deploys, so the enabled control is planned.
_GATE_CASES = [
    pytest.param(BOTH, "PRODUCTION", False, id="PREVIEW+RELEASE"),
    pytest.param((S.PREVIEW,), "STAGING", False, id="PREVIEW"),
    pytest.param((S.RELEASE,), "PRODUCTION", False, id="RELEASE"),
    pytest.param((S.RELEASE,), "DISABLED", False, id="RELEASE-retires"),
    pytest.param((S.PREVIEW,), "PRODUCTION", True, id="PREVIEW-wide"),
]


@pytest.fixture
def local_workspace(workspace: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run outside CI; the tests pass ``all_files`` to read the local rules folder."""
    for name in CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    return workspace


@pytest.mark.parametrize(("strategies", "status", "wide"), _GATE_CASES)
def test_disabled_platform_is_never_planned(
    local_workspace: Path,
    plan_log: list[LoggedEvent],
    strategies: tuple[StatusStrategy, ...],
    status: str,
    wide: bool,
) -> None:
    """#414: the workspace flag gates deploy. The block's own ``enabled: true`` does not."""
    from opentide.deployment import make_deploy_plan

    _write_gated_rule(local_workspace, status=status, splunk_enabled=False)
    assert make_deploy_plan(strategies, wide_scope=wide, all_files=True) == {}
    assert _disabled_skips(plan_log) == [
        {
            "system": "SPLUNK",
            "rule": "Gated Rule",
            "advice": "enable it with 'opentide setup platforms --splunk'",
        }
    ]


@pytest.mark.parametrize(("strategies", "status", "wide"), _GATE_CASES)
def test_enabling_the_platform_plans_the_same_rule(
    local_workspace: Path,
    plan_log: list[LoggedEvent],
    strategies: tuple[StatusStrategy, ...],
    status: str,
    wide: bool,
) -> None:
    from opentide.deployment import make_deploy_plan

    _write_gated_rule(local_workspace, status=status, splunk_enabled=True)
    assert make_deploy_plan(strategies, wide_scope=wide, all_files=True) == {
        "splunk": [GATED_RULE_UUID]
    }
    assert _disabled_skips(plan_log) == []


def test_disabled_platform_advice_spells_the_flag_with_dashes(
    local_workspace: Path, plan_log: list[LoggedEvent]
) -> None:
    """The advice named ``--defender_for_endpoint``, which ``setup platforms`` rejects."""
    from opentide.deployment import make_deploy_plan

    _write_gated_rule(
        local_workspace,
        status="PRODUCTION",
        splunk_enabled=True,
        platform="defender_for_endpoint",
    )
    assert make_deploy_plan(BOTH, all_files=True) == {}
    ((fields),) = _disabled_skips(plan_log)
    assert fields["advice"] == "enable it with 'opentide setup platforms --defender-for-endpoint'"


@pytest.mark.parametrize(
    ("strategies", "status", "selected"),
    [
        pytest.param((S.PREVIEW,), "STAGING", True, id="PREVIEW-takes-PREVIEW"),
        pytest.param((S.PREVIEW,), "PRODUCTION", False, id="PREVIEW-skips-RELEASE"),
        pytest.param((S.PREVIEW,), "DISABLED", False, id="PREVIEW-skips-DISABLEMENT"),
        pytest.param((S.RELEASE,), "PRODUCTION", True, id="RELEASE-takes-RELEASE"),
        pytest.param((S.RELEASE,), "REMOVED", True, id="RELEASE-takes-DELETION"),
        pytest.param((S.RELEASE,), "DEVELOPMENT", False, id="RELEASE-skips-PREVIEW"),
        pytest.param(BOTH, "DESIGN", False, id="both-skip-INERT"),
    ],
)
def test_make_deploy_plan_selects_by_the_strategy_a_status_maps_to(
    local_workspace: Path,
    plan_log: list[LoggedEvent],
    strategies: tuple[StatusStrategy, ...],
    status: str,
    selected: bool,
) -> None:
    """A skipped block names the strategy, the run's strategies and the runs that would take it."""
    from opentide.deployment import make_deploy_plan
    from opentide.deployment.utils import check_status

    _write_gated_rule(local_workspace, status=status, splunk_enabled=True)
    planned = make_deploy_plan(strategies, all_files=True)
    assert planned == ({"splunk": [GATED_RULE_UUID]} if selected else {})
    skipped = [fields for _, event, fields in plan_log if event == "mdr_skipped_for_strategy"]
    if selected:
        assert skipped == []
        return
    strategy = check_status(status)
    assert skipped == [
        {
            "system": "SPLUNK",
            "status": status,
            "strategy": strategy.name,
            "run_strategies": ", ".join(s.name for s in strategies),
            "deployed_by": ", ".join(r.name for r in deployed_by(strategy)) or "no run",
            "rule": "Gated Rule",
        }
    ]


def test_make_deploy_plan_drops_retired_rules_only_when_asked(
    local_workspace: Path,
) -> None:
    from opentide.deployment import make_deploy_plan

    _write_gated_rule(local_workspace, status="DISABLED", splunk_enabled=True)
    run = (S.RELEASE,)
    assert make_deploy_plan(run, all_files=True) == {"splunk": [GATED_RULE_UUID]}
    assert make_deploy_plan(run, keep_deprecated=False, all_files=True) == {}


# --- Tenant resolution ---------------------------------------------------------------------


def _tenant(name: str, *strategies: StatusStrategy, manual: bool = False):
    from opentide.models.system_config import SystemConfig

    if strategies:
        return SystemConfig.Tenant(
            name=name, description="", setup=None, strategies=strategies, manual=manual
        )
    return SystemConfig.Tenant(name=name, description="", setup=None, manual=manual)


@pytest.mark.parametrize(
    ("tenant_strategies", "rule", "run", "accepted"),
    [
        ((S.PREVIEW,), S.PREVIEW, (S.PREVIEW,), True),
        ((S.PREVIEW,), S.PREVIEW, (S.RELEASE,), False),
        ((S.PREVIEW,), S.RELEASE, BOTH, False),
        ((S.PREVIEW,), S.UNIVERSAL, BOTH, True),
        ((S.RELEASE,), S.UNIVERSAL, (S.PREVIEW,), False),
        ((S.RELEASE,), S.DELETION, (S.RELEASE,), True),
        ((S.RELEASE,), S.DISABLEMENT, (S.PREVIEW,), False),
        (BOTH, S.RELEASE, BOTH, True),
        (BOTH, S.INERT, BOTH, False),
        (BOTH, S.PREVIEW, (), False),
    ],
)
def test_tenant_accepts_a_rule_a_run_strategy_it_lists_deploys(
    tenant_strategies: tuple[StatusStrategy, ...],
    rule: StatusStrategy,
    run: tuple[StatusStrategy, ...],
    accepted: bool,
) -> None:
    assert _tenant("T", *tenant_strategies).accepts(rule, run) is accepted


def test_tenant_defaults_to_every_strategy_and_not_manual() -> None:
    tenant = _tenant("T")
    assert tenant.strategies == DEPLOYABLE_STRATEGIES
    assert tenant.manual is False


#: preview: PREVIEW only; release: RELEASE only; both: default; handpicked: manual, both.
_TENANTS = (
    ("preview", (S.PREVIEW,), False),
    ("release", (S.RELEASE,), False),
    ("both", (), False),
    ("handpicked", (), True),
)


def _resolve(
    metadata: dict,
    *,
    status: str,
    run: tuple[StatusStrategy, ...],
    rule_tenants: list[str] | None = None,
    wide: bool = False,
) -> list[str]:
    """Tenant names ``TideDeployment.tenants_resolver`` picks for one Splunk rule."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from opentide.deployment.planning import TideDeployment, wide_scope
    from opentide.loading.rule_loader import load_rule_from_dict
    from opentide.models.deployment_enums import DetectionPlatforms

    block: dict[str, object] = {"schema": "splunk::3.0", "status": status, "query": "index=main"}
    if rule_tenants is not None:
        block["tenants"] = rule_tenants
    rule = load_rule_from_dict(
        {
            "name": "Routed Rule",
            "metadata": metadata,
            "description": "desc",
            "configurations": {"splunk": block},
        }
    )
    tenants = [_tenant(name, *strategies, manual=manual) for name, strategies, manual in _TENANTS]
    tide = TideDeployment.__new__(TideDeployment)
    tide.system_configuration_resolver = MagicMock(return_value=SimpleNamespace(tenants=tenants))
    if wide:
        with wide_scope():
            chosen = tide.tenants_resolver(rule, DetectionPlatforms.SPLUNK, run)
    else:
        chosen = tide.tenants_resolver(rule, DetectionPlatforms.SPLUNK, run)
    return [tenant.name for tenant in chosen]


@pytest.mark.parametrize(
    ("status", "run", "expected"),
    [
        # STAGING maps to PREVIEW: only a PREVIEW run takes it, to PREVIEW-accepting tenants.
        pytest.param("STAGING", (S.PREVIEW,), ["preview", "both"], id="PREVIEW-rule-PREVIEW-run"),
        pytest.param("STAGING", (S.RELEASE,), [], id="PREVIEW-rule-RELEASE-run"),
        pytest.param("STAGING", BOTH, ["preview", "both"], id="PREVIEW-rule-both-runs"),
        pytest.param("PRODUCTION", (S.RELEASE,), ["release", "both"], id="RELEASE-rule"),
        pytest.param("PRODUCTION", (S.PREVIEW,), [], id="RELEASE-rule-PREVIEW-run"),
        pytest.param("DISABLED", (S.RELEASE,), ["release", "both"], id="DISABLEMENT-rule"),
        pytest.param("REMOVED", BOTH, ["release", "both"], id="DELETION-rule"),
        pytest.param("DESIGN", BOTH, [], id="INERT-rule"),
        pytest.param("STAGING", None, [], id="no-run-strategies"),
    ],
)
def test_tenants_resolver_routes_by_tenant_strategies(
    workspace: Path,
    metadata: dict,
    status: str,
    run: tuple[StatusStrategy, ...] | None,
    expected: list[str],
) -> None:
    """A manual tenant is skipped: no rule lists it."""
    assert _resolve(metadata, status=status, run=run) == expected  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("rule_tenants", "run", "expected"),
    [
        pytest.param(["handpicked"], (S.PREVIEW,), ["handpicked"], id="manual-listed"),
        pytest.param(["preview", "handpicked"], BOTH, ["preview", "handpicked"], id="listed-two"),
        # A listed tenant still has to accept a run strategy that deploys the rule.
        pytest.param(["release"], (S.PREVIEW,), [], id="listed-but-refuses-PREVIEW"),
        pytest.param(["release", "both"], (S.PREVIEW,), ["both"], id="listed-mix"),
        pytest.param(["unknown"], BOTH, [], id="listed-unknown"),
    ],
)
def test_tenants_resolver_reaches_only_the_tenants_a_rule_lists(
    workspace: Path,
    metadata: dict,
    rule_tenants: list[str],
    run: tuple[StatusStrategy, ...],
    expected: list[str],
) -> None:
    assert _resolve(metadata, status="STAGING", run=run, rule_tenants=rule_tenants) == expected


@pytest.mark.parametrize(
    ("status", "run", "expected"),
    [
        pytest.param("DESIGN", (S.PREVIEW,), ["preview", "both"], id="INERT-PREVIEW"),
        pytest.param("DESIGN", (S.RELEASE,), ["release", "both"], id="INERT-RELEASE"),
        pytest.param("PRODUCTION", (S.PREVIEW,), ["preview", "both"], id="RELEASE-rule-PREVIEW"),
    ],
)
def test_wide_scope_reaches_the_tenants_accepting_a_run_strategy(
    workspace: Path,
    metadata: dict,
    status: str,
    run: tuple[StatusStrategy, ...],
    expected: list[str],
) -> None:
    """``--wide`` deploys whatever the status, so the rule's strategy no longer filters tenants."""
    assert _resolve(metadata, status=status, run=run, wide=True) == expected
    assert _resolve(metadata, status=status, run=run) == []


# --- Tenant keys in platform TOML ---------------------------------------------------------


def _splunk_raw(**tenant: object) -> dict[str, object]:
    return {
        "platform": {
            "enabled": True,
            "identifier": "splunk",
            "name": "Splunk",
            "subschema": "Splunk Sub Schema",
            "description": "desc",
            "flags": [],
        },
        "tenants": [
            {
                "name": "Primary",
                "description": "Primary tenant",
                **tenant,
                "setup": {
                    "url": "https://splunk.example",
                    "port": "8089",
                    "app": "search",
                    "token": "secret",
                },
            }
        ],
    }


def _cbc_raw(**tenant: object) -> dict[str, object]:
    return {
        "platform": {
            "enabled": True,
            "identifier": "carbon_black_cloud",
            "name": "CBC",
            "subschema": "CBC EDR Sub Schema",
            "description": "desc",
            "flags": [],
        },
        "tenants": [
            {
                "name": "Primary",
                "description": "Primary tenant",
                **tenant,
                "setup": {"url": "https://cbc.example", "org_key": "key", "token": "token"},
            }
        ],
    }


def _sentinel_raw(**tenant: object) -> dict[str, object]:
    return {
        "platform": {
            "enabled": True,
            "identifier": "sentinel",
            "name": "Sentinel",
            "subschema": "Sentinel",
            "description": "desc",
            "flags": [],
        },
        "tenants": [
            {
                "name": "Primary",
                "description": "Primary tenant",
                **tenant,
                "setup": {
                    "resource_group": "rg",
                    "workspace_name": "ws",
                    "workspace_id": "wid",
                    "azure_tenant_id": "t",
                    "azure_subscription_id": "sub",
                    "azure_client_id": "c",
                    "azure_client_secret": "s",
                },
            }
        ],
    }


_PLATFORM_RAW = {
    "splunk": _splunk_raw,
    "carbon_black_cloud": _cbc_raw,
    "sentinel": _sentinel_raw,
}


@pytest.mark.parametrize("system", list(_PLATFORM_RAW))
@pytest.mark.parametrize(
    ("keys", "strategies", "manual"),
    [
        pytest.param({}, BOTH, False, id="default"),
        pytest.param({"strategies": ["PREVIEW"]}, (S.PREVIEW,), False, id="PREVIEW"),
        pytest.param({"strategies": ["release"]}, (S.RELEASE,), False, id="RELEASE"),
        pytest.param({"strategies": "RELEASE"}, (S.RELEASE,), False, id="string"),
        pytest.param({"strategies": ["RELEASE", "PREVIEW"]}, BOTH, False, id="both"),
        pytest.param({"manual": True}, BOTH, True, id="manual"),
        pytest.param(
            {"manual": True, "strategies": ["PREVIEW"]}, (S.PREVIEW,), True, id="manual-PREVIEW"
        ),
    ],
)
def test_platform_toml_tenant_strategies_and_manual(
    system: str, keys: dict[str, object], strategies: tuple[StatusStrategy, ...], manual: bool
) -> None:
    from opentide.platforms.config import build_system_config

    config = build_system_config(system, _PLATFORM_RAW[system](**keys))
    (tenant,) = config.tenants
    assert tenant.strategies == strategies
    assert tenant.manual is manual


@pytest.mark.parametrize("system", list(_PLATFORM_RAW))
@pytest.mark.parametrize(
    ("value", "replacement"),
    [
        ("STAGING", 'strategies = ["PREVIEW"]'),
        ("PRODUCTION", 'strategies = ["RELEASE"]'),
        ("ALWAYS", "no key at all (a tenant accepts every strategy by default)"),
        ("FULL", "no key at all (a tenant accepts every strategy by default)"),
        ("MANUAL", "manual = true"),
        ("DEBUG", 'strategies = ["PREVIEW"]'),
        ("whatever", 'strategies = ["PREVIEW"] or strategies = ["RELEASE"]'),
    ],
)
def test_platform_toml_tenant_deployment_key_is_refused(
    system: str, value: str, replacement: str
) -> None:
    from opentide.platforms.config import build_system_config

    with pytest.raises(ValueError) as raised:
        build_system_config(system, _PLATFORM_RAW[system](deployment=value))
    message = str(raised.value)
    assert "'Primary'" in message
    assert message.endswith(
        ": the tenant key 'deployment' was removed in 0.17.0. A tenant now lists the status "
        f"strategies it accepts. Replace deployment = {value!r} with {replacement}."
    )


@pytest.mark.parametrize("system", list(_PLATFORM_RAW))
@pytest.mark.parametrize(
    ("keys", "match"),
    [
        pytest.param(
            {"strategies": []},
            "strategies must list PREVIEW, RELEASE, or both; omit it to accept every strategy",
            id="empty",
        ),
        pytest.param(
            {"strategies": ["UNIVERSAL"]},
            "strategies: 'UNIVERSAL' is not a deployable strategy. Use PREVIEW or RELEASE. "
            "UNIVERSAL is a status strategy that both PREVIEW and RELEASE runs deploy",
            id="UNIVERSAL",
        ),
        pytest.param(
            {"strategies": ["STAGING"]},
            "STAGING was a deployment plan, removed in 0.17.0: pass PREVIEW",
            id="STAGING",
        ),
        pytest.param({"manual": "yes"}, "manual must be true or false", id="manual-string"),
    ],
)
def test_platform_toml_tenant_bad_strategies_are_refused(
    system: str, keys: dict[str, object], match: str
) -> None:
    import re

    from opentide.platforms.config import build_system_config

    with pytest.raises(ValueError, match=re.escape(match)):
        build_system_config(system, _PLATFORM_RAW[system](**keys))


# --- Outside CI: the last commit ----------------------------------------------------------


def _git(cwd: Path, *args: str) -> str:
    import os
    import subprocess

    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "dev",
            "GIT_AUTHOR_EMAIL": "dev@example.test",
            "GIT_COMMITTER_NAME": "dev",
            "GIT_COMMITTER_EMAIL": "dev@example.test",
        }
    )
    done = subprocess.run(
        ["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env
    )
    return done.stdout.strip()


FIRST_RULE_UUID = "00000000-0000-4000-8003-000000000501"
SECOND_RULE_UUID = "00000000-0000-4000-8003-000000000502"
THIRD_RULE_UUID = "00000000-0000-4000-8003-000000000503"


def _write_rule(rules: Path, filename: str, uuid: str, *, status: str = "PRODUCTION") -> None:
    rules.mkdir(parents=True, exist_ok=True)
    (rules / filename).write_text(
        _GATED_RULE.format(uuid=uuid, platform="splunk", status=status).replace(
            "name: Gated Rule", f"name: Rule {uuid[-3:]}"
        ),
        encoding="utf-8",
    )


@pytest.fixture
def local_checkout(local_workspace: Path) -> Path:
    """A workspace that is a git checkout: commit 1 has one rule, commit 2 adds two more."""
    root = local_workspace
    _write_gated_rule(root, status="PRODUCTION", splunk_enabled=True)
    rules = root / "objects" / "rules"
    _write_rule(rules, "first.yaml", FIRST_RULE_UUID)
    _git(root, "init", "-q", "-b", "main")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "first")
    _write_rule(rules, "second.yaml", SECOND_RULE_UUID)
    _write_rule(rules, "third.yaml", THIRD_RULE_UUID, status="STAGING")
    (root / "README.md").write_text("docs\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "second")
    return root


def test_outside_ci_the_run_reads_the_last_commit(local_workspace: Path) -> None:
    from opentide.deployment.git_repo import run_diff_source

    assert run_diff_source() is DiffSource.LAST_COMMIT


def test_last_commit_diff_lists_the_files_head_changed(local_checkout: Path) -> None:
    from opentide.deployment.git_repo import changed_rule_scope, diff_calculation

    assert sorted(diff_calculation(DiffSource.LAST_COMMIT)) == [
        "README.md",
        "objects/rules/second.yaml",
        "objects/rules/third.yaml",
    ]
    scope, source = changed_rule_scope()
    assert source is DiffSource.LAST_COMMIT
    rules = local_checkout / "objects" / "rules"
    assert sorted(scope.files) == [rules / "second.yaml", rules / "third.yaml"]


def test_last_commit_diff_keeps_modified_and_drops_deleted_files(local_checkout: Path) -> None:
    from opentide.deployment.git_repo import diff_calculation

    rules = local_checkout / "objects" / "rules"
    _write_rule(rules, "first.yaml", FIRST_RULE_UUID, status="STAGING")
    (rules / "second.yaml").unlink()
    _git(local_checkout, "add", "-A")
    _git(local_checkout, "commit", "-q", "-m", "third")
    assert diff_calculation(DiffSource.LAST_COMMIT) == ["objects/rules/first.yaml"]


def test_last_commit_diff_ignores_uncommitted_edits(local_checkout: Path) -> None:
    from opentide.deployment.git_repo import diff_calculation

    rules = local_checkout / "objects" / "rules"
    _write_rule(rules, "first.yaml", FIRST_RULE_UUID, status="STAGING")
    _write_rule(rules, "untracked.yaml", "00000000-0000-4000-8003-000000000599")
    assert "objects/rules/first.yaml" not in diff_calculation(DiffSource.LAST_COMMIT)
    assert "objects/rules/untracked.yaml" not in diff_calculation(DiffSource.LAST_COMMIT)


@pytest.mark.parametrize(
    ("strategies", "changed", "every"),
    [
        pytest.param(
            BOTH,
            [SECOND_RULE_UUID, THIRD_RULE_UUID],
            [FIRST_RULE_UUID, SECOND_RULE_UUID, THIRD_RULE_UUID, GATED_RULE_UUID],
            id="PREVIEW+RELEASE",
        ),
        pytest.param(
            (S.RELEASE,),
            [SECOND_RULE_UUID],
            [FIRST_RULE_UUID, SECOND_RULE_UUID, GATED_RULE_UUID],
            id="RELEASE",
        ),
        pytest.param((S.PREVIEW,), [THIRD_RULE_UUID], [THIRD_RULE_UUID], id="PREVIEW"),
    ],
)
def test_local_deploy_plan_reads_the_last_commit_unless_all(
    local_checkout: Path,
    strategies: tuple[StatusStrategy, ...],
    changed: list[str],
    every: list[str],
) -> None:
    """Outside CI a run reads HEAD^1..HEAD; ``--all`` reads every rule file (the old FULL)."""
    from opentide.deployment import make_deploy_plan

    assert sorted(make_deploy_plan(strategies)["splunk"]) == changed
    assert sorted(make_deploy_plan(strategies, all_files=True)["splunk"]) == sorted(every)


def test_last_commit_diff_of_the_first_commit_is_empty(local_workspace: Path) -> None:
    from opentide.deployment import make_deploy_plan
    from opentide.deployment.git_repo import diff_calculation

    _write_gated_rule(local_workspace, status="PRODUCTION", splunk_enabled=True)
    _git(local_workspace, "init", "-q", "-b", "main")
    _git(local_workspace, "add", "-A")
    _git(local_workspace, "commit", "-q", "-m", "first")
    assert diff_calculation(DiffSource.LAST_COMMIT) == []
    assert make_deploy_plan(BOTH) == {}
    assert make_deploy_plan(BOTH, all_files=True) == {"splunk": [GATED_RULE_UUID]}


def test_last_commit_diff_without_a_checkout_names_the_folder_and_all(
    local_workspace: Path,
) -> None:
    from opentide.deployment import make_deploy_plan
    from opentide.deployment.git_repo import MissingGitCheckout, missing_checkout_message

    _write_gated_rule(local_workspace, status="PRODUCTION", splunk_enabled=True)
    with pytest.raises(MissingGitCheckout) as raised:
        make_deploy_plan(BOTH)
    assert raised.value.searched == local_workspace.resolve()
    message = missing_checkout_message(raised.value.searched)
    assert message == (
        "deploy reads the rule files the last commit, push or pull request changed, which "
        f"needs a git checkout; no .git was found from {local_workspace.resolve()}. "
        "Run inside the repository, or pass --all to read every rule file."
    )
    assert make_deploy_plan(BOTH, all_files=True) == {"splunk": [GATED_RULE_UUID]}


def test_a_change_request_diff_needs_a_ci_run(local_checkout: Path) -> None:
    from opentide.deployment.git_repo import diff_calculation

    with pytest.raises(Exception, match="A pull or merge request diff needs a CI run"):
        diff_calculation(DiffSource.CHANGE_REQUEST)
