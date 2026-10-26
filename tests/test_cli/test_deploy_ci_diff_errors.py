"""A CI run's diff must fail with a sentence, not a leaked exception (#339).

The CI context picks the diff: a pull or merge request run (``GITHUB_EVENT_NAME``,
``BUILD_REASON``, ``CI_PIPELINE_SOURCE``) reads its request from the merge base,
any other run its push. ``--strategy`` only decides which statuses deploy.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_LEAKS = (
    "lookup_ref",
    "encode",
    "list index out of range",
    "KeyError while selecting the rules to deploy",
    "Invalid object name",
)

_HIDDEN = (
    "GITHUB_ACTIONS",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
    "CI",
    "CI_PROJECT_DIR",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    "CI_MERGE_REQUEST_EVENT_TYPE",
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "DEPLOYMENT_PLAN",
    "GITHUB_EVENT_NAME",
    "BUILD_REASON",
    "CI_PIPELINE_SOURCE",
)

#: What each provider sets on a pull or merge request run, by its CI marker.
_CHANGE_REQUEST = {
    "CI": {"CI_PIPELINE_SOURCE": "merge_request_event"},
    "GITHUB_ACTIONS": {"GITHUB_EVENT_NAME": "pull_request"},
    "TF_BUILD": {"BUILD_REASON": "PullRequest"},
}

_AZURE_REFS = (
    "Expected to find SYSTEM_PULLREQUEST_SOURCEBRANCH and "
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME | Ensure this is running in a Pull Request pipeline"
)


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _init_repo(path: Path, commits: int = 1) -> str:
    _git(path, "init", "-q", "-b", "main")
    for index in range(commits):
        (path / "README.md").write_text(f"rules {index}\n", encoding="utf-8")
        _git(path, "add", "README.md")
        _git(path, "commit", "-q", "-m", f"commit {index}")
    return _git(path, "rev-parse", "HEAD")


def _env(repo: Path, **values: str | None) -> dict[str, str | None]:
    env: dict[str, str | None] = dict.fromkeys(_HIDDEN)
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    env.update(values)
    return env


def _visible(result: object) -> str:
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    visible = _ANSI.sub("", rendered)
    return re.sub(r"[\u2500-\u257f]", "", visible)


def _assert_failure(result: object, message: str, *, json_output: bool) -> None:
    assert result.exit_code == 1, result.stdout + result.stderr  # type: ignore[attr-defined]
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    for leak in _LEAKS:
        assert leak not in rendered
    if json_output:
        payload = json.loads(result.stdout)  # type: ignore[attr-defined]
        assert payload["ok"] is False
        assert payload["message"] == message
    else:
        assert message in re.sub(r"\s+", " ", _visible(result))


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_gitlab_missing_tip_names_ci_commit_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_env(
            repo,
            CI="true",
            CI_PROJECT_DIR=str(repo),
            CI_MERGE_REQUEST_DIFF_BASE_SHA=head,
            **_CHANGE_REQUEST["CI"],
        ),
    )
    _assert_failure(
        result, "CI_COMMIT_SHA is required to compute the changed rules", json_output=json_output
    )


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_github_missing_tip_names_github_sha(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, commits=2)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "RELEASE"],
        env=_env(repo, GITHUB_ACTIONS="true", GITHUB_WORKSPACE=str(repo)),
    )
    _assert_failure(
        result, "GITHUB_SHA is required to compute the changed rules", json_output=json_output
    )


@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_azure_missing_tip_names_build_sourceversion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path, json_output: bool
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, commits=2)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "RELEASE"],
        env=_env(repo, TF_BUILD="true", BUILD_SOURCESDIRECTORY=str(repo)),
    )
    _assert_failure(
        result,
        "BUILD_SOURCEVERSION is required to compute the changed rules",
        json_output=json_output,
    )


@pytest.mark.parametrize("with_origin", [False, True], ids=["no-origin", "origin"])
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_azure_pull_request_without_pr_refs_names_azure_variables(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    with_origin: bool,
    json_output: bool,
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    if with_origin:
        origin = tmp_path / "origin.git"
        _git(tmp_path, "init", "-q", "--bare", str(origin))
        _git(repo, "remote", "add", "origin", str(origin))
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_env(
            repo,
            TF_BUILD="true",
            BUILD_SOURCESDIRECTORY=str(repo),
            BUILD_SOURCEVERSION=head,
            **_CHANGE_REQUEST["TF_BUILD"],
        ),
    )
    _assert_failure(result, _AZURE_REFS, json_output=json_output)
    rendered = result.stdout + result.stderr
    assert "No git repository was found" not in rendered


@pytest.mark.parametrize(
    ("marker", "workspace", "tip_name", "tip_value"),
    [
        ("GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SHA", "head"),
        ("TF_BUILD", "BUILD_SOURCESDIRECTORY", "BUILD_SOURCEVERSION", "head"),
    ],
    ids=["github", "azure"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_pull_request_missing_origin_ref_names_the_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    marker: str,
    workspace: str,
    tip_name: str,
    tip_value: str,
    json_output: bool,
) -> None:
    del git_home, tip_value
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "HEAD:refs/heads/main")
    monkeypatch.chdir(repo)
    extra = {
        marker: "true",
        workspace: str(repo),
        tip_name: head,
        **_CHANGE_REQUEST[marker],
    }
    if marker == "GITHUB_ACTIONS":
        extra["GITHUB_HEAD_REF"] = "no-such"
        extra["GITHUB_BASE_REF"] = "also-missing"
    else:
        extra["SYSTEM_PULLREQUEST_SOURCEBRANCH"] = "no-such"
        extra["SYSTEM_PULLREQUEST_TARGETBRANCHNAME"] = "also-missing"
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_env(repo, **extra),
    )
    _assert_failure(result, "Could not find git ref origin/also-missing", json_output=json_output)


@pytest.mark.parametrize(
    ("marker", "workspace", "tip_name"),
    [
        ("GITHUB_ACTIONS", "GITHUB_WORKSPACE", "GITHUB_SHA"),
        ("TF_BUILD", "BUILD_SOURCESDIRECTORY", "BUILD_SOURCEVERSION"),
    ],
    ids=["github", "azure"],
)
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_pull_request_detached_head_fetches_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    marker: str,
    workspace: str,
    tip_name: str,
    json_output: bool,
) -> None:
    """A pull-request checkout is detached. Fetch must not ask for the branch.

    GitHub (#402) and Azure (#415) both crashed in ``porcelain.fetch`` with
    ``list index out of range`` before merge-base ran.
    """
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo, commits=2)
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "README.md").write_text("feature\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "feature")
    origin = tmp_path / "origin.git"
    _git(tmp_path, "init", "-q", "--bare", str(origin))
    _git(repo, "remote", "add", "origin", str(origin))
    _git(repo, "push", "-q", "origin", "main")
    _git(repo, "push", "-q", "origin", "feature")
    tip = _git(repo, "rev-parse", "HEAD")
    _git(repo, "checkout", "-q", "--detach", tip)
    detached = subprocess.run(
        ["git", "symbolic-ref", "-q", "HEAD"], cwd=repo, capture_output=True, text=True
    )
    assert detached.returncode != 0
    monkeypatch.chdir(repo)
    extra: dict[str, str | None] = {
        marker: "true",
        workspace: str(repo),
        tip_name: tip,
        **_CHANGE_REQUEST[marker],
    }
    if marker == "GITHUB_ACTIONS":
        extra["GITHUB_HEAD_REF"] = "feature"
        extra["GITHUB_BASE_REF"] = "main"
    else:
        extra["SYSTEM_PULLREQUEST_SOURCEBRANCH"] = "refs/heads/feature"
        extra["SYSTEM_PULLREQUEST_TARGETBRANCHNAME"] = "main"
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_env(repo, **extra),
    )
    rendered = result.stdout + result.stderr
    for leak in _LEAKS:
        assert leak not in rendered
    assert "Traceback" not in rendered
    assert result.exit_code == 0, rendered


_CI_PLATFORMS = pytest.mark.parametrize(
    "platform",
    [
        {"CI": "true", "CI_PROJECT_DIR": "repo", "CI_COMMIT_SHA": "head"},
        {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": "repo", "GITHUB_SHA": "head"},
        {"TF_BUILD": "true", "BUILD_SOURCESDIRECTORY": "repo", "BUILD_SOURCEVERSION": "head"},
    ],
    ids=["gitlab", "github", "azure"],
)


def _ci_values(platform: dict[str, str], repo: Path, head: str) -> dict[str, str | None]:
    values: dict[str, str | None] = {}
    for key, value in platform.items():
        if value == "repo":
            values[key] = str(repo)
        elif value == "head":
            values[key] = head
        else:
            values[key] = value
    return values


def _assert_refused(result: object, message: str, *, json_output: bool) -> None:
    """A usage error (exit 2) before any git work, with the sentence and nothing leaked."""
    assert result.exit_code == 2, result.stdout + result.stderr  # type: ignore[attr-defined]
    rendered = result.stdout + result.stderr  # type: ignore[attr-defined]
    for leak in (*_LEAKS, "Traceback"):
        assert leak not in rendered
    if json_output:
        payload = json.loads(result.stdout)  # type: ignore[attr-defined]
        assert payload["ok"] is False
        assert payload["message"] == message
    else:
        assert message in re.sub(r"\s+", " ", _visible(result))


@pytest.mark.parametrize(
    ("name", "hint"),
    [
        ("DEBUG", "deployment plans were removed in 0.17.0; pass PREVIEW or RELEASE"),
        (
            "MANUAL",
            "deployment plans were removed in 0.17.0; a tenant that only takes the rules "
            "naming it sets 'manual = true'",
        ),
        (
            "ALWAYS",
            "deployment plans were removed in 0.17.0; a tenant lists the strategies it "
            "accepts in 'strategies'",
        ),
    ],
)
@_CI_PLATFORMS
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_an_old_plan_name_as_a_strategy_is_refused_in_ci(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    name: str,
    hint: str,
    platform: dict[str, str],
    json_output: bool,
) -> None:
    """DEBUG, MANUAL and ALWAYS were not CI diff plans; they are not strategies either."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", name],
        env=_env(repo, **_ci_values(platform, repo, head)),
    )
    _assert_refused(
        result,
        f"--strategy {name!r} is not a deployable strategy. Use PREVIEW or RELEASE. {hint}",
        json_output=json_output,
    )


@pytest.mark.parametrize(
    ("plan", "replacement"),
    [
        ("STAGING", "--strategy PREVIEW"),
        ("PRODUCTION", "--strategy RELEASE"),
        ("FULL", "--strategy PREVIEW --strategy RELEASE --all"),
        ("ALWAYS", "--strategy PREVIEW or --strategy RELEASE"),
    ],
)
@_CI_PLATFORMS
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_the_removed_plan_option_names_its_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    plan: str,
    replacement: str,
    platform: dict[str, str],
    json_output: bool,
) -> None:
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--plan", plan],
        env=_env(repo, **_ci_values(platform, repo, head)),
    )
    _assert_refused(
        result,
        "--plan was removed in 0.17.0: a run now says which status strategy it deploys. "
        f"Use {replacement}. See 'opentide deploy --help'.",
        json_output=json_output,
    )


@_CI_PLATFORMS
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_a_pipeline_still_setting_deployment_plan_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    platform: dict[str, str],
    json_output: bool,
) -> None:
    """The generated jobs used to export ``DEPLOYMENT_PLAN``; it must not be silently ignored."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run", "--strategy", "RELEASE"],
        env=_env(repo, DEPLOYMENT_PLAN="PRODUCTION", **_ci_values(platform, repo, head)),
    )
    _assert_refused(
        result,
        "DEPLOYMENT_PLAN was removed in 0.17.0: a run now says which status strategy it "
        "deploys. Use --strategy RELEASE. Unset DEPLOYMENT_PLAN. See 'opentide deploy --help'.",
        json_output=json_output,
    )


@_CI_PLATFORMS
@pytest.mark.parametrize("json_output", [False, True], ids=["human", "json"])
def test_a_ci_deploy_without_a_strategy_is_refused(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    platform: dict[str, str],
    json_output: bool,
) -> None:
    from opentide.cli.services.deploy import STRATEGY_REQUIRED

    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    head = _init_repo(repo)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        [*(["--json"] if json_output else []), "deploy", "--dry-run"],
        env=_env(repo, **_ci_values(platform, repo, head)),
    )
    _assert_refused(result, STRATEGY_REQUIRED, json_output=json_output)


def _shallow_clone(tmp_path: Path) -> tuple[Path, str, str]:
    origin = tmp_path / "origin"
    origin.mkdir()
    _init_repo(origin, commits=2)
    parent = _git(origin, "rev-parse", "HEAD^")
    head = _git(origin, "rev-parse", "HEAD")
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "--depth", "1", "--no-local", "--quiet", str(origin), str(clone)],
        check=True,
        capture_output=True,
    )
    return clone, head, parent


@pytest.mark.parametrize(
    ("strategy", "change_request"),
    [("PREVIEW", True), ("RELEASE", False)],
    ids=["pull-request", "push"],
)
def test_shallow_checkout_names_the_missing_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_home: Path,
    strategy: str,
    change_request: bool,
) -> None:
    """#348: a depth-1 clone of two commits crashed with ``b'<parent sha>'``."""
    del git_home
    repo, head, parent = _shallow_clone(tmp_path)
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", strategy],
        env=_env(
            repo,
            GITHUB_ACTIONS="true",
            GITHUB_WORKSPACE=str(repo),
            GITHUB_SHA=head,
            **(_CHANGE_REQUEST["GITHUB_ACTIONS"] if change_request else {}),
        ),
    )
    rendered = result.stdout + result.stderr
    assert result.exit_code == 1, rendered
    assert f"b'{parent}'" not in rendered
    assert "Traceback" not in rendered
    payload = json.loads(result.stdout)
    if not change_request:
        assert payload["message"] == f"Could not find git commit {parent}"
    else:
        assert "GITHUB_HEAD_REF" in payload["message"]
        assert "GITHUB_BASE_REF" in payload["message"]


def test_gitlab_merged_result_with_one_parent_keeps_the_tip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    """A one-parent ``CI_COMMIT_BEFORE_SHA`` must not index ``parents[1]``."""
    del git_home
    repo = tmp_path / "repo"
    repo.mkdir()
    _init_repo(repo)
    _git(repo, "checkout", "-q", "-b", "feature")
    (repo / "README.md").write_text("feature\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "feature")
    _git(repo, "checkout", "-q", "main")
    _git(repo, "merge", "--no-ff", "-q", "-m", "merge feature", "feature")
    head = _git(repo, "rev-parse", "HEAD")
    parent = _git(repo, "rev-parse", "HEAD^1")
    monkeypatch.chdir(repo)
    result = runner.invoke(
        app,
        ["--json", "deploy", "--dry-run", "--strategy", "PREVIEW"],
        env=_env(
            repo,
            **_CHANGE_REQUEST["CI"],
            CI="true",
            CI_PROJECT_DIR=str(repo),
            CI_COMMIT_SHA=head,
            CI_COMMIT_BEFORE_SHA=parent,
            CI_MERGE_REQUEST_DIFF_BASE_SHA=parent,
            CI_MERGE_REQUEST_EVENT_TYPE="merged_result",
        ),
    )
    assert result.exit_code == 0, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert "list index out of range" not in result.stdout
