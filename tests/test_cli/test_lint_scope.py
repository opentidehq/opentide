"""``lint --changed`` and ``--file``: every check narrowed to the selected object files.

The CI pipeline gates on ``lint --strict``, which no inherited catalogue passes
on day one (hundreds of objects without ``author``). Narrowed to the files a
pull request changed, the gate holds new work to the convention without
failing on the backlog (0.20.1 migration report).
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from opentide.cli import app
from opentide.cli.enums import LintCheck
from opentide.cli.services.lint import run_lint

runner = CliRunner()

#: CI variables that would make the diff a CI run's instead of the last commit's.
_CI_VARIABLES = (
    "CI",
    "CI_PROJECT_DIR",
    "CI_PIPELINE_SOURCE",
    "CI_COMMIT_SHA",
    "CI_COMMIT_BEFORE_SHA",
    "CI_MERGE_REQUEST_DIFF_BASE_SHA",
    "CI_MERGE_REQUEST_EVENT_TYPE",
    "GITHUB_ACTIONS",
    "GITHUB_EVENT_NAME",
    "GITHUB_EVENT_PATH",
    "GITHUB_WORKSPACE",
    "GITHUB_SHA",
    "GITHUB_HEAD_REF",
    "GITHUB_BASE_REF",
    "TF_BUILD",
    "BUILD_REASON",
    "BUILD_SOURCESDIRECTORY",
    "BUILD_SOURCEVERSION",
    "SYSTEM_PULLREQUEST_SOURCEBRANCH",
    "SYSTEM_PULLREQUEST_TARGETBRANCHNAME",
)


def _threat(name: str, uuid_tail: str, *, author: bool = False) -> str:
    return (
        f"name: {name}\n"
        "metadata:\n"
        f"  uuid: 00000000-0000-4000-8001-{uuid_tail:0>12}\n"
        "  schema: threat::1.0\n" + ("  author: SOC\n  organisation: Example\n" if author else "")
    )


def _write(root: Path, relative: str, body: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


def _paths(result: dict[str, object]) -> set[str]:
    findings = result["findings"]
    assert isinstance(findings, list)
    return {str(item["path"]) for item in findings}


@pytest.fixture
def catalogue(tmp_path: Path) -> Path:
    """Two threats, each misnamed and without author: two findings apiece."""
    root = tmp_path / "workspace"
    (root / ".opentide").mkdir(parents=True)
    _write(root, "objects/threats/Actor One.yaml", _threat("Actor One", "1"))
    _write(root, "objects/threats/Actor Two.yaml", _threat("Actor Two", "2"))
    return root


def test_file_narrows_every_check_to_the_selected_file(catalogue: Path) -> None:
    result = run_lint(catalogue, files=["objects/threats/Actor One.yaml"])

    assert _paths(result) == {"objects/threats/Actor One.yaml"}
    assert {item["check"] for item in result["findings"]} == {"filenames", "metadata"}  # type: ignore[union-attr]
    assert result["scope"] == "selected"
    assert result["_summary"]["files"] == 1  # type: ignore[index]
    assert "scope" not in run_lint(catalogue)


def test_file_takes_a_bare_name_an_absolute_path_and_repeats(catalogue: Path) -> None:
    absolute = str(catalogue / "objects/threats/Actor Two.yaml")

    result = run_lint(catalogue, files=["Actor One.yaml", absolute])

    assert _paths(result) == {"objects/threats/Actor One.yaml", "objects/threats/Actor Two.yaml"}


def test_file_that_selects_nothing_fails_and_names_it(catalogue: Path) -> None:
    _write(catalogue, "objects/threats/team/nested.yaml", _threat("Nested", "3"))

    result = run_lint(
        catalogue,
        files=[
            "objects/threats/Actor One.yaml",
            "objects/threats/missing.yaml",
            "objects/threats/team/nested.yaml",
        ],
    )

    assert result["status"] == "failed"
    assert result["_exit_code"] == 1
    assert result["unmatched"] == [
        "objects/threats/missing.yaml",
        "objects/threats/team/nested.yaml",
    ]
    assert "objects/threats/missing.yaml" in str(result["message"])


def test_changed_and_file_together_are_a_usage_error(catalogue: Path) -> None:
    human = runner.invoke(
        app,
        ["--json", "--repo", str(catalogue), "lint", "--changed", "--file", "Actor One.yaml"],
    )

    assert human.exit_code == 2
    payload = json.loads(human.stdout)
    assert payload["failure"]["code"] == "usage_error"
    assert payload["message"] == "--changed cannot be combined with --file"


def test_a_stem_held_by_an_unselected_file_is_still_a_collision(tmp_path: Path) -> None:
    """The filenames check reads the whole folder: a full run would give the same answer."""
    _write(tmp_path, "objects/threats/actor.yaml", _threat("Actor", "1", author=True))
    other = _write(tmp_path, "objects/threats/other.yaml", _threat("Actor", "2", author=True))

    result = run_lint(tmp_path, files=[str(other)], fix=True, checks=[LintCheck.filenames])

    assert [item["expected"] for item in result["findings"]] == [  # type: ignore[union-attr]
        "objects/threats/actor-00000000.yaml"
    ]
    assert (tmp_path / "objects/threats/actor.yaml").is_file()


def test_fix_on_a_narrowed_run_renames_only_the_selected_file(catalogue: Path) -> None:
    result = run_lint(catalogue, files=["Actor One.yaml"], checks=[LintCheck.filenames])
    assert [action.command for action in result["_next_actions"]] == [  # type: ignore[union-attr]
        "opentide lint --fix --file 'Actor One.yaml'"
    ]

    run_lint(catalogue, files=["Actor One.yaml"], fix=True)

    assert sorted(path.name for path in (catalogue / "objects/threats").iterdir()) == [
        "Actor Two.yaml",
        "actor-one.yaml",
    ]


# --------------------------------------------------------------------------- --changed


def _git(cwd: Path, *args: str) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return done.stdout.strip()


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def checkout(catalogue: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path) -> Iterator[Path]:
    """The two-threat catalogue committed, outside CI, as the workspace."""
    del git_home
    from tests.corpus_support import clear_runtime_caches

    _git(catalogue, "init", "-q", "-b", "main")
    _commit(catalogue, "catalogue")
    for name in _CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(catalogue))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(catalogue))
    monkeypatch.chdir(catalogue)
    clear_runtime_caches()
    yield catalogue
    clear_runtime_caches()


def _lint(*args: str, env: dict[str, str] | None = None) -> tuple[int, dict[str, object]]:
    result = runner.invoke(app, ["--json", "lint", *args], env=env)
    return result.exit_code, json.loads(result.stdout)


def test_changed_outside_ci_lints_the_last_commits_files(checkout: Path) -> None:
    _write(checkout, "objects/threats/Actor Two.yaml", _threat("Actor Two", "2") + "# edited\n")
    _write(checkout, "README.md", "not an object\n")
    _commit(checkout, "edit one threat")

    code, payload = _lint("--strict", "--changed")

    assert code == 1, payload
    assert _paths(payload) == {"objects/threats/Actor Two.yaml"}
    assert payload["scope"] == "changed"
    assert payload["summary"]["files"] == 1  # type: ignore[index]


def test_changed_with_no_object_file_passes_strict(checkout: Path) -> None:
    _write(checkout, "README.md", "not an object\n")
    _commit(checkout, "readme")

    code, payload = _lint("--strict", "--changed")

    assert code == 0, payload
    assert payload["status"] == "completed"
    assert payload["count"] == 0
    human = runner.invoke(app, ["--no-color", "lint", "--strict", "--changed"])
    assert human.exit_code == 0
    assert "No changed object file to lint" in human.stdout


def test_changed_on_a_github_push_reads_the_pushed_commits(checkout: Path) -> None:
    base = _git(checkout, "rev-parse", "HEAD")
    _write(checkout, "objects/threats/actor-three.yaml", _threat("Actor Three", "3"))
    _commit(checkout, "new threat")
    _write(checkout, "README.md", "later\n")
    head = _commit(checkout, "readme")
    event = checkout.parent / "event.json"
    event.write_text(json.dumps({"before": base, "after": head}), encoding="utf-8")

    code, payload = _lint(
        "--changed",
        env={
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_EVENT_PATH": str(event),
            "GITHUB_WORKSPACE": str(checkout),
            "GITHUB_SHA": head,
        },
    )

    assert code == 0, payload
    # Both commits of the push, so the threat added before the README is linted.
    assert _paths(payload) == {"objects/threats/actor-three.yaml"}


def test_changed_reads_a_workspace_nested_in_the_checkout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, git_home: Path
) -> None:
    del git_home
    from tests.corpus_support import clear_runtime_caches

    repo = tmp_path / "repo"
    workspace = repo / "detections"
    (workspace / ".opentide").mkdir(parents=True)
    _write(workspace, "objects/threats/Actor One.yaml", _threat("Actor One", "1"))
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "catalogue")
    _write(workspace, "objects/threats/Actor Two.yaml", _threat("Actor Two", "2"))
    _write(repo, "objects/threats/outside.yaml", _threat("Outside", "9"))
    _commit(repo, "one threat in the workspace, one outside it")
    for name in _CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(workspace))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(workspace))
    monkeypatch.chdir(workspace)
    clear_runtime_caches()

    result = run_lint(workspace, changed=True)

    clear_runtime_caches()
    assert _paths(result) == {"objects/threats/Actor Two.yaml"}


def test_changed_without_a_checkout_fails(catalogue: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _CI_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(catalogue.parent))

    result = run_lint(catalogue, changed=True)

    assert result["_exit_code"] == 1
    assert str(result["message"]).startswith("--changed needs a git checkout")


def test_narrowed_json_matches_the_lint_result_model(checkout: Path) -> None:
    from tests.result_models_support import document_problems

    _write(checkout, "objects/threats/Actor Two.yaml", _threat("Actor Two", "2") + "# edited\n")
    _commit(checkout, "edit one threat")

    for args in (("--changed",), ("--file", "missing.yaml"), ("--file", "Actor One.yaml")):
        _, payload = _lint(*args)
        assert not document_problems(payload), args
