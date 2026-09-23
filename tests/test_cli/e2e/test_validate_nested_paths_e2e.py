"""CLI E2E: ``validate --file`` with object files in nested folders (issue #297).

The index kept only each object's basename and validation rebuilt its path as
``<type folder>/<basename>``. Every object in a subfolder therefore "lived" at
the top-level file sharing its name: ``--file objects/rules/x.yaml`` also
validated ``objects/rules/other/x.yaml`` and blamed that object's issues on the
parent file, while ``--file objects/rules/other/x.yaml`` matched nothing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pytest_console_scripts import ScriptRunner
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.conftest import assert_json_ok, parse_cli_json
from tests.test_cli.e2e.helpers import write_tutorial_objects
from tests.validation_support import (
    NESTED_TWIN_LAYOUT,
    TWIN,
    assert_issues_point_at_their_objects,
    write_nested_twins,
)

pytestmark = pytest.mark.cli_e2e

TUTORIAL_RULE = "objects/rules/sentinel-kql-rule.yaml"
TUTORIAL_RULE_UUID = "00000000-0000-4000-8003-000000000001"
TUTORIAL_OBJECTIVE_UUID = "00000000-0000-4000-8002-000000000001"
DECOY_RULE = "objects/rules/other/sentinel-kql-rule.yaml"
DECOY_UUID = "00000000-0000-4000-8003-000000000099"
DECOY_DETECTION_MODEL = "00000000-0000-4000-8002-DEADBEEF0000"


def write_decoy(repo: Path) -> Path:
    """The #297 decoy: the tutorial rule, one folder down, with a dangling parent."""
    decoy = repo / DECOY_RULE
    decoy.parent.mkdir(parents=True, exist_ok=True)
    text = (repo / TUTORIAL_RULE).read_text(encoding="utf-8")
    decoy.write_text(
        text.replace(TUTORIAL_RULE_UUID, DECOY_UUID).replace(
            TUTORIAL_OBJECTIVE_UUID, DECOY_DETECTION_MODEL
        ),
        encoding="utf-8",
    )
    return decoy


def _report(payload: dict[str, object]) -> dict:
    report = payload["report"]
    assert isinstance(report, dict)
    return report


def _issue_uuids(report: dict) -> set[str]:
    return {issue["object_uuid"] for issue in report["issues"] if issue["object_uuid"]}


@pytest.fixture
def tutorial_with_decoy(invoke_cli, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Tutorial repo plus the decoy, with the repo as the working directory.

    The suite pins repo discovery to this checkout, so in-process runs pass
    ``--repo``; the console-script smoke below runs the issue's commands with
    no repo flag or environment at all.
    """
    repo = tmp_path / "tutorial-detections"
    assert_json_ok(
        invoke_cli(
            "setup",
            "--yes",
            "--name",
            "Tutorial Detections",
            "--platform",
            "sentinel",
            "--path",
            str(repo),
            repo=tmp_path,
        )
    )
    write_tutorial_objects(repo)
    write_decoy(repo)
    monkeypatch.chdir(repo)
    monkeypatch.setenv("OPENTIDE_REPO_ROOT", str(repo))
    monkeypatch.setenv("OPENTIDE_TIDE_WORKSPACE", str(repo))
    return repo


def _validate(invoke_cli, repo: Path, *args: str) -> tuple[int, dict]:
    result = invoke_cli("validate", *args, repo=repo)
    return result.exit_code, _report(parse_cli_json(result))


def _target(repo: Path, relative: str, style: str) -> str:
    return {
        "repo-relative": relative,
        "dot-relative": f"./{relative}",
        "absolute": str(repo / relative),
    }[style]


@pytest.mark.parametrize("style", ["repo-relative", "dot-relative", "absolute"])
def test_the_parent_path_selects_only_the_parent_file(
    invoke_cli, tutorial_with_decoy: Path, style: str
) -> None:
    repo = tutorial_with_decoy
    code, report = _validate(invoke_cli, repo, "--file", _target(repo, TUTORIAL_RULE, style))
    assert code == 0, report["issues"]
    assert report["stats"]["objects_checked"] == 1, report["stats"]
    assert DECOY_UUID not in _issue_uuids(report)
    assert_issues_point_at_their_objects(report)


@pytest.mark.parametrize("style", ["repo-relative", "dot-relative", "absolute"])
def test_the_nested_path_selects_the_decoy_and_blames_its_own_file(
    invoke_cli, tutorial_with_decoy: Path, style: str
) -> None:
    repo = tutorial_with_decoy
    code, report = _validate(invoke_cli, repo, "--file", _target(repo, DECOY_RULE, style))
    assert code == 1
    assert report["stats"]["objects_checked"] == 1, report["stats"]
    codes = {issue["code"] for issue in report["issues"]}
    assert "invalid_ref" in codes
    assert "scope_no_match" not in codes
    assert _issue_uuids(report) == {DECOY_UUID}
    decoy = (tutorial_with_decoy / DECOY_RULE).resolve()
    for issue in report["issues"]:
        assert Path(issue["file_path"]).resolve() == decoy, issue
    assert_issues_point_at_their_objects(report)


def test_a_bare_file_name_selects_every_file_with_that_name(
    invoke_cli, tutorial_with_decoy: Path
) -> None:
    """A basename has no directory to disagree with, so it matches in every subfolder."""
    code, report = _validate(invoke_cli, tutorial_with_decoy, "--file", "sentinel-kql-rule.yaml")
    assert code == 1
    assert report["stats"]["objects_checked"] == 2, report["stats"]
    assert _issue_uuids(report) == {DECOY_UUID}
    decoy = (tutorial_with_decoy / DECOY_RULE).resolve()
    assert {Path(issue["file_path"]).resolve() for issue in report["issues"]} == {decoy}
    assert_issues_point_at_their_objects(report)


def test_a_full_run_blames_the_decoy_on_its_own_file(invoke_cli, tutorial_with_decoy: Path) -> None:
    _, report = _validate(invoke_cli, tutorial_with_decoy)
    assert _issue_uuids(report) == {DECOY_UUID}
    assert_issues_point_at_their_objects(report)


@pytest.mark.parametrize("args", [(), ("--file", "objects/rules/other/copy-of-rule.yaml")])
def test_a_duplicate_uuid_in_a_subfolder_fails_validation(
    invoke_cli, tutorial_with_decoy: Path, args: tuple[str, ...]
) -> None:
    """The ID scan only read the top of each folder, so this passed a full run."""
    repo = tutorial_with_decoy
    (repo / DECOY_RULE).unlink()
    copy = repo / "objects" / "rules" / "other" / "copy-of-rule.yaml"
    copy.write_text((repo / TUTORIAL_RULE).read_text(encoding="utf-8"), encoding="utf-8")
    code, report = _validate(invoke_cli, repo, *args)
    assert code == 1
    duplicates = [issue for issue in report["issues"] if issue["code"] == "duplicate_id"]
    assert duplicates, report["issues"]
    assert {issue["object_uuid"] for issue in duplicates} == {TUTORIAL_RULE_UUID}
    assert_issues_point_at_their_objects(report)


def test_mcp_validation_report_selects_the_nested_file(tutorial_with_decoy: Path) -> None:
    from opentide.mcp_server.tools import tool_validation_report

    clear_runtime_caches()
    nested = tool_validation_report(file=DECOY_RULE)
    assert nested["stats"]["objects_checked"] == 1, nested["stats"]
    assert _issue_uuids(nested) == {DECOY_UUID}
    assert_issues_point_at_their_objects(nested)

    clear_runtime_caches()
    parent = tool_validation_report(file=TUTORIAL_RULE)
    assert parent["ok"] is True, parent["issues"]
    assert parent["stats"]["objects_checked"] == 1, parent["stats"]


@pytest.mark.cli_smoke
@pytest.mark.script_launch_mode("subprocess")
def test_issue_297_commands_on_console_script(script_runner: ScriptRunner, tmp_path: Path) -> None:
    """The two commands from the issue, through the installed binary, with no repo env."""
    repo = tmp_path / "repo"
    env = {k: v for k, v in os.environ.items() if not k.startswith("OPENTIDE_")}
    setup = script_runner.run(
        ["opentide", "--json", "setup", "--yes", "--name", "Scope", "--platform", "sentinel"]
        + ["--path", str(repo)],
        env=env,
        cwd=str(tmp_path),
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr
    write_tutorial_objects(repo)
    write_decoy(repo)

    def _run(target: str) -> tuple[int, dict]:
        result = script_runner.run(
            ["opentide", "--json", "validate", "--file", target],
            env=env,
            cwd=str(repo),
            print_result=False,
        )
        assert "Traceback" not in result.stderr, result.stderr
        return result.returncode, json.loads(result.stdout.strip())["report"]

    code, parent = _run(TUTORIAL_RULE)
    assert code == 0, parent["issues"]
    assert parent["stats"]["objects_checked"] == 1

    code, nested = _run(DECOY_RULE)
    assert code == 1
    assert nested["stats"]["objects_checked"] == 1
    assert _issue_uuids(nested) == {DECOY_UUID}
    assert {Path(issue["file_path"]).resolve() for issue in nested["issues"]} == {
        (repo / DECOY_RULE).resolve()
    }
    assert_issues_point_at_their_objects(nested)


# --- Same-basename layouts across object types and depths -------------------


@pytest.fixture
def nested_twins(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    """Write the nested-twin layout into the corpus; return UUID -> real file path."""
    real_paths = write_nested_twins(tide_corpus_repo)
    monkeypatch.chdir(tide_corpus_repo)
    return real_paths


def _uuid(relative: str) -> str:
    return NESTED_TWIN_LAYOUT[relative][1]


_ALL_TWINS = frozenset(uuid for _, uuid in NESTED_TWIN_LAYOUT.values())
_LAYOUT_CASES: list[tuple[str, frozenset[str]]] = [
    *((relative, frozenset({_uuid(relative)})) for relative in NESTED_TWIN_LAYOUT),
    (TWIN, _ALL_TWINS),
    (
        f"./objects/threats/actors/apt/{TWIN}",
        frozenset({_uuid(f"objects/threats/actors/apt/{TWIN}")}),
    ),
    (
        f"<abs>objects/objectives/access/emea/{TWIN}",
        frozenset({_uuid(f"objects/objectives/access/emea/{TWIN}")}),
    ),
    (
        f"Objects/Detection Rules/team-a/{TWIN}",
        frozenset({_uuid(f"objects/rules/team-a/{TWIN}")}),
    ),
    (f"objects/rules/emea/{TWIN}", frozenset()),
    (f"objects/rules/team-a/emea/deeper/{TWIN}", frozenset()),
    (f"objects/threats/team-a/{TWIN}", frozenset()),
]


@pytest.mark.parametrize(
    ("target", "expected"),
    _LAYOUT_CASES,
    ids=[target.replace("<abs>", "absolute:") for target, _ in _LAYOUT_CASES],
)
def test_a_file_target_selects_exactly_its_objects_and_blames_their_own_files(
    invoke_cli,
    nested_twins: dict[str, Path],
    tide_corpus_repo: Path,
    target: str,
    expected: frozenset[str],
) -> None:
    if target.startswith("<abs>"):
        target = str(tide_corpus_repo / target.removeprefix("<abs>"))
    exit_code, report = _validate(invoke_cli, tide_corpus_repo, "--file", target)
    codes = [issue["code"] for issue in report["issues"]]

    assert _issue_uuids(report) == expected, report["issues"]
    assert report["stats"]["objects_checked"] == len(expected), report["stats"]
    for uuid in expected:
        assert any(
            issue["object_uuid"] == uuid and issue["code"] == "invalid_ref"
            for issue in report["issues"]
        ), uuid
    for issue in report["issues"]:
        if issue["object_uuid"]:
            assert Path(issue["file_path"]).resolve() == nested_twins[issue["object_uuid"]], issue
    assert_issues_point_at_their_objects(report)
    if not expected:
        assert "scope_no_match" in codes
        assert exit_code == 1
