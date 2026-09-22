"""CLI E2E: ``validate --file`` scoping and unparseable object YAML.

Covers harness gaps #267 and #265: the corpus is driven through real
repo-relative, absolute, and basename ``--file`` targets (issue #240), and a
deliberately broken object file must produce a validation issue rather than a
``yaml.ParserError`` traceback (issue #250).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from pytest_console_scripts import ScriptRunner
from tests.test_cli.conftest import assert_json_ok, parse_cli_json

pytestmark = pytest.mark.cli_e2e

CORPUS_RULE = "rule-0001-sentinel-kql.yaml"
CORPUS_RULE_RELATIVE = f"objects/rules/{CORPUS_RULE}"


def _issue_codes(payload: dict[str, object]) -> list[str]:
    report = payload["report"]
    assert isinstance(report, dict)
    return [issue["code"] for issue in report["issues"]]


@pytest.mark.parametrize(
    "target_style",
    ["basename", "repo-relative", "absolute", "legacy-capitalised"],
)
def test_validate_file_accepts_every_documented_path_form(
    invoke_cli,
    tide_corpus_repo: Path,
    target_style: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = f"Objects/Detection Rules/{CORPUS_RULE}"
    target = {
        "basename": CORPUS_RULE,
        "repo-relative": CORPUS_RULE_RELATIVE,
        "absolute": str(tide_corpus_repo / CORPUS_RULE_RELATIVE),
        "legacy-capitalised": legacy,
    }[target_style]
    if target_style in {"repo-relative", "legacy-capitalised"}:
        # Repo-relative targets are resolved from the working directory, which
        # is how a user in their detection repo types them.
        monkeypatch.chdir(tide_corpus_repo)
    payload = assert_json_ok(invoke_cli("validate", "--file", target))
    report = payload["report"]
    assert isinstance(report, dict)
    assert report["ok"] is True
    assert report["stats"]["objects_checked"] == 1, report["stats"]


def test_validate_file_unknown_path_does_not_silently_pass(invoke_cli) -> None:
    result = invoke_cli("validate", "--file", "objects/rules/does-not-exist.yaml")
    assert result.exit_code != 0
    payload = parse_cli_json(result)
    assert "scope_no_match" in _issue_codes(payload)


def test_validate_file_scopes_out_other_objects(
    invoke_cli, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tide_corpus_repo)
    payload = assert_json_ok(invoke_cli("validate", "--file", CORPUS_RULE_RELATIVE))
    report = payload["report"]
    assert isinstance(report, dict)
    assert report["stats"]["objects_checked"] == 1


def test_unparseable_object_yaml_is_a_validation_issue(invoke_cli, tide_corpus_repo: Path) -> None:
    broken = tide_corpus_repo / "Objects" / "Detection Rules" / "broken.yaml"
    broken.write_text("name: [\n", encoding="utf-8")
    result = invoke_cli("validate", "--strict")
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = parse_cli_json(result)
    assert payload["status"] == "failed"
    assert "yaml_parse" in _issue_codes(payload)
    assert "Traceback" not in (result.stdout + result.stderr)
    assert payload["checks"]["schema"]["status"] == "failed"


def test_unparseable_object_yaml_scoped_by_file(invoke_cli, tide_corpus_repo: Path) -> None:
    broken = tide_corpus_repo / "Objects" / "Detection Rules" / "broken.yaml"
    broken.write_text("name: [\n", encoding="utf-8")
    result = invoke_cli("validate", "--file", "broken.yaml")
    assert result.exit_code != 0
    codes = _issue_codes(parse_cli_json(result))
    assert codes == ["yaml_parse"], codes


@pytest.mark.cli_smoke
@pytest.mark.script_launch_mode("subprocess")
def test_validate_file_and_broken_yaml_on_console_script(
    script_runner: ScriptRunner, tmp_path: Path
) -> None:
    """Same contract through the installed binary: one JSON document, no traceback."""
    repo = tmp_path / "repo"
    env = os.environ.copy()
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    setup = script_runner.run(
        [
            "opentide",
            "--json",
            "setup",
            "--yes",
            "--name",
            "Scope",
            "--platform",
            "sentinel",
            "--path",
            str(repo),
        ],
        env=env,
        print_result=False,
    )
    assert setup.returncode == 0, setup.stdout + setup.stderr

    from tests.test_cli.e2e.helpers import write_tutorial_objects

    write_tutorial_objects(repo)
    scoped = script_runner.run(
        [
            "opentide",
            "--json",
            "--repo",
            str(repo),
            "validate",
            "--file",
            "objects/rules/sentinel-kql-rule.yaml",
        ],
        env=env,
        cwd=str(repo),
        print_result=False,
    )
    assert scoped.returncode == 0, scoped.stdout + scoped.stderr
    payload = json.loads(scoped.stdout.strip())
    assert payload["report"]["stats"]["objects_checked"] == 1

    (repo / "objects" / "rules" / "broken.yaml").write_text("name: [\n", encoding="utf-8")
    broken = script_runner.run(
        ["opentide", "--json", "--repo", str(repo), "validate", "--strict"],
        env=env,
        cwd=str(repo),
        print_result=False,
    )
    assert broken.returncode == 1, broken.stdout + broken.stderr
    assert "Traceback" not in broken.stderr
    broken_payload = json.loads(broken.stdout.strip())
    assert any(issue["code"] == "yaml_parse" for issue in broken_payload["report"]["issues"]), (
        broken_payload
    )
