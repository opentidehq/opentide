"""What a person or an agent sees when an object or a configuration file is wrong.

From the spec audit and the end-to-end run of the CLI rework: case-only typos
with no fix (D1, E2E 15), a missing field with no position (E2E 9), no next
step after a failed ``validate`` (D8), a TOML typo reported as a crash (E2E 2),
a list at the top of a rule file reported as a Python error (E2E 3), and log
lines that repeat what the result already says (D14, D20).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

runner = CliRunner()

_RULE = Path("objects", "rules", "sentinel-kql-rule.yaml")
_PLATFORM = Path(".opentide", "configurations", "platforms", "sentinel.toml")
_CI_ENV = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "TF_BUILD", "CLAUDECODE", "AI_AGENT")
_DEPLOY = ("deploy", "--dry-run", "--strategy", "PREVIEW", "--all", "--platform", "sentinel")


@pytest.fixture(scope="module")
def pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repo = tmp_path_factory.mktemp("pristine") / "detections"
    run_repo_setup(RepoSetupOptions(path=repo, name="Detections", yes=True))
    write_tutorial_objects(repo)
    return repo


@pytest.fixture
def repo(pristine: Path, tmp_path: Path) -> Path:
    import shutil

    target = tmp_path / "detections"
    shutil.copytree(pristine, target)
    return target


def _edit(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{path.name} no longer contains {old!r}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _invoke(repo: Path, *args: str, json_output: bool = True) -> Result:
    env = dict.fromkeys(_CI_ENV)
    env["OPENTIDE_REPO_ROOT"] = str(repo)
    env["OPENTIDE_TIDE_WORKSPACE"] = str(repo)
    env["OPENTIDE_LINKS"] = "none"
    flags = ["--json"] if json_output else ["--no-color"]
    return runner.invoke(app, [*flags, "--repo", str(repo), *args], env=env)


def _issues(result: Result) -> dict[str, dict]:
    payload = json.loads(result.stdout)
    return {".".join(issue["field_path"]): issue for issue in payload["report"]["issues"]}


# --------------------------------------------------------------------------
# validate
# --------------------------------------------------------------------------


def test_case_only_typos_get_a_safe_fix(repo: Path) -> None:
    """D1 and E2E 15: ``AMBER``, ``high`` and ``design`` are respellings."""
    rule = repo / _RULE
    _edit(rule, "  tlp: clear\n", "  tlp: AMBER\n")
    _edit(rule, "\nseverity: High\n", "\nseverity: high\n")
    _edit(rule, "    status: STAGING", "    status: staging")
    issues = _issues(_invoke(repo, "validate"))
    expected = {
        "metadata.tlp": ("vocab_unknown", "amber"),
        "severity": ("vocab_unknown", "High"),
        "configurations.sentinel.status": ("config_enum_unknown", "STAGING"),
    }
    assert set(issues) == set(expected)
    for field, (code, value) in expected.items():
        issue = issues[field]
        assert issue["code"] == code
        assert issue["suggestion"] == value
        assert issue["help"] == f"did you mean {value!r}?"
        assert issue["fix"]["safe"] is True, field
        assert issue["fix"]["edits"][0]["replacement"] == value


def test_an_unknown_platform_status_fails_validate_as_deploy_would(repo: Path) -> None:
    _edit(repo / _RULE, "    status: STAGING", "    status: SHIPPED")
    issue = _issues(_invoke(repo, "validate"))["configurations.sentinel.status"]
    assert issue["code"] == "config_enum_unknown"
    assert issue["fix"] is None


def test_a_missing_field_is_framed_in_the_spec_words(repo: Path) -> None:
    """E2E 9: ``description: Field required`` had no line and no frame."""
    _edit(repo / _RULE, "description: Detects", "summary: Detects")
    result = _invoke(repo, "validate", json_output=False)
    assert result.exit_code == 1
    assert (
        "error[schema_validation]: missing required field 'description'\n"
        "  ╭─▶ objects/rules/sentinel-kql-rule.yaml:1:1\n"
    ) in result.stdout
    assert "━━━━ add 'description' at the top level" in result.stdout


def test_a_failed_validate_says_what_to_run_next(repo: Path) -> None:
    """D8: MCP gave ``explain`` and validate-again; the CLI gave nothing."""
    _edit(repo / _RULE, "  tlp: clear\n", "  tlp: clearr\n")
    payload = json.loads(_invoke(repo, "validate").stdout)
    assert payload["next_actions"] == [
        {"command": "opentide --json explain vocab_unknown", "reason": "how to fix it"},
        {"command": "opentide --json validate", "reason": "check again"},
    ]
    human = _invoke(repo, "validate", json_output=False)
    assert human.stderr.endswith(
        "→ opentide explain vocab_unknown · how to fix it\n→ opentide validate · check again\n"
    )


def test_a_passing_validate_suggests_nothing(repo: Path) -> None:
    assert json.loads(_invoke(repo, "validate").stdout)["next_actions"] == []


def test_an_empty_catalogue_names_its_directory_relative_to_the_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """D20: the outcome showed the absolute workspace path."""
    repo = tmp_path / "empty"
    run_repo_setup(RepoSetupOptions(path=repo, name="Empty", yes=True))
    monkeypatch.chdir(tmp_path)
    payload = json.loads(_invoke(repo, "validate").stdout)
    assert payload["message"] == (
        "Validation passed, but no detection objects were found under ./empty"
    )


# --------------------------------------------------------------------------
# A file the user must fix, from any command
# --------------------------------------------------------------------------

_COMMANDS = [("validate",), ("info",), _DEPLOY]


def _break_platform_file(repo: Path) -> None:
    """A platform file whose tenants header misses a bracket, on line 4, column 10."""
    path = repo / _PLATFORM
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        '[platform]\nidentifier = "sentinel"\n\n[[tenants]\nname = "prod"\n', encoding="utf-8"
    )


@pytest.mark.parametrize("command", _COMMANDS, ids=lambda command: command[0])
def test_a_toml_typo_is_a_config_diagnostic_not_a_crash(repo: Path, command: tuple) -> None:
    """E2E 2: ``[[tenants]`` reached the crash handler as ``error[internal]``."""
    _break_platform_file(repo)
    result = _invoke(repo, *command)
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["command"] == command[0]
    assert payload["failure"]["code"] == "config_parse"
    (diagnostic,) = payload["diagnostics"]
    assert diagnostic["path"] == _PLATFORM.as_posix()
    assert (diagnostic["line"], diagnostic["column"]) == (4, 10)
    assert diagnostic["help"]
    assert payload["next_actions"][0]["command"] == "opentide --json explain config_parse"


def test_a_toml_typo_prints_a_frame_then_one_outcome_line(repo: Path) -> None:
    _break_platform_file(repo)
    result = _invoke(repo, "validate", json_output=False)
    assert result.exit_code == 1
    assert "Traceback" not in result.output
    assert result.stderr.startswith(
        "error[config_parse]: Could not parse configuration TOML: "
        "Expected ']]' at the end of an array declaration\n"
        "  ╭─▶ .opentide/configurations/platforms/sentinel.toml:4:10\n"
    )
    assert "\n✗ 1 configuration file does not parse\n" in result.stderr


def test_a_list_for_a_rule_is_framed_by_validate(repo: Path) -> None:
    """E2E 3: 'list indices must be integers or slices, not str'."""
    (repo / _RULE).write_text("- name: one\n- name: two\n", encoding="utf-8")
    result = _invoke(repo, "validate", json_output=False)
    assert (
        "error[yaml_parse]: expected a mapping at the top of the file, found a list\n"
        "  ╭─▶ objects/rules/sentinel-kql-rule.yaml:1:1\n"
    ) in result.stdout


@pytest.mark.parametrize("body", ["- name: one\n", "just a string\n"])
def test_a_rule_that_is_not_a_mapping_stops_deploy_with_a_frame(repo: Path, body: str) -> None:
    (repo / _RULE).write_text(body, encoding="utf-8")
    result = _invoke(repo, *_DEPLOY)
    assert result.exit_code == 1, result.stdout + result.stderr
    payload = json.loads(result.stdout)
    assert payload["failure"]["code"] == "yaml_parse"
    (diagnostic,) = payload["diagnostics"]
    assert diagnostic["message"].startswith("expected a mapping at the top of the file")
    assert (diagnostic["path"], diagnostic["line"], diagnostic["column"]) == (
        _RULE.as_posix(),
        1,
        1,
    )
    assert "list indices" not in result.stdout + result.stderr


def test_info_counts_a_broken_file_without_also_logging_it(repo: Path) -> None:
    """D14: info printed an absolute-path 'Malformed object yaml' line as well."""
    (repo / _RULE).write_text("- name: one\n", encoding="utf-8")
    result = _invoke(repo, "info", json_output=False)
    assert result.exit_code == 0
    assert "Malformed object yaml" not in result.output
    assert "1 load error" in result.stdout


def test_a_generate_failure_never_shows_a_raw_event_slug(repo: Path) -> None:
    """D14: 'logged an error: uuid_does_not_exist_in_the_index_of_tide_objects (detail=…)'."""
    _edit(
        repo / _RULE,
        "detection_model: 00000000-0000-4000-8002-000000000001",
        "detection_model: 00000000-0000-4000-8002-00000000dead",
    )
    result = _invoke(repo, "generate", "exports")
    assert result.exit_code == 1
    message = json.loads(result.stdout)["message"]
    assert "00000000-0000-4000-8002-00000000dead does not exist in the catalogue" in message
    assert "uuid_does_not_exist" not in result.stdout + result.stderr


def test_a_rule_deploy_frames_is_not_also_a_log_line(repo: Path) -> None:
    """E2E 31c: deploy printed `error: Malformed object yaml` and then the frame."""
    (repo / _RULE).write_text("- just\n- a list\n", encoding="utf-8")
    result = _invoke(repo, *_DEPLOY, json_output=False)
    assert result.exit_code == 1, result.stdout + result.stderr
    assert "error[yaml_parse]: expected a mapping at the top of the file" in result.output
    assert "Malformed object yaml" not in result.output
    assert "malformed_object_yaml" not in result.output


def test_deploy_warns_once_about_an_object_file_it_could_not_read(repo: Path) -> None:
    """A malformed file deploy does not read is one warning, not a log line."""
    threats = repo / "objects" / "threats"
    threats.mkdir(parents=True, exist_ok=True)
    (threats / "broken.yaml").write_text("- just\n- a list\n", encoding="utf-8")
    result = _invoke(repo, *_DEPLOY, json_output=False)
    assert "Malformed object yaml" not in result.output
    assert (
        "warning: 1 object file could not be read: objects/threats/broken.yaml; "
        "opentide validate shows where"
    ) in " ".join(result.output.split())
