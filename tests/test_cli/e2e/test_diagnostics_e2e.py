"""CLI E2E: validate, lint and info print code frames and counted outcome lines.

The three cases of #620 run on the tutorial workspace: a dangling reference, a
vocabulary typo and a YAML syntax error. JSON keeps every key it had and gains
the diagnostic fields. Output is read with ANSI stripped, since CI forces colour.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.corpus_support import clear_runtime_caches
from tests.test_cli.e2e.helpers import write_tutorial_objects
from typer.testing import CliRunner, Result

from opentide.cli import app
from opentide.cli.enums import DetectionPlatform
from opentide.cli.services.setup.repo import RepoSetupOptions, run_repo_setup

pytestmark = pytest.mark.cli_e2e

_LEAKY_ENV = (
    "OPENTIDE_REPO_ROOT",
    "OPENTIDE_TIDE_WORKSPACE",
    "OPENTIDE_OUTPUT",
    "DEPLOYMENT_PLAN",
    "CI",
    "GITHUB_ACTIONS",
    "GITLAB_CI",
    "TF_BUILD",
    "NO_COLOR",
    "FORCE_COLOR",
    "AI_AGENT",
    "CLAUDECODE",
)
_RULE_FILE = Path("objects/rules/sentinel-kql-rule.yaml")
_OBJECTIVE = "00000000-0000-4000-8002-000000000001"
_DANGLING = "00000000-0000-4000-8002-DEADBEEF0000"
_ANSI = re.compile(r"\x1b\[[0-9;]*m|\x1b\]8;[^\x1b]*\x1b\\")

#: Keys every validation issue had before diagnostics.
_ISSUE_KEYS = (
    "code",
    "severity",
    "object_uuid",
    "object_type",
    "file_path",
    "yaml_line",
    "field_path",
    "message",
    "suggestion",
    "context",
)
_DIAGNOSTIC_KEYS = ("path", "line", "column", "end_column", "help", "fix", "explain")


@pytest.fixture(scope="module")
def _pristine(tmp_path_factory: pytest.TempPathFactory) -> Path:
    repo = tmp_path_factory.mktemp("diagnostics") / "tutorial"
    run_repo_setup(
        RepoSetupOptions(
            path=repo,
            name="Tutorial Detections",
            org="Example Corp",
            platforms=[DetectionPlatform.sentinel],
            yes=True,
        )
    )
    write_tutorial_objects(repo)
    result = CliRunner().invoke(
        app, ["--repo", str(repo), "--json", "generate"], env=dict.fromkeys(_LEAKY_ENV)
    )
    assert result.exit_code == 0, result.output
    return repo


@pytest.fixture
def tutorial(_pristine: Path, tmp_path: Path) -> Iterator[Path]:
    repo = tmp_path / "tutorial"
    shutil.copytree(_pristine, repo)
    yield repo
    clear_runtime_caches()


def _edit_rule(repo: Path, old: str, new: str) -> None:
    path = repo / _RULE_FILE
    text = path.read_text(encoding="utf-8")
    assert old in text
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def _run(repo: Path, *argv: str, json_output: bool = False) -> Result:
    clear_runtime_caches()
    env = dict.fromkeys(_LEAKY_ENV) | {
        "OPENTIDE_REPO_ROOT": str(repo),
        "OPENTIDE_TIDE_WORKSPACE": str(repo),
    }
    head = ["--repo", str(repo)] + (["--json"] if json_output else [])
    return CliRunner().invoke(app, [*head, *argv], env=env)


def _text(result: Result) -> str:
    return _ANSI.sub("", result.output)


def _issues(result: Result) -> list[dict]:
    return json.loads(result.stdout)["report"]["issues"]


def test_a_dangling_reference_is_one_framed_finding(tutorial: Path) -> None:
    _edit_rule(tutorial, f"detection_model: {_OBJECTIVE}", f"detection_model: {_DANGLING}")
    result = _run(tutorial, "validate")
    assert result.exit_code == 1, result.output
    text = _text(result)
    assert (
        "error[invalid_ref]: Unknown objective or signal reference "
        f"'{_DANGLING}'\n"
        "   ╭─▶ objects/rules/sentinel-kql-rule.yaml:17:18\n"
        "   │\n"
        "16 │ techniques: [T1059]\n"
        f"17 │ detection_model: {_DANGLING}   # the objective from step 4\n"
        "   │                  " + "━" * 36 + " no object has this id\n"
        "   │\n"
        "   ╰─ help: opentide info objectives lists the ones that exist\n"
    ) in text
    assert "vocab_unknown" not in text
    assert re.search(r"✗ 1 error in 1 file · 3 objects checked · \d+\.\ds\n", text)

    payload = json.loads(_run(tutorial, "validate", json_output=True).stdout)
    (issue,) = payload["report"]["issues"]
    assert list(issue) == [*_ISSUE_KEYS, *_DIAGNOSTIC_KEYS]
    assert issue["yaml_line"] == 16
    assert issue["context"] == {"value": _DANGLING}
    assert {key: issue[key] for key in _DIAGNOSTIC_KEYS} == {
        "path": "objects/rules/sentinel-kql-rule.yaml",
        "line": 17,
        "column": 18,
        "end_column": 54,
        "help": "opentide info objectives lists the ones that exist",
        "fix": None,
        "explain": "opentide explain invalid_ref",
    }
    assert payload["message"] == "Validation failed"
    assert payload["summary"] == {
        "objects": 3,
        "errors": 1,
        "warnings": 0,
        "files": 1,
        "warning_files": 0,
    }
    assert payload["failure"]["code"] == "issues_found"


def test_a_vocabulary_typo_carries_a_fix_for_review(tutorial: Path) -> None:
    _edit_rule(tutorial, "  tlp: clear\n", "  tlp: clearr\n")
    text = _text(_run(tutorial, "validate"))
    assert (
        "error[vocab_unknown]: 'clearr' is not a TLP value\n"
        "  ╭─▶ objects/rules/sentinel-kql-rule.yaml:8:8\n"
        "  │\n"
        "7 │   modified: 2026-01-02\n"
        "8 │   tlp: clearr\n"
        "  │        ━━━━━━ not in tlp::1.0\n"
        "  │\n"
        "  ╰─ help: did you mean 'clear'?\n"
    ) in text
    (issue,) = _issues(_run(tutorial, "validate", json_output=True))
    assert issue["suggestion"] == "clear"
    assert issue["fix"] == {
        "safe": False,
        "edits": [
            {"line": 8, "column": 8, "end_line": 8, "end_column": 14, "replacement": "clear"}
        ],
    }


def test_a_yaml_error_is_reported_once_with_its_position(tutorial: Path) -> None:
    _edit_rule(tutorial, "  tlp: clear\n", "  tlp: [clear\n")
    result = _run(tutorial, "validate")
    assert result.exit_code == 1
    text = _text(result)
    assert "<unicode string>" not in text
    assert text.count("sentinel-kql-rule.yaml") == 1, text
    assert (
        "error[yaml_parse]: Could not parse object YAML: did not find expected ',' or ']'\n"
        "  ╭─▶ objects/rules/sentinel-kql-rule.yaml:9:9\n"
    ) in text
    assert "╰─ note: while parsing a flow sequence that starts at line 8, column 8\n" in text

    (issue,) = _issues(_run(tutorial, "validate", json_output=True))
    assert issue["message"] == (
        "Could not parse object YAML: did not find expected ',' or ']' at line 9, column 9 "
        "(while parsing a flow sequence that starts at line 8, column 8)"
    )
    assert (issue["line"], issue["column"], issue["end_column"]) == (9, 9, 10)


def test_a_clean_workspace_counts_what_it_checked(tutorial: Path) -> None:
    assert re.fullmatch(r"✓ 3 objects valid · \d+\.\ds\n", _text(_run(tutorial, "validate")))
    assert _text(_run(tutorial, "lint")) == "✓ 3 files clean\n"
    info = _text(_run(tutorial, "info"))
    assert info.endswith("✓ 1 rule · 1 threat · 1 objective · 0 load errors\n")


def test_info_strict_says_why_it_fails(tutorial: Path) -> None:
    _edit_rule(tutorial, "  tlp: clear\n", "  tlp: [clear\n")
    result = _run(tutorial, "info", "--strict")
    assert result.exit_code == 1
    text = _text(result)
    assert "✗ 0 rules · 1 threat · 1 objective · 1 load error\n" in text
    assert "→ opentide validate · show where each object failed to load\n" in text
    payload = json.loads(_run(tutorial, "info", "--strict", json_output=True).stdout)
    assert payload["failure"]["code"] == "issues_found"
    assert payload["summary"] == {"rules": 0, "threats": 1, "objectives": 1, "load_errors": 1}
    relaxed = _run(tutorial, "info")
    assert relaxed.exit_code == 0
    assert "! 0 rules · 1 threat · 1 objective · 1 load error\n" in _text(relaxed)


def test_a_check_that_does_not_report_unreadable_files_still_logs_them(tutorial: Path) -> None:
    """Only the schema check turns a broken file into a finding; others must not hide it."""
    broken = tutorial / "objects" / "rules" / "broken.yaml"
    broken.write_text("metadata: [oops\n", encoding="utf-8")
    narrow = _text(_run(tutorial, "validate", "--check", "uuid-format"))
    assert "objects/rules/broken.yaml" in narrow or str(broken) in narrow, narrow
    assert "Malformed object yaml" in narrow
    full = _text(_run(tutorial, "validate"))
    assert "Malformed object yaml" not in full, "the schema check reports it once, as a frame"
    assert "error[yaml_parse]" in full


def test_an_ascii_stream_gets_ascii_separators(tutorial: Path) -> None:
    clear_runtime_caches()
    env = dict.fromkeys(_LEAKY_ENV) | {
        "OPENTIDE_REPO_ROOT": str(tutorial),
        "OPENTIDE_TIDE_WORKSPACE": str(tutorial),
    }
    result = CliRunner(charset="ascii").invoke(app, ["--repo", str(tutorial), "lint"], env=env)
    assert result.exit_code == 0, result.output
    assert result.output == "ok 3 files clean\n"


def test_a_cp1252_pipe_prints_a_frame_with_an_emoji_in_the_file(tutorial: Path) -> None:
    """Windows pipes default to cp1252: a source line it cannot write must not crash."""
    _edit_rule(tutorial, "  tlp: clear\n", "  tlp: clearr  # \U0001f525 hot\n")
    env = {key: value for key, value in os.environ.items() if key not in _LEAKY_ENV}
    env |= {
        "PYTHONIOENCODING": "cp1252",
        "OPENTIDE_REPO_ROOT": str(tutorial),
        "OPENTIDE_TIDE_WORKSPACE": str(tutorial),
    }
    env.pop("PYTHONUTF8", None)
    result = subprocess.run(
        [sys.executable, "-m", "opentide", "--repo", str(tutorial), "validate"],
        capture_output=True,
        env=env,
        check=False,
    )
    stdout = result.stdout.decode("cp1252")
    stderr = result.stderr.decode("cp1252", errors="replace")
    assert result.returncode == 1, stdout + stderr
    assert "Traceback" not in stderr
    assert "8 |   tlp: clearr  # ? hot" in stdout
    assert "  |        ^^^^^^ not in tlp::1.0" in stdout
