"""The GitLab validate job merges its Code Quality reports into one valid file."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from opentide.ci.codequality import main, merge_issues


def _issue(fingerprint: str, check: str = "schema_validation") -> dict[str, object]:
    return {
        "type": "issue",
        "check_name": check,
        "description": "message",
        "severity": "major",
        "fingerprint": fingerprint,
        "location": {"path": "objects/rules/a.yaml", "lines": {"begin": 1}},
    }


def _write(path: Path, document: object) -> Path:
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def _merged(output: Path) -> list[dict[str, object]]:
    document = json.loads(output.read_text(encoding="utf-8"))
    assert isinstance(document, list)
    return document


def test_merges_both_reports_in_order(tmp_path: Path) -> None:
    validate = _write(tmp_path / "validate.codequality.json", [_issue("a")])
    lint = _write(tmp_path / "lint.codequality.json", [_issue("b", "filename_style")])
    output = tmp_path / "codequality.json"
    assert main(["--output", str(output), str(validate), str(lint)]) == 0
    assert [issue["fingerprint"] for issue in _merged(output)] == ["a", "b"]


def test_a_fingerprint_is_kept_once(tmp_path: Path) -> None:
    first = _write(tmp_path / "one.json", [_issue("a"), _issue("b")])
    second = _write(tmp_path / "two.json", [_issue("b"), _issue("c")])
    assert [issue["fingerprint"] for issue in merge_issues([first, second])] == ["a", "b", "c"]


@pytest.mark.parametrize(
    ("content", "why"),
    [
        (None, "does not exist"),
        ("", "is empty"),
        ('[{"type": "issue", "finger', "is not JSON"),
        ('{"issues": []}', "is not a Code Quality report"),
        (b"\xff\xfe[]", "cannot be read"),
    ],
    ids=["missing", "empty", "truncated", "object", "not-utf8"],
)
def test_a_broken_input_still_gives_a_valid_report(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str | bytes | None, why: str
) -> None:
    """``validate`` failed or crashed before ``lint`` ran: the merge request keeps its findings."""
    validate = _write(tmp_path / "validate.codequality.json", [_issue("a")])
    lint = tmp_path / "lint.codequality.json"
    if isinstance(content, bytes):
        lint.write_bytes(content)
    elif content is not None:
        lint.write_text(content, encoding="utf-8")
    output = tmp_path / "reports" / "codequality.json"
    assert main(["--output", str(output), str(validate), str(lint)]) == 0
    assert [issue["fingerprint"] for issue in _merged(output)] == ["a"]
    assert why in capsys.readouterr().err


def test_no_readable_input_writes_an_empty_report(tmp_path: Path) -> None:
    output = tmp_path / "codequality.json"
    assert main(["--output", str(output), str(tmp_path / "missing.json")]) == 0
    assert _merged(output) == []


def test_items_that_are_not_issues_are_dropped(tmp_path: Path) -> None:
    report = _write(tmp_path / "r.json", [_issue("a"), "text", 3, None])
    assert merge_issues([report]) == [_issue("a")]


def test_the_merge_leaves_no_temporary_file(tmp_path: Path) -> None:
    output = tmp_path / "codequality.json"
    output.write_text("stale", encoding="utf-8")
    assert main(["--output", str(output), str(_write(tmp_path / "v.json", []))]) == 0
    assert sorted(path.name for path in tmp_path.iterdir()) == ["codequality.json", "v.json"]
    assert _merged(output) == []


def test_runs_as_a_module(tmp_path: Path) -> None:
    """The generated ``after_script`` runs ``python -m opentide.ci.codequality``."""
    validate = _write(tmp_path / "validate.codequality.json", [_issue("a")])
    output = tmp_path / "codequality.json"
    env = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
    result = subprocess.run(
        [sys.executable, "-m", "opentide.ci.codequality", "--output", str(output), str(validate)],
        capture_output=True,
        text=True,
        check=False,
        env=env,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert [issue["fingerprint"] for issue in _merged(output)] == ["a"]
