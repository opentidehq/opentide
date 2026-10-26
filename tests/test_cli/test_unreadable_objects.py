"""Object files a person can save by mistake are findings, never ``error[internal]``.

Found by the post-merge end-to-end run: an empty file, an impossible date, a
list where a reference belongs and a file saved in Latin-1 each crashed
``validate`` (and ``lint``, ``info``, ``deploy --dry-run``, ``share preview``).
``CliRunner`` lets an unhandled exception through, so a crash fails these tests.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from typer.testing import Result

from opentide.core.io import parse_yaml


def _rule(repo: Path) -> Path:
    return sorted((repo / "objects" / "rules").rglob("*.yaml"))[0]


def _codes(result: Result) -> list[str]:
    payload = json.loads(result.stdout)
    return [issue["code"] for issue in payload["report"]["issues"]]


@pytest.mark.parametrize("text", ["", "# a new rule, not written yet\n", "---\n"])
def test_parse_yaml_reads_an_empty_document_as_none(text: str) -> None:
    assert parse_yaml(text) is None


def test_parse_yaml_reports_an_impossible_date_at_the_value() -> None:
    with pytest.raises(yaml.YAMLError) as caught:
        parse_yaml("name: x\ncreated: 2026-13-45\n")
    error = caught.value
    assert isinstance(error, yaml.MarkedYAMLError)
    assert error.problem_mark is not None
    assert (error.problem_mark.line, error.problem_mark.column) == (1, 9)
    assert "'2026-13-45' is not a valid date" in str(error.problem)


def _write(path: Path, content: str | bytes) -> None:
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8")


@pytest.mark.parametrize(
    ("label", "content", "expected"),
    [
        ("empty", "", "found an empty file"),
        ("comments only", "# draft\n", "found an empty file"),
        ("latin-1", b"name: caf\xe9\n", "not UTF-8 text (byte 0xe9 at offset 9)"),
    ],
)
@pytest.mark.parametrize("command", [("validate",), ("info",), ("lint",)])
def test_an_unreadable_object_file_is_reported_not_a_crash(
    invoke_cli: Callable[..., Result],
    tide_corpus_repo: Path,
    label: str,
    content: str | bytes,
    expected: str,
    command: tuple[str, ...],
) -> None:
    _write(tide_corpus_repo / "objects" / "rules" / "draft.yaml", content)
    result = invoke_cli(*command)
    assert result.exception is None or isinstance(result.exception, SystemExit), label
    payload = json.loads(result.stdout)
    if command == ("info",):
        # info counts the files it could not load; validate says why.
        assert payload["parse_error_count"] == 1, label
    else:
        assert expected in json.dumps(payload), (label, command)


def test_an_impossible_date_is_a_yaml_parse_finding(
    invoke_cli: Callable[..., Result], tide_corpus_repo: Path
) -> None:
    rule = _rule(tide_corpus_repo)
    text = rule.read_text(encoding="utf-8")
    rule.write_text(text.replace("modified:", "modified: 2026-13-45\n  x_modified:", 1))
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout
    assert "yaml_parse" in _codes(result)
    assert "is not a valid date" in result.stdout


def test_a_list_where_detection_model_belongs_is_a_schema_finding(
    invoke_cli: Callable[..., Result], tide_corpus_repo: Path
) -> None:
    rule = _rule(tide_corpus_repo)
    text = rule.read_text(encoding="utf-8")
    assert "detection_model: " in text
    rule.write_text(text.replace("detection_model: ", "detection_model:\n  - ", 1))
    result = invoke_cli("validate")
    assert result.exit_code == 1, result.stdout
    assert "schema_validation" in _codes(result)
