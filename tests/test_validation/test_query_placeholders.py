"""A query ``opentide new`` left as its ``...`` stand-in is lint's finding, not the engine's."""

from __future__ import annotations

from pathlib import Path

import pytest

from opentide.analysis import Finding, QueryCheck
from opentide.cli.services.lint import _in_placeholder
from opentide.validation.queries import is_placeholder_query, is_stand_in

MARK = "# opentide:placeholder"


def _check(path: Path, line: int, column: int) -> QueryCheck:
    return QueryCheck(
        file_path=path,
        platform="splunk",
        language="spl",
        field_path=("configurations", "splunk", "query"),
        line=line,
        column=column,
    )


@pytest.mark.parametrize(
    ("text", "line", "column", "expected"),
    [
        (f"    query: |  {MARK}\n      ...\n", 2, 7, True),
        (f"    query: ...  {MARK}\n", 1, 12, True),
        # Written, but the marker was not deleted: checked.
        (f"    query: |  {MARK}\n      index=main | statz count\n", 2, 7, False),
        # The stand-in without a marker is someone's query: checked.
        ("    query: |\n      ...\n", 2, 7, False),
    ],
)
def test_a_query_is_a_placeholder_only_when_marked_and_still_the_stand_in(
    tmp_path: Path, text: str, line: int, column: int, expected: bool
) -> None:
    path = tmp_path / "rule.yaml"
    path.write_text(text, encoding="utf-8")
    assert is_placeholder_query(_check(path, line, column), {}) is expected


def test_an_unreadable_file_has_no_placeholder(tmp_path: Path) -> None:
    assert is_placeholder_query(_check(tmp_path / "gone.yaml", 2, 7), {}) is False


def test_the_stand_in_is_three_dots_and_nothing_else() -> None:
    assert is_stand_in(f"...  {MARK}")
    assert is_stand_in("...")
    assert not is_stand_in("... | stats count")


@pytest.mark.parametrize(
    ("lines", "line", "expected"),
    [
        ([f"    query: |  {MARK}", "      ..."], 2, True),
        ([f"    query: ...  {MARK}"], 1, True),
        ([f"    query: |  {MARK}", "      index=* | stats count"], 2, False),
        (["    query: |", "      ..."], 2, False),
    ],
)
def test_lint_leaves_a_placeholder_query_to_the_placeholders_check(
    lines: list[str], line: int, expected: bool
) -> None:
    marked = {number + 1 for number, text in enumerate(lines) if MARK in text}
    finding = Finding(
        code="spl_parse_error",
        severity="warning",
        message="m",
        line=line,
        column=7,
        end_line=line,
        end_column=8,
    )
    assert _in_placeholder(finding, lines, marked) is expected
