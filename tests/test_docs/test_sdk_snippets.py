"""Run the Python samples in ``docs/sdk/`` against the tide corpus.

Issue #298: models.md printed ``rule.metadata.schema  # "rule::1.0"``. On a
loaded rule that attribute was Pydantic's deprecated ``BaseModel.schema``
classmethod, so the documented line evaluated to a bound method and nothing
noticed: the golden runner reads shell fences only, never Python ones.

Only statements without side effects run — imports, and expressions or name
assignments that contain no call — so every attribute path a page prints is
resolved without deploying, writing files, or reaching a vendor API. A trailing
comment that opens with a literal (``# "rule::1.0"``, ``# ["T1059"]``) states
the value the line evaluates to, and has to match.
"""

from __future__ import annotations

import ast
import inspect
import io
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.docs_commands import DOCS, ROOT, _iter_fenced

SDK_PAGES = sorted((DOCS / "sdk").glob("*.md"))

#: Names the pages leave for the reader to fill in, bound to a corpus object.
PLACEHOLDERS: dict[str, Any] = {"uuid": CORPUS_RULE_UUIDS["sentinel"], "platform": "sentinel"}
#: Plugin identifiers a page invents to show registration; no repository has them.
INVENTED = frozenset({"acme"})
#: A documented value that elides part of itself illustrates a shape, not a value.
ELISIONS = ("…", "...")

_LITERAL = re.compile(r"""^("[^"]*"|'[^']*'|\[[^\]]*\]|-?\d+(?:\.\d+)?|True|False|None)(?=\s|$)""")
_UNDOCUMENTED = object()


@dataclass(frozen=True)
class Fence:
    page: str
    line: int
    source: str


def python_fences(page: Path) -> list[Fence]:
    """Every ``python`` fence in *page* with the page line of its first source line."""
    fences: list[Fence] = []
    lines: list[str] = []
    start = previous = -1
    for language, number, raw in _iter_fenced(page.read_text(encoding="utf-8")):
        if number != previous + 1:
            if lines:
                fences.append(Fence(page.relative_to(ROOT).as_posix(), start, "\n".join(lines)))
            lines, start = [], number
        previous = number
        if language == "python":
            lines.append(raw)
    if lines:
        fences.append(Fence(page.relative_to(ROOT).as_posix(), start, "\n".join(lines)))
    return fences


def documented_value(comment: str) -> object:
    """The literal a trailing comment opens with, or ``_UNDOCUMENTED``."""
    match = _LITERAL.match(comment.lstrip("#").strip())
    if match is None or any(marker in match.group(1) for marker in ELISIONS):
        return _UNDOCUMENTED
    return ast.literal_eval(match.group(1))


def _comments(source: str) -> dict[int, str]:
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    return {token.start[0]: token.string for token in tokens if token.type == tokenize.COMMENT}


def _bound_names(node: ast.stmt) -> set[str]:
    names = {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
    }
    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
        names.add(node.name)
    return names


def _is_inert(node: ast.stmt) -> bool:
    """Whether running *node* can only read: an import, or a call-free read or name binding."""
    if isinstance(node, ast.Import | ast.ImportFrom):
        return True
    if isinstance(node, ast.Assign):
        if not all(isinstance(target, ast.Name) for target in node.targets):
            return False
    elif not isinstance(node, ast.Expr):
        return False
    return not any(isinstance(child, ast.Call | ast.Await | ast.Lambda) for child in ast.walk(node))


def _mentions_invented(node: ast.stmt) -> bool:
    return any(
        isinstance(child, ast.Constant) and child.value in INVENTED for child in ast.walk(node)
    )


@dataclass
class PageReport:
    checked: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def check_page(fences: list[Fence], namespace: dict[str, Any]) -> PageReport:
    """Run the inert statements of *fences* in order, sharing one namespace per page."""
    report = PageReport()
    unbound: set[str] = set()
    for fence in fences:
        try:
            tree = ast.parse(fence.source)
        except SyntaxError:
            # Signature listings (`rule.validate() -> ValidationResult`) are not code.
            continue
        comments = _comments(fence.source)
        for node in tree.body:
            where = f"{fence.page}:{fence.line + node.lineno - 1}"
            text = ast.get_source_segment(fence.source, node) or ""
            if not _is_inert(node) or _mentions_invented(node):
                unbound |= _bound_names(node)
                continue
            try:
                if isinstance(node, ast.Assign):
                    value = eval(compile(ast.Expression(node.value), where, "eval"), namespace)
                    namespace.update(dict.fromkeys(_bound_names(node), value))
                elif isinstance(node, ast.Expr):
                    value = eval(compile(ast.Expression(node.value), where, "eval"), namespace)
                else:
                    exec(compile(ast.Module([node], []), where, "exec"), namespace)
                    report.checked.append(f"{where}: {text}")
                    continue
            except NameError as exc:
                if exc.name in unbound:
                    unbound |= _bound_names(node)
                    continue
                report.problems.append(f"{where}: {text}\n    raised {exc!r}")
                continue
            except Exception as exc:
                report.problems.append(f"{where}: {text}\n    raised {exc!r}")
                continue
            unbound -= _bound_names(node)
            report.checked.append(f"{where}: {text}")
            if inspect.isroutine(value):
                report.problems.append(
                    f"{where}: {text}\n    is {value!r}, a method the reader would print"
                )
                continue
            documented = documented_value(comments.get(node.end_lineno or node.lineno, ""))
            if documented is not _UNDOCUMENTED and value != documented:
                report.problems.append(
                    f"{where}: {text}\n    documented {documented!r}, evaluates to {value!r}"
                )
    return report


@pytest.fixture
def sdk_namespace(tide_corpus_repo: Path) -> Iterator[dict[str, Any]]:
    from opentide import OpenTide

    OpenTide.initialise()
    yield {"OpenTide": OpenTide, **PLACEHOLDERS}


# --------------------------------------------------------------------------
# The documented samples
# --------------------------------------------------------------------------


@pytest.mark.parametrize("page", SDK_PAGES, ids=lambda page: page.name)
def test_sdk_samples_resolve_to_their_documented_values(
    page: Path, sdk_namespace: dict[str, Any]
) -> None:
    report = check_page(python_fences(page), sdk_namespace)
    assert not report.problems, "\n".join(report.problems)


def test_every_models_page_attribute_read_is_checked(sdk_namespace: dict[str, Any]) -> None:
    """Guard the filter above: the lines that motivated it must be among those it runs."""
    report = check_page(python_fences(DOCS / "sdk" / "models.md"), sdk_namespace)
    checked = {entry.split(": ", 1)[1] for entry in report.checked}
    for line in (
        "rule.metadata.schema",
        "rule.metadata.schema_id",
        "rule.configurations.sentinel.query",
        "threat.threat.att_ck",
        "[s.name for s in obj.objective.signals]",
        "DetectionRule.__schema_identifier__",
    ):
        assert line in checked, f"{line!r} was not evaluated:\n" + "\n".join(sorted(checked))


def test_the_sdk_pages_yield_enough_samples(sdk_namespace: dict[str, Any]) -> None:
    """A filter that silently skips everything would make the page test pass."""
    checked = [
        line
        for page in SDK_PAGES
        for line in check_page(python_fences(page), dict(sdk_namespace)).checked
    ]
    assert len(checked) > 40, checked


# --------------------------------------------------------------------------
# Negative controls
# --------------------------------------------------------------------------


def _fence(source: str) -> list[Fence]:
    return [Fence("docs/sdk/example.md", 1, source)]


def test_an_attribute_that_is_a_method_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = "rule = OpenTide.Rules[uuid]\nrule.metadata.model_dump"
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "a method the reader would print" in problem


def test_a_documented_value_that_differs_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = 'rule = OpenTide.Rules[uuid]\nrule.name  # "Some Other Rule"'
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "documented 'Some Other Rule'" in problem


def test_a_missing_attribute_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = "rule = OpenTide.Rules[uuid]\nrule.metadata.schema_version"
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "AttributeError" in problem


def test_calls_and_names_they_bind_are_skipped(sdk_namespace: dict[str, Any]) -> None:
    source = 'result = rule.deploy("sentinel")\nresult.dry_run\nOpenTide.debug'
    report = check_page(_fence(source), sdk_namespace)
    assert report.problems == []
    assert [line.split(": ", 1)[1] for line in report.checked] == ["OpenTide.debug"]


@pytest.mark.parametrize(
    ("comment", "expected"),
    [
        ('# "rule::1.0"', "rule::1.0"),
        ('# ["T1059"]  (YAML `att&ck`, aliased att_ck)', ["T1059"]),
        ('# ["…8001…"]  (threat UUIDs)', _UNDOCUMENTED),
        ("# objective UUID", _UNDOCUMENTED),
        ('# vocabulary list, e.g. ["Windows::Desktop"]', _UNDOCUMENTED),
        ("", _UNDOCUMENTED),
    ],
)
def test_only_a_leading_literal_is_a_documented_value(comment: str, expected: object) -> None:
    assert documented_value(comment) == expected
