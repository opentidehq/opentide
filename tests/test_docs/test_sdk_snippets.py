"""Run the Python samples in ``docs/sdk/`` against the tide corpus.

Issue #298: models.md printed ``rule.metadata.schema  # "rule::1.0"``. On a
loaded rule that attribute was Pydantic's deprecated ``BaseModel.schema``
classmethod, so the documented line evaluated to a bound method and nothing
noticed: the golden runner reads shell fences only, never Python ones.

The pages of the SDK's ``Workspace`` (UC-5.2, #837: ``RUN_PAGES``) run whole,
every statement of every fence in order, from a copy of the tide corpus: nothing
they do leaves it or reaches a vendor API. Their tenant operations (UC-5.2b) reach
the tenant the Workspace page's TOML fence configures, which the run points at the
SentinelOne stand-in of ``tests/cassettes/`` on loopback. On the other pages, which document
the models and the platform plugins, only statements without side
effects run — imports, and expressions or name assignments that contain no
call — so every attribute path a page prints is resolved without deploying,
writing files, or reaching a vendor API. A trailing comment that opens with a
literal (``# "rule::1.0"``, ``# ["T1059"]``) states the value the line evaluates
to, and has to match.
"""

from __future__ import annotations

import ast
import inspect
import io
import os
import re
import tokenize
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from tests.corpus_support import CORPUS_RULE_UUIDS
from tests.stand_in_support import S1_TOKEN, sentinel_one

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"

#: CommonMark fence: three or more backticks or tildes, then an info string
#: whose first word is the language (Fumadocs adds ``title="…"`` after it).
_FENCE = re.compile(r"^(?P<marker>`{3,}|~{3,})\s*(?P<info>.*)$")


def _iter_fenced(text: str) -> Iterator[tuple[str, int, str]]:
    """Yield ``(language, line_number, raw_line)`` for every line inside a fence.

    A fence closes only on the same character repeated at least as many times
    with no info string, as CommonMark has it.
    """
    marker: str | None = None
    language = ""
    for number, raw in enumerate(text.splitlines(), start=1):
        fence = _FENCE.match(raw.strip())
        if marker is None:
            if fence is not None:
                marker = fence["marker"]
                info = fence["info"].strip()
                language = info.split()[0].lower() if info else ""
            continue
        if (
            fence is not None
            and fence["marker"][0] == marker[0]
            and len(fence["marker"]) >= len(marker)
            and not fence["info"].strip()
        ):
            marker = None
            continue
        yield language, number, raw


SDK_PAGES = sorted((DOCS / "sdk").glob("*.md"))
#: The pages whose Python fences run whole, calls included.
RUN_PAGES = frozenset({"index.md", "workspace.md", "migration.md"})
INERT_PAGES = [page for page in SDK_PAGES if page.name not in RUN_PAGES]

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


def check_page(
    fences: list[Fence], namespace: dict[str, Any], *, run_all: bool = False
) -> PageReport:
    """Run the inert statements of *fences* (every statement with *run_all*) in order,
    sharing one namespace per page."""
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
            if not run_all and (not _is_inert(node) or _mentions_invented(node)):
                unbound |= _bound_names(node)
                continue
            try:
                if isinstance(node, ast.Assign) and all(
                    isinstance(t, ast.Name) for t in node.targets
                ):
                    value = eval(compile(ast.Expression(node.value), where, "eval"), namespace)
                    namespace.update(dict.fromkeys(_bound_names(node), value))
                elif isinstance(node, ast.Expr):
                    value = eval(compile(ast.Expression(node.value), where, "eval"), namespace)
                else:
                    exec(compile(ast.Module([node], []), where, "exec"), namespace)
                    report.checked.append(f"{where}: {text}")
                    continue
            except NameError as exc:
                if not run_all and exc.name in unbound:
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
    """The objects the pages read from: the corpus's Sentinel rule, its first
    objective and threat, as the Rust models, read as models.md says."""
    import yaml

    from opentide.models import DetectionObjective, DetectionRule, DetectionRule_v1_1, ThreatVector

    classes: dict[str, Any] = {
        "rule::1.0": DetectionRule,
        "rule::1.1": DetectionRule_v1_1,
        "objective::1.0": DetectionObjective,
        "threat::1.0": ThreatVector,
    }
    by_uuid: dict[str, Any] = {}
    for path in sorted((tide_corpus_repo / "Objects").rglob("*.yaml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
        metadata = document.get("metadata") if isinstance(document, dict) else None
        if isinstance(metadata, dict) and metadata.get("schema") in classes:
            by_uuid.setdefault(
                str(metadata["uuid"]), classes[metadata["schema"]].model_validate(document)
            )
    yield {
        "rule": by_uuid[CORPUS_RULE_UUIDS["sentinel"]],
        "obj": by_uuid["00000000-0000-4000-8002-000000000001"],
        "threat": by_uuid["00000000-0000-4000-8001-000000000001"],
        **PLACEHOLDERS,
    }


# --------------------------------------------------------------------------
# The documented samples
# --------------------------------------------------------------------------


def _toml_fence(page: Path) -> str:
    """The lines of *page*'s ``toml`` fences, in order."""
    text = page.read_text(encoding="utf-8")
    toml = [raw for language, _, raw in _iter_fenced(text) if language == "toml"]
    assert toml, f"{page.name} has no toml fence"
    return "\n".join(toml) + "\n"


@pytest.fixture
def stand_in_tenant(tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """The tenant the Workspace page configures, as its TOML fence writes it, on the
    SentinelOne stand-in; no proxy of the process applies."""
    config = tide_corpus_repo / ".opentide" / "configurations" / "platforms" / "sentinel_one.toml"
    page = DOCS / "sdk" / "workspace.md"
    config.write_text(
        config.read_text(encoding="utf-8") + "\n" + _toml_fence(page), encoding="utf-8"
    )
    for name in list(os.environ):
        if name.lower().endswith("_proxy"):
            monkeypatch.delenv(name)
    with sentinel_one() as url:
        monkeypatch.setenv("S1_URL", url)
        monkeypatch.setenv("S1_API_TOKEN", S1_TOKEN)
        yield


@pytest.mark.parametrize("page", sorted(RUN_PAGES))
@pytest.mark.usefixtures("stand_in_tenant")
def test_the_workspace_pages_run_whole(
    page: str, tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tide_corpus_repo)
    fences = python_fences(DOCS / "sdk" / page)
    report = check_page(fences, {**PLACEHOLDERS}, run_all=True)
    assert not report.problems, "\n".join(report.problems)
    statements = sum(len(ast.parse(fence.source).body) for fence in fences)
    assert len(report.checked) == statements, report.checked


def test_a_failing_statement_on_a_run_page_is_reported(
    tide_corpus_repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tide_corpus_repo)
    source = "\n".join(
        [
            "from opentide import Workspace",
            'ws = Workspace.open(".")',
            'ws.coverage("T1059")["count"]  # 0',
        ]
    )
    (problem,) = check_page(_fence(source), {}, run_all=True).problems
    assert "documented 0" in problem


@pytest.mark.parametrize("page", INERT_PAGES, ids=lambda page: page.name)
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
        "threat.threat.mitre_attack",
        "[s.name for s in obj.objective.signals]",
        "DetectionRule.__schema_identifier__",
    ):
        assert line in checked, f"{line!r} was not evaluated:\n" + "\n".join(sorted(checked))


def test_the_sdk_pages_yield_enough_samples(sdk_namespace: dict[str, Any]) -> None:
    """A filter that silently skips everything would make the page test pass."""
    checked = [
        line
        for page in INERT_PAGES
        for line in check_page(python_fences(page), dict(sdk_namespace)).checked
    ]
    # 35 since the registry, validation and documentation pages went (UC-6.2).
    assert len(checked) >= 35, checked


# --------------------------------------------------------------------------
# Negative controls
# --------------------------------------------------------------------------


def _fence(source: str) -> list[Fence]:
    return [Fence("docs/sdk/example.md", 1, source)]


def test_an_attribute_that_is_a_method_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = "rule.metadata.model_dump"
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "a method the reader would print" in problem


def test_a_documented_value_that_differs_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = 'rule.name  # "Some Other Rule"'
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "documented 'Some Other Rule'" in problem


def test_a_missing_attribute_is_reported(sdk_namespace: dict[str, Any]) -> None:
    source = "rule.metadata.schema_version"
    (problem,) = check_page(_fence(source), sdk_namespace).problems
    assert "AttributeError" in problem


def test_calls_and_names_they_bind_are_skipped(sdk_namespace: dict[str, Any]) -> None:
    source = "result = ws.validate()\nresult.failed\nrule.name"
    report = check_page(_fence(source), sdk_namespace)
    assert report.problems == []
    assert [line.split(": ", 1)[1] for line in report.checked] == ["rule.name"]


@pytest.mark.parametrize(
    ("comment", "expected"),
    [
        ('# "rule::1.0"', "rule::1.0"),
        ('# ["T1059"]  (YAML `mitre_attack`)', ["T1059"]),
        ('# ["…8001…"]  (threat UUIDs)', _UNDOCUMENTED),
        ("# objective UUID", _UNDOCUMENTED),
        ('# vocabulary list, e.g. ["OS::Windows::Desktop"]', _UNDOCUMENTED),
        ("", _UNDOCUMENTED),
    ],
)
def test_only_a_leading_literal_is_a_documented_value(comment: str, expected: object) -> None:
    assert documented_value(comment) == expected
