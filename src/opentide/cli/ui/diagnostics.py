"""The shape every finding takes: a code, a severity, a message and a place in a file.

A :class:`Diagnostic` is built from a validation issue or a lint finding by
an adapter here, rendered as a code frame by :mod:`opentide.cli.ui.codeframe`,
and merged into the JSON entry it came from by :func:`annotate`, which adds
keys and never changes one. See "Diagnostics" in
``docs/internal/cli-experience.md``.

Positions are 1-based. ``end_column`` is the column just after the last
character, so ``end_column - column`` is the length of the span, and a fix
edit replaces the text from ``column`` up to ``end_column``.

Kept free of Rich and Typer. The YAML parsers load only when a position is
looked up.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from opentide.core.io import YamlProblem
    from opentide.validation.issues import ValidationIssue

Severity = Literal["error", "warning", "note"]

#: Keys :func:`annotate` adds to a JSON finding. Keys the finding has keep their value.
DIAGNOSTIC_FIELDS = ("path", "line", "column", "end_column", "help", "fix", "explain")

#: Codes whose ``suggestion`` is a replacement value for the one at fault.
VALUE_SUGGESTION_CODES = frozenset({"vocab_unknown", "invalid_ref", "chaining_relation_unknown"})

#: A suggested value at least this similar to the one written is a typo fix,
#: safe to apply without reading it. Below it, a person or an agent decides.
SAFE_FIX_SIMILARITY = 0.8

#: Lint finding codes, by what the finding is about.
LINT_CODES = {
    "parse": "yaml_parse",
    "name": "name_missing",
    "filename": "filename_mismatch",
    "metadata": "metadata_recommended",
}


def explain_command(code: str) -> str:
    """``opentide explain <code>``: the page that says what *code* means."""
    return f"opentide explain {code}"


@dataclass(frozen=True)
class TextEdit:
    """Replace the text of *line* from *column* up to *end_column* with *replacement*."""

    line: int
    column: int
    end_column: int
    replacement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "column": self.column,
            "end_column": self.end_column,
            "replacement": self.replacement,
        }


@dataclass(frozen=True)
class Fix:
    """Edits that resolve a diagnostic. ``safe`` ones may be applied without review."""

    safe: bool
    edits: tuple[TextEdit, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"safe": self.safe, "edits": [edit.to_dict() for edit in self.edits]}


@dataclass(frozen=True)
class Diagnostic:
    """One finding, in the shape every renderer reads."""

    code: str
    severity: Severity
    message: str
    #: Workspace-relative, with ``/`` separators. ``None`` when no file is at fault.
    path: str | None = None
    #: Absolute; the renderer reads the source lines from it.
    file_path: Path | None = None
    line: int | None = None
    column: int | None = None
    end_column: int | None = None
    field_path: tuple[str, ...] = ()
    help: str | None = None
    fix: Fix | None = None
    #: A few words under the underline (``not in tlp::1.0``).
    label: str | None = None
    #: Further ``(label, text)`` lines, such as ``("expected", "…")``.
    notes: tuple[tuple[str, str], ...] = ()

    @property
    def explain(self) -> str:
        return explain_command(self.code)

    def fields(self) -> dict[str, Any]:
        """The values of :data:`DIAGNOSTIC_FIELDS`."""
        return {
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "end_column": self.end_column,
            "help": self.help,
            "fix": None if self.fix is None else self.fix.to_dict(),
            "explain": self.explain,
        }

    def to_dict(self) -> dict[str, Any]:
        """The whole diagnostic, for a surface that has no finding shape of its own."""
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "field_path": list(self.field_path),
            **self.fields(),
        }


def annotate(entry: MutableMapping[str, Any], diagnostic: Diagnostic) -> MutableMapping[str, Any]:
    """Add the diagnostic fields to a JSON finding, keeping every key it already has."""
    for key, value in diagnostic.fields().items():
        entry.setdefault(key, value)
    return entry


def relative_path(path: Path | str, base: Path | None) -> str:
    """*path* relative to *base* with ``/`` separators, or absolute when it is outside."""
    target = Path(path)
    if base is not None:
        for candidate, root in ((target, base), (_resolved(target), _resolved(base))):
            try:
                return candidate.relative_to(root).as_posix()
            except ValueError:
                continue
    return target.as_posix()


def _resolved(path: Path) -> Path:
    try:
        return path.resolve()
    except OSError:  # pragma: no cover - unresolvable path
        return path


# --------------------------------------------------------------------------
# Source positions
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Span:
    """Where a value sits: 1-based line, and the columns it covers."""

    line: int
    column: int
    end_column: int
    #: The text inside the span, unquoted.
    text: str = ""


@dataclass
class SourceFiles:
    """Reads each file once, for every diagnostic that points into it."""

    _lines: dict[Path, list[str] | None] = field(default_factory=dict)
    _documents: dict[Path, Any] = field(default_factory=dict)

    def lines(self, path: Path) -> list[str] | None:
        if path not in self._lines:
            try:
                self._lines[path] = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                self._lines[path] = None
        return self._lines[path]

    def line(self, path: Path, number: int) -> str | None:
        lines = self.lines(path)
        if lines is None or not 1 <= number <= len(lines):
            return None
        return lines[number - 1]

    def _document(self, path: Path) -> Any:
        if path not in self._documents:
            from opentide.validation.errors import load_yaml_with_lines

            self._documents[path] = load_yaml_with_lines(path)
        return self._documents[path]

    def yaml_problem(self, path: Path) -> YamlProblem | None:
        """Why *path* does not parse, or ``None`` when it does (or cannot be read)."""
        import yaml

        from opentide.core.io import describe_yaml_error, parse_yaml

        lines = self.lines(path)
        if lines is None:
            return None
        try:
            parse_yaml("\n".join(lines))
        except yaml.YAMLError as exc:
            return describe_yaml_error(exc)
        return None

    def span(self, path: Path, field_path: Sequence[str], value: str | None = None) -> Span | None:
        """The value at *field_path*; its key when the value is a block or empty.

        When the path stops short of a missing key, the deepest key that exists
        is returned, so "field required" points at the mapping it belongs in.
        *value* picks the list item when the path names a whole list.
        """
        document = self._document(path)
        if document is None or not field_path:
            return None
        node, parent, key = document, None, None
        for part in field_path:
            child = _child(node, part)
            if child is _MISSING:
                break
            node, parent, key = child, node, part
        if parent is None or key is None:
            return None
        if isinstance(node, list) and value is not None and value in node:
            parent, key, node = node, str(node.index(value)), value
        position = _value_position(parent, key)
        if position is not None and not isinstance(node, (dict, list)):
            span = self._token(path, *position)
            if span is not None:
                return span
        position = _key_position(parent, key)
        if position is None:
            return None
        line, column = position
        text = self.line(path, line + 1)
        if text is None:
            return None
        length = len(key) if isinstance(parent, dict) else 1
        if isinstance(parent, dict):
            found = text.find(key, column)
            column = found if found >= 0 else column
        return Span(line + 1, column + 1, column + 1 + length, text[column : column + length])

    def _token(self, path: Path, line: int, column: int) -> Span | None:
        text = self.line(path, line + 1)
        if text is None or column >= len(text):
            return None
        start, end = _token_bounds(text, column)
        if end <= start:
            return None
        return Span(line + 1, start + 1, end + 1, text[start:end])


_MISSING = object()


def _child(node: Any, part: str) -> Any:
    if isinstance(node, dict) and part in node:
        return node[part]
    if isinstance(node, list) and part.isdigit() and int(part) < len(node):
        return node[int(part)]
    return _MISSING


def _marker(node: Any, accessor: str, key: str) -> tuple[int, int] | None:
    marker = getattr(node, "lc", None)
    lookup = getattr(marker, accessor, None)
    if not callable(lookup):
        return None
    try:
        located = lookup(int(key) if isinstance(node, list) else key)
    except (KeyError, IndexError, TypeError, ValueError):
        return None
    if not located or not all(isinstance(part, int) for part in located[:2]):
        return None
    return located[0], located[1]


def _value_position(parent: Any, key: str) -> tuple[int, int] | None:
    return _marker(parent, "item" if isinstance(parent, list) else "value", key)


def _key_position(parent: Any, key: str) -> tuple[int, int] | None:
    return _marker(parent, "item" if isinstance(parent, list) else "key", key)


def _token_bounds(text: str, start: int) -> tuple[int, int]:
    """``[start, end)`` of the scalar written at *start*, without its quotes."""
    first = text[start]
    if first in "\"'":
        end = start + 1
        while end < len(text):
            if text[end] == "\\" and first == '"':
                end += 2
                continue
            if text[end] == first:
                if first == "'" and text[end + 1 : end + 2] == "'":
                    end += 2
                    continue
                return start + 1, end
            end += 1
        return start + 1, len(text)
    if first in "|>":
        return start, start + 1
    stops = {"#"} if not _in_flow(text[:start]) else {"#", ",", "]", "}"}
    end = start
    while end < len(text):
        if text[end] in stops and (text[end] != "#" or text[end - 1] in " \t"):
            break
        end += 1
    return start, len(text[:end].rstrip())


def _in_flow(prefix: str) -> bool:
    return prefix.count("[") > prefix.count("]") or prefix.count("{") > prefix.count("}")


# --------------------------------------------------------------------------
# Validation issues
# --------------------------------------------------------------------------


#: The command that lists what a reference field may point at, by field name.
_REFERENCE_LISTINGS = {
    "detection_model": "opentide info objectives",
    "threats": "opentide info threats",
    "vector": "opentide info threats",
}


def _value_fix(code: str, value: str, suggestion: str, span: Span | None) -> Fix | None:
    """Replace *value* with *suggestion* where it is written; ``None`` if it is not there."""
    if span is None or span.text != value or value == suggestion:
        return None
    similarity = difflib.SequenceMatcher(None, value.casefold(), suggestion.casefold()).ratio()
    safe = code != "invalid_ref" and similarity >= SAFE_FIX_SIMILARITY
    return Fix(safe, (TextEdit(span.line, span.column, span.end_column, suggestion),))


def _issue_label(issue: ValidationIssue) -> str | None:
    context = issue.context
    if issue.code == "vocab_unknown" and context.get("vocab"):
        return f"not in {context['vocab']}"
    if issue.code == "invalid_ref":
        return "no object has this id"
    if issue.code == "config_enum_unknown" and context.get("setting"):
        return f"not a configured {context['setting']} value"
    if issue.code == "chaining_relation_unknown":
        return "not a chaining relation"
    return None


def _issue_value(issue: ValidationIssue) -> str | None:
    value = issue.context.get("value")
    return value if isinstance(value, str) else None


def diagnostic_from_issue(
    issue: ValidationIssue, *, workspace: Path | None, sources: SourceFiles
) -> Diagnostic:
    """A validation issue as a diagnostic, with its position read from the file."""
    file_path = issue.file_path
    value = _issue_value(issue)
    message = issue.message
    notes: list[tuple[str, str]] = []
    line = None if issue.yaml_line is None else issue.yaml_line + 1
    span: Span | None = None
    if file_path is not None and issue.code == "yaml_parse":
        problem = sources.yaml_problem(file_path)
        if problem is not None and problem.line is not None and problem.column is not None:
            message = f"Could not parse object YAML: {problem.problem}"
            span = Span(problem.line, problem.column, problem.column + 1)
            if note := problem.context_note:
                notes.append(("note", note))
    elif file_path is not None and issue.field_path:
        # A block's yaml_line is its first child; the frame points at its key.
        span = sources.span(file_path, issue.field_path, value)
    if span is not None:
        line = span.line
    help_text = issue.suggestion
    fix = None
    if issue.code in VALUE_SUGGESTION_CODES and issue.suggestion:
        help_text = f"did you mean {issue.suggestion!r}?"
        if value is not None:
            fix = _value_fix(issue.code, value, issue.suggestion, span)
    elif issue.code == "invalid_ref" and not help_text:
        listing = _REFERENCE_LISTINGS.get(
            next((part for part in reversed(issue.field_path) if not part.isdigit()), "")
        )
        if listing:
            help_text = f"{listing} lists the ones that exist"
    allowed = issue.context.get("allowed")
    if issue.code == "config_enum_unknown" and isinstance(allowed, list) and allowed:
        notes.append(("expected", "one of " + ", ".join(str(item) for item in allowed)))
    return Diagnostic(
        code=issue.code,
        severity="warning" if issue.severity == "warning" else "error",
        message=message,
        path=None if file_path is None else relative_path(file_path, workspace),
        file_path=file_path,
        line=line,
        column=None if span is None else span.column,
        end_column=None if span is None else span.end_column,
        field_path=tuple(issue.field_path),
        help=help_text,
        fix=fix,
        label=_issue_label(issue),
        notes=tuple(notes),
    )


def diagnostics_from_issues(
    issues: Iterable[ValidationIssue], *, workspace: Path | None, sources: SourceFiles | None = None
) -> list[Diagnostic]:
    sources = sources or SourceFiles()
    return [diagnostic_from_issue(issue, workspace=workspace, sources=sources) for issue in issues]


# --------------------------------------------------------------------------
# Lint findings
# --------------------------------------------------------------------------

_LINT_SEVERITY: dict[str, Severity] = {"error": "error", "warning": "warning", "info": "note"}


def diagnostic_from_lint_finding(
    finding: Mapping[str, Any], *, root: Path, sources: SourceFiles
) -> Diagnostic:
    """A lint finding as a diagnostic. Lint points at top-level keys, read from the line."""
    path = str(finding["path"])
    file_path = root / path
    code = str(finding.get("code") or "lint")
    field_path = tuple(str(part) for part in finding.get("field_path") or ())
    line: int | None = finding.get("line")
    column: int | None = finding.get("column")
    end_column: int | None = finding.get("end_column")
    if column is not None and end_column is None:
        end_column = column + 1
    yaml_line = finding.get("yaml_line")
    if line is None and isinstance(yaml_line, int):
        line = yaml_line + 1
        text = sources.line(file_path, line)
        key = field_path[0] if field_path else None
        if text is not None and key and (found := text.find(key)) >= 0:
            column, end_column = found + 1, found + 1 + len(key)
    notes: list[tuple[str, str]] = []
    help_text: str | None = None
    expected = finding.get("expected")
    if code == LINT_CODES["filename"] and expected and finding.get("fixed") is not True:
        help_text = f"rename it to {expected}"
    elif code == LINT_CODES["name"]:
        help_text = "add a name: the file name is derived from it"
    elif code == LINT_CODES["metadata"]:
        help_text = "add the missing keys under metadata"
    if finding.get("fixed") is True and finding.get("from"):
        notes.append(("note", f"renamed from {finding['from']}"))
    if note := finding.get("note"):
        notes.append(("note", str(note)))
    return Diagnostic(
        code=code,
        severity=_LINT_SEVERITY.get(str(finding.get("severity")), "warning"),
        message=str(finding.get("message", "")),
        path=path,
        file_path=file_path,
        line=line,
        column=column,
        end_column=end_column,
        field_path=field_path,
        help=help_text,
        notes=tuple(notes),
    )
