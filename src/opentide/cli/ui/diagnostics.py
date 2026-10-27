"""The shape every finding takes: a code, a severity, a message and a place in a file.

A :class:`Diagnostic` is built from a validation issue or a lint finding by
an adapter here, rendered as a code frame by :mod:`opentide.cli.ui.codeframe`,
and merged into the JSON entry it came from by :func:`annotate`, which adds
keys and never changes one. See "Diagnostics" in
``docs/internal/cli-experience.md``.

Positions are 1-based. Columns count Unicode code points, as Python
indexes a ``str``: ``🔥`` is one column. A SARIF or LSP consumer that wants
UTF-16 code units converts (SARIF ``columnKind: "unicodeCodePoints"`` says
it as is). ``end_column`` is the column just after the last character, so
``end_column - column`` is the length of a one-line span, and an edit
replaces the text from (``line``, ``column``) up to (``end_line``,
``end_column``).

``line`` is where the frame points, which is not always ``yaml_line + 1``:
for a block value (a mapping or a list) it is the line of its key, while
``yaml_line`` is the block's first child. For a missing field it is the key
of the mapping the field belongs in.

Kept free of Rich and Typer. The YAML parsers load only when a position is
looked up.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from opentide.core.io import YamlProblem
    from opentide.validation.issues import ValidationIssue, ValidationReport

Severity = Literal["error", "warning", "note"]

#: Keys :func:`annotate` adds to a JSON finding. Keys the finding has keep their value.
DIAGNOSTIC_FIELDS = ("path", "line", "column", "end_column", "help", "fix", "explain")

#: Codes whose ``suggestion`` is a replacement value for the one at fault.
VALUE_SUGGESTION_CODES = frozenset(
    {"vocab_unknown", "invalid_ref", "chaining_relation_unknown", "config_enum_unknown"}
)

#: Codes whose fix may be ``safe``. A reference fix never is: its suggestion
#: is a fuzzy match on an object's name.
SAFE_FIX_CODES = frozenset({"vocab_unknown", "chaining_relation_unknown", "config_enum_unknown"})

#: Lint finding codes, by what the finding is about.
LINT_CODES = {
    "parse": "yaml_parse",
    "name": "name_missing",
    "filename": "filename_mismatch",
    "metadata": "metadata_recommended",
    "placeholder": "placeholder",
}


#: Help for codes whose issue carries no suggestion, so their frame still ends
#: in a step to take (``╰─ help: …``), as the spec's frame does.
_DEFAULT_HELP = {
    "invalid_uuid": 'replace it with a UUID v4: python -c "import uuid; print(uuid.uuid4())"',
    "missing_uuid": "add metadata.uuid with a fresh UUID v4",
    "duplicate_id": (
        "give one of them a fresh UUID v4; keep the UUID on the object that is deployed "
        "or referenced"
    ),
    # These frames ended on the underline, with no step (post-merge end-to-end run).
    "yaml_parse": (
        "look at the indentation, a missing ':' or an unclosed quote at or just before "
        "this position"
    ),
    "schema_validation": "the template in .opentide/templates/ shows the field and its values",
}

#: ``yaml_parse`` problems that are not syntax: the indentation hint would mislead.
_YAML_PARSE_HELP = (
    ("found an empty file", "fill it in from a template with opentide new, or delete it"),
    ("is not a valid date", "write the date as YYYY-MM-DD, with a month from 01 to 12"),
    ("is not UTF-8 text", "re-save it as UTF-8; most editors offer the encoding under Save As"),
)


def _yaml_parse_help(message: str, notes: Sequence[tuple[str, str]]) -> str | None:
    """The step for a ``yaml_parse`` frame: one that fits the problem, never a second help."""
    if any(kind == "help" for kind, _ in notes):
        return None
    for needle, help_text in _YAML_PARSE_HELP:
        if needle in message:
            return help_text
    return _DEFAULT_HELP["yaml_parse"]


def explain_command(code: str) -> str:
    """``opentide explain <code>``: the page that says what *code* means."""
    return f"opentide explain {code}"


@dataclass(frozen=True)
class TextEdit:
    """Replace the text from (*line*, *column*) up to (*end_line*, *end_column*).

    Columns are 1-based Unicode code points; *end_column* is exclusive.
    *end_line* defaults to *line*: an edit within one line.
    """

    line: int
    column: int
    end_column: int
    replacement: str
    end_line: int | None = None

    @property
    def last_line(self) -> int:
        return self.line if self.end_line is None else self.end_line

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line,
            "column": self.column,
            "end_line": self.last_line,
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
    """One finding, in the shape every renderer reads.

    ``line``, ``column`` and ``end_column`` follow the module docstring: 1-based,
    code points, ``end_column`` exclusive, a block value at its key.
    """

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
    #: The object the finding is about, when one is.
    object_uuid: str | None = None

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
            "object_uuid": self.object_uuid,
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
    #: ``False`` when the path stopped short of a missing key: the span is the
    #: deepest key that exists.
    found: bool = True


#: The line breaks YAML counts. ``str.splitlines`` also breaks on U+2028,
#: U+0085 and others, which YAML keeps inside a scalar.
_YAML_LINE_BREAK = re.compile(r"\r\n|\r|\n")


def split_yaml_lines(text: str) -> list[str]:
    """*text* split the way YAML numbers its lines."""
    lines = _YAML_LINE_BREAK.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


@dataclass
class SourceFiles:
    """Reads each file once, for every diagnostic that points into it."""

    _texts: dict[Path, str | None] = field(default_factory=dict)
    _lines: dict[Path, list[str] | None] = field(default_factory=dict)
    _documents: dict[Path, Any] = field(default_factory=dict)

    def text(self, path: Path) -> str | None:
        if path not in self._texts:
            try:
                with path.open(encoding="utf-8", newline="") as handle:
                    self._texts[path] = handle.read()
            except (OSError, UnicodeDecodeError):
                self._texts[path] = None
        return self._texts[path]

    def lines(self, path: Path) -> list[str] | None:
        if path not in self._lines:
            text = self.text(path)
            self._lines[path] = None if text is None else split_yaml_lines(text)
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

        text = self.text(path)
        if text is None:
            return None
        try:
            parse_yaml(text)
        except yaml.YAMLError as exc:
            return describe_yaml_error(exc)
        return None

    def span(
        self,
        path: Path,
        field_path: Sequence[str],
        value: str | None = None,
        *,
        occurrence: int = 0,
        at_key: bool = False,
    ) -> Span | None:
        """The value at *field_path*; its key when the value is a block or empty.

        When the path stops short of a missing key, the deepest key that exists
        is returned with ``found=False``, so "field required" points at the
        mapping it belongs in. *value* picks the list item when the path names
        a whole list, its *occurrence*-th one when it repeats. *at_key* points
        at the key even when the value is a scalar.
        """
        document = self._document(path)
        if document is None or not field_path:
            return None
        node, parent, key = document, None, None
        found = True
        for part in field_path:
            child = _child(node, part)
            if child is _MISSING:
                found = False
                break
            node, parent, key = child, node, part
        if parent is None and not found and isinstance(document, dict) and document:
            # A top-level field is missing: point at the mapping's first key.
            parent, key = document, str(next(iter(document)))
        if parent is None or key is None:
            return None
        if found and isinstance(node, list) and value is not None:
            indexes = [index for index, item in enumerate(node) if item == value]
            if indexes:
                index = indexes[min(occurrence, len(indexes) - 1)]
                parent, key, node = node, str(index), value
        position = _value_position(parent, key)
        if found and not at_key and position is not None and not isinstance(node, (dict, list)):
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
            located = text.find(key, column)
            column = located if located >= 0 else column
        return Span(
            line + 1, column + 1, column + 1 + length, text[column : column + length], found
        )

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


_IGNORABLE = re.compile(r"[\s_\-]+")


def is_safe_replacement(code: str, value: str, suggestion: str) -> bool:
    """Whether replacing *value* with *suggestion* is certainly what the author meant.

    Only when the two spell the same word: they differ in case, whitespace,
    ``-`` or ``_`` alone, so no second candidate can be closer. Never for a
    value with a digit, which is how identifiers look (``T1059``, a UUID, a
    CVE): one changed character there is another identifier, not a typo.
    """
    if code not in SAFE_FIX_CODES or value == suggestion:
        return False
    if any(char.isdigit() for char in value + suggestion):
        return False
    return _IGNORABLE.sub("", value).casefold() == _IGNORABLE.sub("", suggestion).casefold()


def _value_fix(code: str, value: str, suggestion: str, span: Span | None) -> Fix | None:
    """Replace *value* with *suggestion* where it is written; ``None`` if it is not there."""
    if span is None or not span.found or span.text != value or value == suggestion:
        return None
    safe = is_safe_replacement(code, value, suggestion)
    return Fix(safe, (TextEdit(span.line, span.column, span.end_column, suggestion),))


def _yaml_parse_frame(
    file_path: Path, sources: SourceFiles
) -> tuple[str, Span, tuple[tuple[str, str], ...]] | None:
    """Message, span and notes of a file that does not parse, read from the file itself.

    ``validate`` and ``lint`` render it the same way: the problem in the
    message, the parser's position as the span, its context as a note.
    """
    problem = sources.yaml_problem(file_path)
    if problem is None:
        return _root_shape_frame(file_path, sources)
    if problem.line is None or problem.column is None:
        return None
    end_column = problem.end_column or problem.column + 1
    span = Span(problem.line, problem.column, end_column)
    notes = (("note", note),) if (note := problem.context_note) else ()
    return f"Could not parse object YAML: {problem.problem}", span, notes


def _root_shape_frame(
    file_path: Path, sources: SourceFiles
) -> tuple[str, Span, tuple[tuple[str, str], ...]] | None:
    """A file that parses but is not one mapping: point at where its document starts."""
    from opentide.core.io import first_content_span, parse_yaml, root_mapping_problem

    text = sources.text(file_path)
    if text is None:
        return None
    try:
        message = root_mapping_problem(parse_yaml(text))
    except Exception:
        return None
    position = first_content_span(text)
    if message is None or position is None:
        return None
    from opentide.core.errors import OBJECT_FILE_HELP

    return message, Span(*position), (("help", OBJECT_FILE_HELP),)


#: ``schema_validation`` messages about a key rather than its value.
_KEY_ERRORS = ("Extra inputs are not permitted",)

#: The schema's message for a required field that is not there.
_MISSING_FIELD = "Field required"

#: Vocabulary names written as an acronym in a message (``'clearr' is not a TLP value``).
_VOCAB_ACRONYMS = frozenset({"tlp", "pap", "rsit"})


def _vocab_noun(vocab: str) -> str:
    """``tlp::1.0`` → ``TLP``, ``signal.entities::1.0`` → ``signal entities``."""
    name = vocab.split("::", 1)[0]
    if name in _VOCAB_ACRONYMS:
        return name.upper()
    return re.sub(r"[._]+", " ", name)


def _vocab_message(value: str, context: Mapping[str, Any]) -> str | None:
    vocab = context.get("vocab")
    return f"{value!r} is not a {_vocab_noun(vocab)} value" if isinstance(vocab, str) else None


def _config_enum_message(value: str, context: Mapping[str, Any]) -> str | None:
    setting = context.get("setting")
    if not isinstance(setting, str):
        return None
    noun = {"statuses": "status", "responders": "responder"}.get(setting, setting)
    return f"{value!r} is not a configured {noun}"


#: The message a person reads, in the spec's words, for a finding about one
#: value. The engine's message (kept in JSON and MCP) also says how to fix it,
#: which the frame's label, notes and help already show.
_VALUE_MESSAGES = {
    "vocab_unknown": _vocab_message,
    "config_enum_unknown": _config_enum_message,
}


def _duplicate_message(
    issue: ValidationIssue,
    value: str | None,
    *,
    workspace: Path | None,
    sources: SourceFiles,
) -> tuple[str, str | None]:
    """``UUID … is also used by 'Name'``, and where that one is written.

    The engine's sentence (``Duplicated ID … on 'A' @ a.yaml; already used by
    'B' @ b.yaml``) stays in JSON; a person reads which object shares it, with
    both places in the frame, since neither file is known to be the copy.
    """
    original = issue.context.get("original")
    if not isinstance(original, Mapping) or value is None:
        return issue.message, None
    name = original.get("name")
    other = f"{name!r}" if isinstance(name, str) and name else "another object"
    message = f"UUID {value} is also used by {other}"
    raw_path, raw_field = original.get("file_path"), original.get("field_path")
    if not isinstance(raw_path, str):
        return message, None
    other_path = Path(raw_path)
    where = relative_path(other_path, workspace) or raw_path
    if isinstance(raw_field, list):
        span = sources.span(other_path, tuple(str(part) for part in raw_field), value)
        if span is not None and span.found:
            where = f"{where}:{span.line}:{span.column}"
    return message, where


def _issue_label(issue: ValidationIssue) -> str | None:
    context = issue.context
    if issue.code == "vocab_unknown" and context.get("vocab"):
        return f"not in {context['vocab']}"
    if issue.code == "invalid_ref":
        return "no object has this id"
    if issue.code == "config_enum_unknown" and context.get("setting"):
        return f"not in [[{context['setting']}]]"
    if issue.code == "chaining_relation_unknown":
        return "not a chaining relation"
    return None


def _issue_value(issue: ValidationIssue) -> str | None:
    value = issue.context.get("value")
    return value if isinstance(value, str) else None


def diagnostic_from_issue(
    issue: ValidationIssue,
    *,
    workspace: Path | None,
    sources: SourceFiles,
    occurrence: int = 0,
) -> Diagnostic:
    """A validation issue as a diagnostic, with its position read from the file.

    *occurrence* is how many earlier issues reported the same value in the
    same list, so a value that repeats is pointed at each time it is written.
    """
    file_path = issue.file_path
    value = _issue_value(issue)
    message = issue.message
    notes: list[tuple[str, str]] = []
    label = _issue_label(issue)
    line = None if issue.yaml_line is None else issue.yaml_line + 1
    span: Span | None = None
    if file_path is not None and issue.code == "yaml_parse":
        frame = _yaml_parse_frame(file_path, sources)
        if frame is not None:
            message, span, parse_notes = frame
            notes.extend(parse_notes)
    elif file_path is not None and issue.field_path:
        # A block's yaml_line is its first child; the frame points at its key.
        at_key = issue.code == "schema_validation" and issue.message.startswith(_KEY_ERRORS)
        span = sources.span(
            file_path, issue.field_path, value, occurrence=occurrence, at_key=at_key
        )
    if issue.code == "schema_validation" and issue.field_path:
        missing, parent = issue.field_path[-1], ".".join(issue.field_path[:-1])
        where = f" in {parent}" if parent else ""
        if message == _MISSING_FIELD:
            message = f"missing required field {missing!r}{where}"
        else:
            # The schema's message does not say which field.
            message = f"{'.'.join(issue.field_path)}: {message}"
        if span is not None and not span.found:
            # The message names the field; the label says where it goes.
            label = f"add {missing!r} " + ("under this key" if parent else "at the top level")
    elif issue.code in _VALUE_MESSAGES and value is not None:
        message = _VALUE_MESSAGES[issue.code](value, issue.context) or message
    if span is not None:
        line = span.line
    help_text = issue.suggestion
    if issue.code == "platform_not_enabled" and "; " in message and not help_text:
        # The engine's sentence ends in the step to take; the frame shows it as help.
        message, help_text = message.rsplit("; ", 1)
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
    if not help_text and issue.code == "yaml_parse":
        help_text = _yaml_parse_help(message, notes)
    elif not help_text:
        help_text = _DEFAULT_HELP.get(issue.code)
    if issue.code == "duplicate_id":
        message, also = _duplicate_message(issue, value, workspace=workspace, sources=sources)
        if also:
            notes.append(("also", also))
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
        label=label,
        notes=tuple(notes),
        object_uuid=issue.object_uuid or None,
    )


def diagnostics_from_issues(
    issues: Iterable[ValidationIssue], *, workspace: Path | None, sources: SourceFiles | None = None
) -> list[Diagnostic]:
    """One diagnostic per issue, in order. A value repeated in a list is found each time."""
    sources = sources or SourceFiles()
    seen: dict[tuple[object, ...], int] = {}
    diagnostics: list[Diagnostic] = []
    for issue in issues:
        key = (issue.code, issue.file_path, issue.field_path, _issue_value(issue))
        occurrence = seen.get(key, 0)
        seen[key] = occurrence + 1
        diagnostics.append(
            diagnostic_from_issue(
                issue, workspace=workspace, sources=sources, occurrence=occurrence
            )
        )
    return diagnostics


def annotate_report(
    payload: Mapping[str, Any],
    report: ValidationReport,
    *,
    workspace: Path | None,
    buckets: Sequence[str] = ("issues", "warnings"),
    sources: SourceFiles | None = None,
) -> list[Diagnostic]:
    """Add the diagnostic fields to each issue of a dumped *report*; return the diagnostics.

    *payload* is ``report.model_dump_json_ready()``, or the part of it a
    surface returns: each list under *buckets* is annotated in place, entry
    for entry with the report's own list of that name.
    """
    sources = sources or SourceFiles()
    diagnostics: list[Diagnostic] = []
    for bucket in buckets:
        found = diagnostics_from_issues(
            getattr(report, bucket), workspace=workspace, sources=sources
        )
        for entry, diagnostic in zip(payload.get(bucket, []), found, strict=True):
            annotate(entry, diagnostic)
        diagnostics.extend(found)
    return diagnostics


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
    message = str(finding.get("message", ""))
    if code == LINT_CODES["parse"] and (frame := _yaml_parse_frame(file_path, sources)):
        message, span, parse_notes = frame
        line, column, end_column = span.line, span.column, span.end_column
        notes.extend(parse_notes)
    help_text: str | None = None
    expected = finding.get("expected")
    if code == LINT_CODES["filename"] and expected and finding.get("fixed") is not True:
        help_text = f"rename it to {expected}"
    elif code == LINT_CODES["name"]:
        help_text = "add a name: the file name is derived from it"
    elif code == LINT_CODES["metadata"]:
        help_text = "add the missing keys under metadata"
    elif finding.get("help"):
        # A check that words its own step, such as a placeholder's.
        help_text = str(finding["help"])
    if finding.get("fixed") is True and finding.get("from"):
        notes.append(("note", f"renamed from {finding['from']}"))
    if note := finding.get("note"):
        notes.append(("note", str(note)))
    return Diagnostic(
        code=code,
        severity=_LINT_SEVERITY.get(str(finding.get("severity")), "warning"),
        message=message,
        path=path,
        file_path=file_path,
        line=line,
        column=column,
        end_column=end_column,
        field_path=field_path,
        help=help_text,
        notes=tuple(notes),
        object_uuid=str(finding["uuid"]) if finding.get("uuid") else None,
    )
