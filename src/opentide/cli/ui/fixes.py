"""Apply the safe ``fix`` edits of diagnostics to the files they point into.

``opentide validate --fix`` writes them; ``--fix --dry-run`` prints them as a
unified diff. An edit replaces the text of one line from ``column`` up to
``end_column`` (see :mod:`opentide.cli.ui.diagnostics`) and leaves every other
byte of the file as it was, so comments, quoting, key order, indentation and
line endings survive. Positions come from ruamel's round-trip loader when the
diagnostic is built.

Each edit is checked before it is kept: the file must still parse, and the
parsed document must differ from the one before in exactly that value. An
edit that fails the check (a value that would need quoting, a file that
changed since it was read) is left out, and its finding stays reported.

Kept free of Rich and Typer.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentide.cli.ui.diagnostics import Diagnostic, TextEdit


@dataclass(frozen=True)
class FixChange:
    """One value a fix replaces: where, which finding, and the text before and after."""

    path: str
    file_path: Path
    line: int
    column: int
    code: str
    before: str
    after: str

    def to_dict(self) -> dict[str, Any]:
        """The JSON entry of ``fixed`` (``would_fix`` under ``--dry-run``)."""
        return {
            "path": self.path,
            "line": self.line,
            "code": self.code,
            "before": self.before,
            "after": self.after,
        }


@dataclass(frozen=True)
class FixPlan:
    """The edits that apply, file by file, with each file's text before and after."""

    changes: tuple[FixChange, ...] = ()
    #: ``file_path -> (display path, text before, text after)``, in the order found.
    files: dict[Path, tuple[str, str, str]] = field(default_factory=dict)

    @property
    def file_count(self) -> int:
        return len(self.files)

    def __bool__(self) -> bool:
        return bool(self.changes)

    def diff(self) -> str:
        """A unified diff of every file, ``a/<path>`` against ``b/<path>``."""
        chunks: list[str] = []
        for path, before, after in self.files.values():
            chunks.extend(
                difflib.unified_diff(
                    _diff_lines(before), _diff_lines(after), f"a/{path}", f"b/{path}"
                )
            )
        return "".join(chunks)

    def write(self) -> tuple[FixPlan, list[str]]:
        """Write each changed file; bytes outside the edits are written back unchanged.

        Returns the plan of the files written, and one line per file that
        could not be (``objects/rules/x.yaml: Permission denied``).
        """
        written: dict[Path, tuple[str, str, str]] = {}
        failed: list[str] = []
        for file_path, entry in self.files.items():
            try:
                file_path.write_bytes(entry[2].encode("utf-8"))
            except OSError as exc:
                failed.append(f"{entry[0]}: {exc.strerror or exc}")
                continue
            written[file_path] = entry
        changes = tuple(change for change in self.changes if change.file_path in written)
        return FixPlan(changes=changes, files=written), failed


def _diff_lines(text: str) -> list[str]:
    lines = text.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n\\ No newline at end of file\n"
    return lines


def safe_edits(diagnostic: Diagnostic) -> tuple[TextEdit, ...]:
    """The edits ``--fix`` may apply for *diagnostic*: none unless its fix is safe."""
    if diagnostic.fix is None or not diagnostic.fix.safe or diagnostic.file_path is None:
        return ()
    return diagnostic.fix.edits


def plan_fixes(diagnostics: Iterable[Diagnostic]) -> FixPlan:
    """Read each file with a safe fix once and work out which edits apply.

    Nothing is written; :meth:`FixPlan.write` does that. Two findings with the
    same edit apply it once; an edit that overlaps one already kept is left out.
    """
    by_file: dict[Path, list[tuple[TextEdit, Diagnostic]]] = {}
    for diagnostic in diagnostics:
        for edit in safe_edits(diagnostic):
            assert diagnostic.file_path is not None
            by_file.setdefault(diagnostic.file_path, []).append((edit, diagnostic))
    changes: list[FixChange] = []
    files: dict[Path, tuple[str, str, str]] = {}
    for file_path, edits in by_file.items():
        applied = _plan_file(file_path, edits)
        if applied is None:
            continue
        path, before, after, kept = applied
        files[file_path] = (path, before, after)
        changes.extend(kept)
    changes.sort(key=lambda change: (change.path, change.line, change.column))
    return FixPlan(changes=tuple(changes), files=files)


def _plan_file(
    file_path: Path, edits: Sequence[tuple[TextEdit, Diagnostic]]
) -> tuple[str, str, str, list[FixChange]] | None:
    try:
        original = file_path.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    document = _load(original)
    if document is _UNPARSABLE:
        return None
    # Right to left, so an edit never moves the columns of one still to apply.
    ordered = sorted(
        _unique(edits),
        key=lambda item: (item[0].line, item[0].column),
        reverse=True,
    )
    text, kept = original, []
    taken: list[TextEdit] = []
    for edit, diagnostic in ordered:
        if any(_overlaps(edit, other) for other in taken):
            continue
        result = _apply(text, edit)
        if result is None:
            continue
        updated, before = result
        new_document = _load(updated)
        if new_document is _UNPARSABLE or not _only_change(
            document, new_document, before, edit.replacement
        ):
            continue
        text, document = updated, new_document
        taken.append(edit)
        kept.append(
            FixChange(
                path=diagnostic.path or file_path.as_posix(),
                file_path=file_path,
                line=edit.line,
                column=edit.column,
                code=diagnostic.code,
                before=before,
                after=edit.replacement,
            )
        )
    if not kept:
        return None
    path = kept[0].path
    return path, original, text, kept


def _unique(
    edits: Iterable[tuple[TextEdit, Diagnostic]],
) -> list[tuple[TextEdit, Diagnostic]]:
    seen: set[TextEdit] = set()
    unique: list[tuple[TextEdit, Diagnostic]] = []
    for edit, diagnostic in edits:
        if edit not in seen:
            seen.add(edit)
            unique.append((edit, diagnostic))
    return unique


def end_line(edit: TextEdit) -> int:
    """The line the edit ends on: its own ``end_line`` when it has one, else its ``line``."""
    value = getattr(edit, "end_line", None)
    return value if isinstance(value, int) else edit.line


def _overlaps(edit: TextEdit, other: TextEdit) -> bool:
    return (edit.line, edit.column) < (end_line(other), other.end_column) and (
        other.line,
        other.column,
    ) < (end_line(edit), edit.end_column)


def _offset(lines: list[str], line: int, column: int) -> int | None:
    """Where 1-based *line*, *column* (in code points) falls in the joined text."""
    if not 1 <= line <= len(lines):
        return None
    content = lines[line - 1]
    if content.endswith("\r"):
        content = content[:-1]
    if not 1 <= column <= len(content) + 1:
        return None
    return sum(len(text) + 1 for text in lines[: line - 1]) + column - 1


def _apply(text: str, edit: TextEdit) -> tuple[str, str] | None:
    """*text* with *edit* applied, and the text it replaced; ``None`` if it does not fit.

    The edit replaces from (``line``, ``column``) up to (``end_line``,
    ``end_column``), so it may span lines; columns count code points.
    """
    # Split on "\n" only: a "\r" stays with its line, so CRLF files keep their endings.
    lines = text.split("\n")
    start = _offset(lines, edit.line, edit.column)
    end = _offset(lines, end_line(edit), edit.end_column)
    if start is None or end is None or end <= start:
        return None
    return text[:start] + edit.replacement + text[end:], text[start:end]


_UNPARSABLE = object()


def _load(text: str) -> Any:
    from ruamel.yaml import YAML
    from ruamel.yaml.error import YAMLError

    try:
        return YAML(typ="safe", pure=True).load(text)
    except (YAMLError, ValueError):
        return _UNPARSABLE


def _only_change(before: Any, after: Any, old: str, new: str) -> bool:
    """Whether *after* is *before* with exactly one scalar *old* replaced by *new*.

    *old* and *new* are the text as written; a plain scalar written over
    several lines reads back with its line breaks folded into spaces.
    """
    return _changed_scalars(before, after, {old, _folded(old)}, {new, _folded(new)}) == 1


def _folded(text: str) -> str:
    return " ".join(part.strip() for part in text.split("\n"))


def _changed_scalars(before: Any, after: Any, old: set[str], new: set[str]) -> int | None:
    """How many scalars changed from *old* to *new*; ``None`` on any other difference."""
    if isinstance(before, dict) and isinstance(after, dict):
        if list(before) != list(after):
            return None
        return _sum(_changed_scalars(before[key], after[key], old, new) for key in before)
    if isinstance(before, list) and isinstance(after, list):
        if len(before) != len(after):
            return None
        return _sum(_changed_scalars(a, b, old, new) for a, b in zip(before, after, strict=True))
    if type(before) is type(after) and before == after:
        return 0
    if isinstance(before, str) and isinstance(after, str) and before in old and after in new:
        return 1
    return None


def _sum(counts: Iterable[int | None]) -> int | None:
    total = 0
    for count in counts:
        if count is None:
            return None
        total += count
    return total
