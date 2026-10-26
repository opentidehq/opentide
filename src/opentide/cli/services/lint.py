"""Catalogue hygiene checks for ``opentide lint``."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, NamedTuple

import structlog
import yaml

from opentide.cli.enums import LintCheck
from opentide.cli.ui.contract import ISSUES_FOUND, NextAction
from opentide.cli.ui.diagnostics import (
    LINT_CODES,
    SourceFiles,
    annotate,
    diagnostic_from_lint_finding,
)
from opentide.cli.ui.glyphs import glyph
from opentide.core.io import describe_yaml_error, parse_yaml
from opentide.documentation.markdown.links import slugify
from opentide.registry.catalogue import NESTED_OBJECT_FILE, nested_file_message, scan_object_dir

logger = structlog.get_logger("opentide.cli.services.lint")

_OBJECT_FAMILIES = ("threats", "objectives", "rules")

#: How much a finding matters. ``--strict`` still fails on any finding.
Severity = Literal["error", "warning", "info"]


@dataclass
class _ObjectRecord:
    path: Path
    relative: str
    name: str | None = None
    uuid: str | None = None
    author: str | None = None
    organisation: str | None = None
    parse_error: str | None = None
    #: 1-based position of the YAML error, when the parser gives one.
    parse_position: tuple[int, int] | None = None
    expected_stem: str | None = None
    key_lines: dict[str, int] = field(default_factory=dict)
    #: Each value ``opentide new`` marked as a placeholder.
    placeholder_lines: list[_Marked] = field(default_factory=list)


def _object_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Catalogue files, and the YAML files in subfolders that are not objects (#584)."""
    objects = root / "objects"
    if not objects.is_dir():
        return [], []
    files: list[Path] = []
    nested: list[Path] = []
    for family in _OBJECT_FAMILIES:
        scan = scan_object_dir(objects / family, include_debug=True)
        files.extend(scan.files)
        nested.extend(scan.nested)
    return files, nested


def _nested_findings(root: Path, nested: list[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in nested:
        relative = path.relative_to(root).as_posix()
        folder = path.relative_to(root).parts[:2]
        findings.append(
            {
                "check": LintCheck.filenames.value,
                "severity": "warning",
                "path": relative,
                "yaml_line": None,
                "uuid": None,
                "message": nested_file_message(relative, "/".join(folder)),
                "_code": NESTED_OBJECT_FILE,
                "_field_path": [],
            }
        )
    return findings


def _as_str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _organisation_name(value: object) -> str | None:
    """Accept a string or the nested ``{name, uuid}`` metadata object."""
    named = _as_str(value)
    if named:
        return named
    if isinstance(value, dict):
        return _as_str(value.get("name"))
    return None


#: A top-level key starts in column 0, optionally quoted, followed by a colon.
_TOP_LEVEL_KEY = re.compile(r"""^(?:"([^"]+)"|'([^']+)'|([A-Za-z_][\w.-]*))\s*:(?:\s|$)""")


def _top_level_key_lines(text: str) -> dict[str, int]:
    """Zero-based line of each top-level key, as ``validate`` records ``yaml_line``.

    Read from the text already in hand: a round-trip parse per finding made lint
    roughly 13 times slower on a catalogue where most objects have a finding.
    """
    lines: dict[str, int] = {}
    for number, line in enumerate(text.splitlines()):
        if (match := _TOP_LEVEL_KEY.match(line)) is not None:
            lines.setdefault(next(group for group in match.groups() if group), number)
    return lines


#: The trailing comment ``opentide new`` writes on a value it invented.
_PLACEHOLDER = re.compile(r"\s#\s*opentide:placeholder\s*$")
#: A YAML key is followed by ``: `` or a colon at the end: ``OS::Windows`` is a value.
_MARKED_KEY = re.compile(r"^(?P<lead>\s*(?:-\s+)?)(?P<key>[A-Za-z_][\w.-]*)\s*:(?:\s+|$)")
_ITEM = re.compile(r"^(?P<lead>(?P<indent>\s*)-\s+)")

PLACEHOLDER_CODE = LINT_CODES["placeholder"]
PLACEHOLDER_HELP = "replace the value, then delete the '# opentide:placeholder' comment"


class _Marked(NamedTuple):
    """A value ``opentide new`` marked.

    ``line`` is zero-based; columns are 1-based, end exclusive.
    """

    line: int
    #: The key, or ``key[index]`` for an item of a list.
    label: str
    column: int
    end_column: int


def _list_item_label(lines: Sequence[str], number: int, indent: int) -> str:
    """``surface[0]``: the key that owns the item on line *number*, and its index."""
    index = 0
    for previous in range(number - 1, -1, -1):
        text = lines[previous]
        if not text.strip() or text.lstrip().startswith("#"):
            continue
        current = len(text) - len(text.lstrip())
        if current == indent and text.lstrip().startswith("-"):
            index += 1
            continue
        if current < indent and (key := _MARKED_KEY.match(text)) is not None:
            return f"{key['key']}[{index}]"
        if current < indent:
            break
    return f"list item {index}"


def _placeholder_lines(text: str) -> list[_Marked]:
    """Each placeholder marker: its line, what holds it, and the columns of the value.

    A block scalar (``description: |``) points at its key, since the value
    starts on the next line.
    """
    lines = text.splitlines()
    marked: list[_Marked] = []
    for number, line in enumerate(lines):
        marker = _PLACEHOLDER.search(line)
        if marker is None:
            continue
        content = line[: marker.start()].rstrip()
        if (key := _MARKED_KEY.match(content)) is not None:
            start, label = key.end(), key["key"]
            if content[start:] in ("", "|", ">", "|-", ">-"):
                start = key.start("key")
                end = key.end("key")
            else:
                end = len(content)
        elif (item := _ITEM.match(content)) is not None:
            start, end = item.end(), len(content)
            label = _list_item_label(lines, number, len(item["indent"]))
        else:
            start = len(content) - len(content.lstrip())
            end, label = len(content), "value"
        marked.append(_Marked(number, label, start + 1, max(end, start + 1) + 1))
    return marked


def _load_record(root: Path, path: Path) -> _ObjectRecord:
    relative = path.relative_to(root).as_posix()
    record = _ObjectRecord(path=path, relative=relative)
    try:
        text = path.read_text(encoding="utf-8")
        data: Any = parse_yaml(text)
    except yaml.YAMLError as exc:
        problem = describe_yaml_error(exc)
        record.parse_error = problem.message
        if problem.line is not None and problem.column is not None:
            record.parse_position = (problem.line, problem.column)
        return record
    except (UnicodeDecodeError, OSError) as exc:
        record.parse_error = str(exc)
        return record
    record.key_lines = _top_level_key_lines(text)
    record.placeholder_lines = _placeholder_lines(text)
    if not isinstance(data, dict):
        record.parse_error = "object YAML is not a mapping"
        return record
    record.name = _as_str(data.get("name"))
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        record.uuid = _as_str(metadata.get("uuid"))
        record.author = _as_str(metadata.get("author"))
        record.organisation = _organisation_name(
            metadata.get("organisation")
        ) or _organisation_name(metadata.get("organization"))
    return record


def _key_line(record: _ObjectRecord, key: str) -> int | None:
    """Zero-based line of a top-level *key*, as ``validate`` records ``yaml_line``."""
    return record.key_lines.get(key)


def _finding(
    check: LintCheck,
    severity: Severity,
    record: _ObjectRecord,
    message: str,
    *,
    code: str,
    field: str | None = None,
    yaml_line: int | None = None,
    **extra: object,
) -> dict[str, object]:
    """One finding. ``uuid`` and ``yaml_line`` are ``None`` when the file does not say.

    *code* and *field* become the ``code`` and ``field_path`` keys, which
    :func:`_add_diagnostic_fields` appends after the original ones.
    """
    return {
        "check": check.value,
        "severity": severity,
        "path": record.relative,
        "yaml_line": yaml_line,
        "uuid": record.uuid,
        **extra,
        "message": message,
        "_code": code,
        "_field_path": [field] if field else [],
    }


def _assign_expected_stems(records: list[_ObjectRecord]) -> None:
    grouped: dict[Path, list[_ObjectRecord]] = defaultdict(list)
    for record in records:
        if record.parse_error:
            continue
        grouped[record.path.parent].append(record)
    for group in grouped.values():
        taken: set[str] = set()
        for record in group:
            if record.name and slugify(record.name) == record.path.stem:
                record.expected_stem = record.path.stem
                taken.add(record.path.stem)
        for record in group:
            if record.expected_stem or not record.name:
                continue
            stem = slugify(record.name)
            if stem not in taken:
                record.expected_stem = stem
                taken.add(stem)
                continue
            suffix = (record.uuid or "object")[:8]
            candidate = f"{stem}-{suffix}"
            index = 1
            while candidate in taken:
                candidate = f"{stem}-{suffix}-{index}"
                index += 1
            record.expected_stem = candidate
            taken.add(candidate)


def _filename_findings(
    root: Path, records: list[_ObjectRecord], *, fix: bool
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    _assign_expected_stems(records)
    for record in records:
        if record.parse_error:
            findings.append(
                _finding(
                    LintCheck.filenames,
                    "error",
                    record,
                    f"Could not parse object YAML: {record.parse_error}",
                    code=LINT_CODES["parse"],
                    _position=record.parse_position,
                )
            )
            continue
        if not record.name:
            findings.append(
                _finding(
                    LintCheck.filenames,
                    "error",
                    record,
                    "Object has no name; cannot check filename slug",
                    code=LINT_CODES["name"],
                    field="name",
                    yaml_line=_key_line(record, "name"),
                )
            )
            continue
        expected = record.expected_stem
        if expected is None or expected == record.path.stem:
            continue
        dest = record.path.with_name(f"{expected}{record.path.suffix}")
        finding = _finding(
            LintCheck.filenames,
            "warning",
            record,
            f"Filename {record.path.name!r} does not match slugify(name)={expected!r}",
            code=LINT_CODES["filename"],
            expected=dest.relative_to(root).as_posix(),
        )
        if fix:
            if dest.exists() and not _case_only_rename(record.path, dest):
                finding["fixed"] = False
                finding["message"] = (
                    f"{finding['message']}; --fix skipped because {finding['expected']} exists"
                )
            else:
                _rename(record.path, dest)
                finding["fixed"] = True
                finding["from"] = record.relative
                finding["path"] = dest.relative_to(root).as_posix()
        findings.append(finding)
    return findings


_CASE_RENAME_SUFFIX = ".opentide-case-rename"


def _case_only_rename(src: Path, dest: Path) -> bool:
    """Whether *dest* exists only because it is *src* under another case.

    On a case-insensitive filesystem (macOS, Windows) ``Phishing.yaml`` and
    ``phishing.yaml`` are one file, so the slug's name always "existed" and
    ``--fix`` skipped the rename it was asked for.
    """
    return (
        src.name != dest.name
        and src.name.casefold() == dest.name.casefold()
        and dest.exists()
        and dest.samefile(src)
        and not (src.parent / f"{src.name}{_CASE_RENAME_SUFFIX}").exists()
    )


def _rename(src: Path, dest: Path) -> None:
    """Rename *src* to *dest*, through a temporary name when only the case changes.

    A case-only rename is a no-op on some case-insensitive filesystems.
    """
    if not _case_only_rename(src, dest):
        src.rename(dest)
        return
    staged = src.with_name(f"{src.name}{_CASE_RENAME_SUFFIX}")
    src.rename(staged)
    staged.rename(dest)


def _metadata_findings(records: list[_ObjectRecord]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for record in records:
        if record.parse_error or not record.name:
            continue
        missing: list[str] = []
        if not record.author:
            missing.append("author")
        if not record.organisation:
            missing.append("organisation")
        if missing:
            findings.append(
                _finding(
                    LintCheck.metadata,
                    "info",
                    record,
                    "Recommended metadata missing: " + ", ".join(missing),
                    code=LINT_CODES["metadata"],
                    field="metadata",
                    yaml_line=_key_line(record, "metadata"),
                )
            )
    return findings


def _placeholder_findings(records: list[_ObjectRecord]) -> list[dict[str, object]]:
    """One warning per value ``opentide new`` marked as a stand-in nobody chose."""
    return [
        _finding(
            LintCheck.placeholders,
            "warning",
            record,
            f"{marked.label} holds a placeholder value written by opentide new",
            yaml_line=marked.line,
            code=PLACEHOLDER_CODE,
            help=PLACEHOLDER_HELP,
            line=marked.line + 1,
            column=marked.column,
            end_column=marked.end_column,
        )
        for record in records
        if not record.parse_error
        for marked in record.placeholder_lines
    ]


def _rewrite_renamed_paths(findings: list[dict[str, object]]) -> None:
    """Point earlier findings at the path ``--fix`` just renamed the file to."""
    renamed = {
        str(item["from"]): str(item["path"])
        for item in findings
        if item.get("fixed") is True and item.get("from") and item.get("path")
    }
    if not renamed:
        return
    for finding in findings:
        path = finding.get("path")
        if isinstance(path, str) and path in renamed:
            finding["path"] = renamed[path]


def run_lint(
    root: Path,
    *,
    checks: list[LintCheck] | None = None,
    fix: bool = False,
    strict: bool = False,
) -> dict[str, object]:
    """Run catalogue hygiene checks without a full registry rebuild."""
    target = root.resolve()
    selected = (
        list(checks)
        if checks
        else [LintCheck.filenames, LintCheck.metadata, LintCheck.placeholders]
    )
    object_files, nested = _object_files(target)
    records = [_load_record(target, path) for path in object_files]
    findings: list[dict[str, object]] = []
    if LintCheck.metadata in selected:
        findings.extend(_metadata_findings(records))
    if LintCheck.placeholders in selected:
        findings.extend(_placeholder_findings(records))
    if LintCheck.filenames in selected:
        findings.extend(_filename_findings(target, records, fix=fix))
        _rewrite_renamed_paths(findings)
        findings.extend(_nested_findings(target, nested))
    logger.debug(
        "lint_complete",
        path=str(target),
        checks=[item.value for item in selected],
        findings=len(findings),
        fix=fix,
    )
    # What --fix just fixed is reported, but no longer counts against the run.
    left = [item for item in findings if item.get("fixed") is not True]
    if left and strict:
        status = "failed"
    elif left:
        status = "issues"
    else:
        status = "completed"
    renamable = sum(
        1 for item in findings if item.get("expected") and item.get("fixed") is not True
    )
    _add_diagnostic_fields(target, findings)
    files = len(records)
    fixed = sum(1 for item in findings if item.get("fixed") is True)
    result: dict[str, Any] = {
        "message": ("Catalogue lint found issues" if findings else "Catalogue lint passed"),
        "path": str(target),
        "checks": [item.value for item in selected],
        "findings": findings,
        "count": len(findings),
        "fixed": fixed,
        "status": status,
        "_exit_code": 1 if status == "failed" else 0,
        "_summary": {
            "files": files,
            "findings": len(left),
            "errors": sum(1 for item in left if item.get("severity") == "error"),
            "warnings": sum(1 for item in left if item.get("severity") == "warning"),
            "notes": sum(1 for item in left if item.get("severity") == "info"),
            "fixed": fixed,
        },
        "_outcome": _outcome_line(left, files=files, fixed=fixed, root=target),
    }
    if status == "failed":
        result["_failure_code"] = ISSUES_FOUND
    if renamable:
        result["_next_actions"] = [
            NextAction(
                "opentide lint --fix",
                f"rename {renamable} {'file' if renamable == 1 else 'files'} to match their names",
            )
        ]
    return result


def _add_diagnostic_fields(root: Path, findings: list[dict[str, object]]) -> None:
    """Append ``code``, ``field_path`` and the diagnostic fields to each finding."""
    sources = SourceFiles()
    for finding in findings:
        finding["code"] = finding.pop("_code")
        finding["field_path"] = finding.pop("_field_path")
        position = finding.pop("_position", None)
        if isinstance(position, tuple):
            finding["line"], finding["column"] = position
        annotate(finding, diagnostic_from_lint_finding(finding, root=root, sources=sources))


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _outcome_line(left: list[dict[str, object]], *, files: int, fixed: int, root: Path) -> str:
    """``3 files clean`` or ``3 findings in 2 files · 1 warning, 2 notes · 1 fixed``.

    *left* are the findings ``--fix`` did not fix; *fixed* counts the others.
    The severities are split only when more than one kind is left.
    """
    sep = f" {glyph('separator')} "
    done = f"{sep}{fixed} fixed" if fixed else ""
    if not left:
        if not files:
            return f"Catalogue lint passed, but found no object files under {root}"
        return f"{_plural(files, 'file')} clean{done}"
    touched = len({str(item.get("path")) for item in left})
    line = f"{_plural(len(left), 'finding')} in {_plural(touched, 'file')}"
    kinds = [
        _plural(count, noun)
        for severity, noun in _SEVERITY_NOUNS
        if (count := sum(1 for item in left if item.get("severity") == severity))
    ]
    if len(kinds) > 1:
        line += sep + ", ".join(kinds)
    return line + done


#: How the outcome line names each severity: lint's ``info`` prints as ``note``.
_SEVERITY_NOUNS = (("error", "error"), ("warning", "warning"), ("info", "note"))
