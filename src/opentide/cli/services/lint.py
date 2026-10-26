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
from opentide.cli.ui.contract import NextAction
from opentide.core.io import parse_yaml
from opentide.core.logging.config import get_stdout_console
from opentide.documentation.markdown.links import slugify

logger = structlog.get_logger("opentide.cli.services.lint")

_OBJECT_FAMILIES = ("threats", "objectives", "rules")
_YAML_SUFFIXES = {".yaml", ".yml"}

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
    expected_stem: str | None = None
    key_lines: dict[str, int] = field(default_factory=dict)
    #: Each value ``opentide new`` marked as a placeholder.
    placeholder_lines: list[_Marked] = field(default_factory=list)


def _object_files(root: Path) -> list[Path]:
    objects = root / "objects"
    if not objects.is_dir():
        return []
    files: list[Path] = []
    for family in _OBJECT_FAMILIES:
        folder = objects / family
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix.lower() in _YAML_SUFFIXES:
                files.append(path)
    return files


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

PLACEHOLDER_CODE = "placeholder"
PLACEHOLDER_HELP = "replace the value, then delete the '# opentide:placeholder' comment"


class _Marked(NamedTuple):
    """A value ``opentide new`` marked. ``line`` is zero-based; columns are 1-based, end exclusive."""

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
    except (yaml.YAMLError, UnicodeDecodeError, OSError) as exc:
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
    yaml_line: int | None = None,
    **extra: object,
) -> dict[str, object]:
    """One finding. ``uuid`` and ``yaml_line`` are ``None`` when the file does not say."""
    return {
        "check": check.value,
        "severity": severity,
        "path": record.relative,
        "yaml_line": yaml_line,
        "uuid": record.uuid,
        **extra,
        "message": message,
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
            expected=dest.relative_to(root).as_posix(),
        )
        if fix:
            if dest.exists():
                finding["fixed"] = False
                finding["message"] = (
                    f"{finding['message']}; --fix skipped because {finding['expected']} exists"
                )
            else:
                record.path.rename(dest)
                finding["fixed"] = True
                finding["from"] = record.relative
                finding["path"] = dest.relative_to(root).as_posix()
        findings.append(finding)
    return findings


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
    records = [_load_record(target, path) for path in _object_files(target)]
    findings: list[dict[str, object]] = []
    if LintCheck.metadata in selected:
        findings.extend(_metadata_findings(records))
    if LintCheck.placeholders in selected:
        findings.extend(_placeholder_findings(records))
    if LintCheck.filenames in selected:
        findings.extend(_filename_findings(target, records, fix=fix))
        _rewrite_renamed_paths(findings)
    logger.debug(
        "lint_complete",
        path=str(target),
        checks=[item.value for item in selected],
        findings=len(findings),
        fix=fix,
    )
    if findings and strict:
        status = "failed"
    elif findings:
        status = "issues"
    else:
        status = "completed"
    renamable = sum(
        1 for item in findings if item.get("expected") and item.get("fixed") is not True
    )
    result: dict[str, Any] = {
        "message": ("Catalogue lint found issues" if findings else "Catalogue lint passed"),
        "path": str(target),
        "checks": [item.value for item in selected],
        "findings": findings,
        "count": len(findings),
        "fixed": sum(1 for item in findings if item.get("fixed") is True),
        "status": status,
        "_exit_code": 1 if status == "failed" else 0,
    }
    if renamable:
        result["_next_actions"] = [
            NextAction("opentide lint --fix", f"rename {renamable} file(s) to match their names")
        ]
    return result


def render_findings(findings: list[dict[str, object]]) -> None:
    """Print one line per finding for the human view, ahead of the summary line."""
    console = get_stdout_console()
    for finding in findings:
        renamed = f" (renamed from {finding['from']})" if finding.get("fixed") is True else ""
        line = finding.get("yaml_line")
        where = f"{finding['path']}:{line + 1}" if isinstance(line, int) else finding["path"]
        if isinstance(line, int) and isinstance(finding.get("column"), int):
            where = f"{where}:{finding['column']}"
        console.print(
            f"[{finding['check']}/{finding['severity']}] {where}: {finding['message']}{renamed}",
            markup=False,
            soft_wrap=True,
        )
        if finding.get("help"):
            console.print(f"  help: {finding['help']}", markup=False, soft_wrap=True)
