"""Catalogue hygiene checks for ``opentide lint``."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import structlog
import yaml

from opentide.cli.enums import LintCheck
from opentide.cli.ui.contract import ISSUES_FOUND, NO_WORKSPACE_STEP, NextAction
from opentide.cli.ui.diagnostics import (
    LINT_CODES,
    Diagnostic,
    SourceFiles,
    annotate,
    diagnostic_from_lint_finding,
    lint_severity,
)
from opentide.cli.ui.glyphs import glyph
from opentide.core.errors import UserFileError
from opentide.core.io import (
    describe_yaml_error,
    not_utf8_problem,
    parse_yaml,
    root_mapping_problem,
)
from opentide.core.lint_config import LintConfig, Severity, load_lint_config
from opentide.documentation.markdown.links import slugify
from opentide.registry.catalogue import NESTED_OBJECT_FILE, nested_file_message, scan_object_dir

if TYPE_CHECKING:
    from opentide.analysis import Finding

logger = structlog.get_logger("opentide.cli.services.lint")

_OBJECT_FAMILIES = ("threats", "objectives", "rules")


@dataclass
class _ObjectRecord:
    path: Path
    relative: str
    name: str | None = None
    uuid: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    parse_error: str | None = None
    #: 1-based position of the YAML error, when the parser gives one.
    parse_position: tuple[int, int] | None = None
    expected_stem: str | None = None
    key_lines: dict[str, int] = field(default_factory=dict)
    #: Each value ``opentide new`` marked as a placeholder.
    placeholder_lines: list[_Marked] = field(default_factory=list)
    #: The file's text, for the queries check; ``None`` when it was not read.
    text: str | None = None


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
    except UnicodeDecodeError as exc:
        record.parse_error = not_utf8_problem(exc)
        return record
    except OSError as exc:
        record.parse_error = str(exc)
        return record
    record.text = text
    record.key_lines = _top_level_key_lines(text)
    record.placeholder_lines = _placeholder_lines(text)
    if (problem := root_mapping_problem(data)) is not None:
        # The same words validate uses: "expected a mapping at the top of the
        # file, found an empty file".
        record.parse_error = problem
        return record
    record.name = _as_str(data.get("name"))
    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        record.metadata = metadata
        record.uuid = _as_str(metadata.get("uuid"))
    return record


def _has_metadata(record: _ObjectRecord, key: str) -> bool:
    """True when ``metadata.<key>`` holds a value an author filled in."""
    if key == "organisation":
        metadata = record.metadata
        return bool(
            _organisation_name(metadata.get("organisation"))
            or _organisation_name(metadata.get("organization"))
        )
    value = record.metadata.get(key)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict)):
        return bool(value)
    return True


@cache
def _schema_metadata_keys(schema_id: str) -> frozenset[str] | None:
    """YAML keys the ``metadata`` block of *schema_id* accepts, or ``None`` if unknown."""
    from pydantic import BaseModel

    from opentide.models.schema_registry import is_registered, resolve_model

    if not is_registered(schema_id):
        return None
    field_info = resolve_model(schema_id).model_fields.get("metadata")
    model = field_info.annotation if field_info is not None else None
    if not (isinstance(model, type) and issubclass(model, BaseModel)):
        return None
    return frozenset(info.alias or name for name, info in model.model_fields.items())


def _required_for(record: _ObjectRecord, required: tuple[str, ...]) -> list[str]:
    """*required* minus keys the object's schema forbids (``reviewed`` on a threat)."""
    schema_id = _as_str(record.metadata.get("schema"))
    accepted = _schema_metadata_keys(schema_id) if schema_id else None
    if accepted is None:
        return list(required)
    return [key for key in required if key in accepted]


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


def _metadata_findings(
    records: list[_ObjectRecord], required: tuple[str, ...]
) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    if not required:
        return findings
    for record in records:
        if record.parse_error or not record.name:
            continue
        missing = [key for key in _required_for(record, required) if not _has_metadata(record, key)]
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


def _query_findings(root: Path, records: list[_ObjectRecord]) -> list[dict[str, object]]:
    """The engine's style findings on each object: query warnings and notes, Elastic advisories.

    A query the engine rejects (an error) is ``opentide validate``'s finding,
    and the engine's object checks are validate's and lint's other checks'.
    A placeholder query is the ``placeholders`` check's.
    Raises :class:`~opentide.analysis.EngineUnavailableError`.
    """
    from opentide.analysis import ELASTIC_ADVISORY_CODES, check_file, workspace
    from opentide.cli.ui.diagnostics import diagnostic_from_engine, engine_reference

    space = workspace(root)
    findings: list[dict[str, object]] = []
    for record in records:
        if record.parse_error or record.text is None:
            continue
        lines = record.text.splitlines()
        marked = {marked.line + 1 for marked in record.placeholder_lines}
        for finding in check_file(space, record.path, record.text):
            if finding.severity == "error" or _in_placeholder(finding, lines, marked):
                continue
            if (
                engine_reference(finding.code) is None
                and finding.code not in ELASTIC_ADVISORY_CODES
            ):
                continue
            findings.append(
                {
                    "check": LintCheck.queries.value,
                    "severity": "warning" if finding.severity == "warning" else "info",
                    "path": record.relative,
                    "yaml_line": finding.line - 1,
                    "uuid": record.uuid,
                    "message": finding.message,
                    "_code": finding.code,
                    "_field_path": list(finding.field_path),
                    "_diagnostic": diagnostic_from_engine(
                        finding, file_path=record.path, workspace=root
                    ),
                }
            )
    return findings


def _in_placeholder(finding: Finding, lines: list[str], marked: set[int]) -> bool:
    """Whether *finding* is in a ``...`` stand-in under a marked key (1-based *marked* lines)."""
    from opentide.validation.queries import is_stand_in

    line = finding.line
    if not (line in marked or line - 1 in marked) or not 0 < line <= len(lines):
        return False
    text = lines[line - 1]
    if line in marked:  # inline, `query: ...  # opentide:placeholder`: the value after the key
        text = text.split(":", 1)[-1]
    return is_stand_in(text.lstrip())


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


def _apply_severity(findings: list[dict[str, object]], config: LintConfig) -> None:
    """Replace each finding's severity with its check's configured one, if any."""
    for finding in findings:
        override = config.check(str(finding["check"])).severity
        if override is not None:
            finding["severity"] = override


def run_lint(
    root: Path,
    *,
    checks: list[LintCheck] | None = None,
    fix: bool = False,
    strict: bool = False,
    config: LintConfig | None = None,
) -> dict[str, object]:
    """Run catalogue hygiene checks without a full registry rebuild.

    *config* defaults to the workspace's resolved ``lint.toml``. *checks* (the
    CLI's ``--check``) wins over it: a named check runs even when disabled there.
    """
    target = root.resolve()
    if config is None:
        try:
            config = load_lint_config(target)
        except UserFileError:  # unparsable TOML: the CLI frames it at the file
            raise
        except ValueError as exc:  # LintConfigError, retired keys
            return {
                "message": str(exc),
                "path": str(target),
                "checks": [],
                "findings": [],
                "count": 0,
                "fixed": 0,
                "status": "failed",
                "_exit_code": 2,
            }
    selected = list(checks) if checks else [LintCheck(name) for name in config.enabled_checks()]
    object_files, nested = _object_files(target)
    records = [_load_record(target, path) for path in object_files]
    findings: list[dict[str, object]] = []
    if LintCheck.metadata in selected:
        findings.extend(_metadata_findings(records, config.required_metadata))
    if LintCheck.placeholders in selected:
        findings.extend(_placeholder_findings(records))
    if LintCheck.queries in selected:
        from opentide.analysis import EngineUnavailableError

        try:
            findings.extend(_query_findings(target, records))
        except EngineUnavailableError as exc:
            from opentide.cli.services.engine import engine_unavailable_result

            return engine_unavailable_result(
                exc, path=str(target), checks=[item.value for item in selected], findings=[]
            )
    if LintCheck.filenames in selected:
        findings.extend(_filename_findings(target, records, fix=fix))
        _rewrite_renamed_paths(findings)
        findings.extend(_nested_findings(target, nested))
    _apply_severity(findings, config)
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
    elif left and all(item.get("severity") == "info" for item in left):
        # Notes only: nothing to warn about, so the line takes ✓, not the ``!``
        # of a warning (post-merge end-to-end run). JSON status stays "issues".
        result["_outcome_kind"] = "ok"
    if not files:
        from opentide.core.root import is_workspace_root

        if not is_workspace_root(target):
            result["_next_actions"] = [NO_WORKSPACE_STEP]
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
        engine = finding.pop("_diagnostic", None)
        if isinstance(engine, Diagnostic):
            # The engine framed it; the severity is lint's, after lint.toml.
            severity = lint_severity(str(finding["severity"]))
            annotate(finding, replace(engine, severity=severity))
            continue
        annotate(finding, diagnostic_from_lint_finding(finding, root=root, sources=sources))


def _plural(count: int, noun: str) -> str:
    return f"{count} {noun}" if count == 1 else f"{count} {noun}s"


def _shown(root: Path) -> str:
    """*root* as validate shows it: ``./`` or ``./sub`` from inside, ``..`` above, else absolute."""
    import os

    cwd = Path.cwd().resolve()
    target = root.resolve()
    if target == cwd:
        return "./"
    if target.is_relative_to(cwd):
        return f"./{target.relative_to(cwd).as_posix()}"
    if cwd.is_relative_to(target):
        return os.path.relpath(target, cwd) + "/"
    return target.as_posix()


def _outcome_line(left: list[dict[str, object]], *, files: int, fixed: int, root: Path) -> str:
    """``3 files clean`` or ``3 findings in 2 files · 1 warning, 2 notes · 1 fixed``.

    *left* are the findings ``--fix`` did not fix; *fixed* counts the others.
    The severities are split only when more than one kind is left.
    """
    sep = f" {glyph('separator')} "
    done = f"{sep}{fixed} fixed" if fixed else ""
    if not left:
        if not files:
            return f"Catalogue lint passed, but found no object files under {_shown(root)}"
        return f"{_plural(files, 'file')} clean{done}"
    touched = len({str(item.get("path")) for item in left})
    noun = "note" if all(item.get("severity") == "info" for item in left) else "finding"
    line = f"{_plural(len(left), noun)} in {_plural(touched, 'file')}"
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
