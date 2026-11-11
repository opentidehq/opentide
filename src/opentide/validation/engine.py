"""``validate``'s Rust implementation for the SDK and the MCP server (#822).

:func:`opentide.validation.session.run_validation` and the MCP validation
tools run ``validate`` on the engine ``OPENTIDE_ENGINE`` selects for it
(:mod:`opentide.cli.engine_defaults`): Python by default, ``rust`` for the
Rust workspace (``opentide-workspace`` through ``opentide._native``), or
``compare``, shadow mode: both run, the Python result is returned, and a
difference is logged and written to a diff report (:func:`compared`).
The Rust report comes back as the JSON ``validate --json`` writes;
:func:`report_from` reads it into the Python
:class:`~opentide.validation.issues.ValidationReport`, the compatibility
layer until the public models switch (#837).
"""

from __future__ import annotations

import json
import os
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentide.cli.engine_defaults import PYTHON, RUST, selected
from opentide.validation.issues import ValidationIssue, ValidationReport

COMPARE = "compare"
#: The engines the SDK and MCP accept.
ENGINES = (PYTHON, RUST, COMPARE)
#: The command whose result these surfaces return.
VALIDATE = ("validate",)
#: ``failure.code`` of a comparison that found a difference, as the CLI's.
ENGINE_MISMATCH = "engine_mismatch"

#: Report statistics that differ between any two runs, or between the
#: implementations by design (threads): never compared.
_UNCOMPARED_STATS = frozenset({"wall_ms", "parallel", "workers", "object_workers", "id_workers"})


class EngineSelectionError(ValueError):
    """``OPENTIDE_ENGINE`` names no engine."""

    code = "usage_invalid_choice"


class RustValidationError(RuntimeError):
    """The Rust run stopped before it validated (the configuration does not resolve)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validation_engine(env: Mapping[str, str] | None = None) -> str:
    """The engine that runs ``validate`` for the SDK and MCP now.

    Raises :class:`EngineSelectionError` when ``OPENTIDE_ENGINE`` names none.
    """
    engine = selected(VALIDATE, os.environ if env is None else env)
    if engine not in ENGINES:
        raise EngineSelectionError(
            f"OPENTIDE_ENGINE={engine} is not an engine. Choose {', '.join(ENGINES)}."
        )
    return engine


@dataclass(frozen=True)
class RustRequest:
    """What a Rust ``validate`` run reads: ``validate``'s options."""

    check: str | None = None
    files: tuple[str, ...] = ()
    uuids: tuple[str, ...] = ()
    types: tuple[str, ...] = ()
    queries: str = "error"
    strict: bool = False
    repo: str | None = None
    cwd: Path = field(default_factory=Path.cwd)
    env: Mapping[str, str] | None = None


def run_rust(request: RustRequest) -> dict[str, Any]:
    """``validate`` on the Rust workspace: ``{report, checks, summary, failed}``.

    Raises :class:`opentide.analysis.EngineUnavailableError` without the
    engine, :class:`RustValidationError` when the run stopped.
    """
    from opentide.analysis import engine

    text = engine().validate_report(
        str(request.cwd),
        dict(os.environ if request.env is None else request.env),
        repo=request.repo,
        check=request.check,
        files=list(request.files),
        uuids=list(request.uuids),
        types=list(request.types),
        queries=request.queries,
        strict=request.strict,
    )
    result = json.loads(text)
    error = result.get("error")
    if isinstance(error, dict):
        raise RustValidationError(str(error.get("code")), str(error.get("message")))
    return result


def report_from(report: Mapping[str, Any]) -> ValidationReport:
    """The Rust report (``validate --json``'s ``report``) as the Python model.

    Each issue keeps the fields the model has; the presentation fields the
    CLI adds (``path``, ``line``, ``help``, ``fix``, ``explain``) are left to
    whoever annotates it, as for a Python report.
    """
    fields = set(ValidationIssue.model_fields)

    def issue(entry: Mapping[str, Any]) -> ValidationIssue:
        values = {key: value for key, value in entry.items() if key in fields}
        values["field_path"] = tuple(values.get("field_path") or ())
        return ValidationIssue.model_validate(values)

    return ValidationReport(
        ok=bool(report.get("ok")),
        issues=[issue(entry) for entry in report.get("issues", [])],
        warnings=[issue(entry) for entry in report.get("warnings", [])],
        stats=dict(report.get("stats") or {}),
    )


def differences(python: ValidationReport, rust: ValidationReport) -> list[str]:
    """What differs between the two reports, one line each; empty when they agree.

    Each issue or warning only one side reported is one line; when both
    reported the same ones, a different order is one. Of the statistics,
    what the run read (``objects_checked``, ``queries_checked``) is
    compared, not its timing or threads.
    """
    out: list[str] = []
    left = python.model_dump_json_ready()
    right = rust.model_dump_json_ready()
    if left["ok"] != right["ok"]:
        out.append(f"ok: python {left['ok']}, rust {right['ok']}")
    for bucket in ("issues", "warnings"):
        ours = [_text(entry) for entry in left.get(bucket, [])]
        theirs = [_text(entry) for entry in right.get(bucket, [])]
        only_python = Counter(ours) - Counter(theirs)
        only_rust = Counter(theirs) - Counter(ours)
        out.extend(f"{bucket}: only python: {entry}" for entry in only_python.elements())
        out.extend(f"{bucket}: only rust: {entry}" for entry in only_rust.elements())
        if not only_python and not only_rust and ours != theirs:
            out.append(f"{bucket}: the same entries in another order")
    stats = {
        key
        for key in {*left.get("stats", {}), *right.get("stats", {})}
        if key not in _UNCOMPARED_STATS
    }
    for key in sorted(stats):
        one, other = left["stats"].get(key), right["stats"].get(key)
        if one != other:
            out.append(f"stats.{key}: python {one}, rust {other}")
    return out


def _text(entry: Any) -> str:
    return json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)


def compared(
    python: ValidationReport, rust: ValidationReport, *, surface: str, workspace: Path | None
) -> ValidationReport:
    """*python*, after comparing *rust* with it: shadow mode for the SDK and MCP.

    A difference does not fail the call (an agent's tool call, a script's
    validation): it is logged as a warning, ``engine_mismatch``, with the
    path of a diff report written where the CLI's ``compare`` writes its
    reports. Some differences are approved (``tests/golden/APPROVED_DIFFS.toml``,
    the YAML 1.2 rules); the report lists every one.
    """
    _record(surface, differences(python, rust), workspace)
    return python


def shadowed(
    python: ValidationReport,
    rust: Callable[[], Mapping[str, Any]],
    *,
    surface: str,
    workspace: Path | None,
) -> ValidationReport:
    """*python*, after running *rust* (:func:`run_rust`) and comparing: ``compare``.

    The Rust half never fails the call: a run that raises (no engine, a
    configuration it does not resolve, a defect) is a difference, logged
    and written to the diff report as one line, and *python* is returned,
    as :func:`compared` returns it for a report that differs.
    """
    try:
        candidate = report_from(rust()["report"])
    except Exception as exc:  # shadow mode: the Python result stands, the failure is recorded
        code = getattr(exc, "code", None) or type(exc).__name__
        _record(surface, [f"rust: failed: {code}: {exc}"], workspace)
        return python
    return compared(python, candidate, surface=surface, workspace=workspace)


def _record(surface: str, found: Sequence[str], workspace: Path | None) -> None:
    """Log *found* as ``engine_mismatch`` and write its diff report; nothing when empty."""
    if not found:
        return
    from opentide.core.logging import get_logger

    written = write_report(surface, found, workspace)
    get_logger(__name__).warning(
        ENGINE_MISMATCH, surface=surface, differences=len(found), report=written
    )


def current_workspace() -> Path | None:
    """The workspace a diff report redacts, or ``None`` when none is found."""
    from opentide.registry.discovery import discover_workspace

    try:
        return discover_workspace()
    except Exception:  # a report is still worth writing
        return None


def _placeheld(line: str, workspace: Path | None) -> str:
    """*line* with the workspace's path read as ``<WS>``, as the CLI's reports have it."""
    if workspace is None:
        return line
    for form in sorted({str(workspace), str(workspace.resolve())}, key=len, reverse=True):
        line = line.replace(form, "<WS>")
    return line


def write_report(surface: str, found: Sequence[str], workspace: Path | None) -> str:
    """Write the differences, redacted, to the CLI's compare reports; the path, or why not."""
    from datetime import datetime, timezone

    from opentide.cli.engines import report_dir
    from opentide.cli.ui.crash import workspace_redactor

    redact = workspace_redactor([workspace] if workspace is not None else [])
    now = datetime.now(timezone.utc)
    document = {
        "schema_version": 1,
        "command": "validate",
        "surface": surface,
        "created": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "oracle": PYTHON,
        "candidate": RUST,
        "equal": False,
        "differences": [redact(_placeheld(line, workspace)) for line in found],
    }
    try:
        directory = report_dir()
        for folder in (directory.parent, directory):
            folder.mkdir(parents=True, exist_ok=True, mode=0o700)
            folder.chmod(0o700)
        stamp = f"{now:%Y%m%dT%H%M%S%f}Z"
        for attempt in range(100):
            target = directory / (f"{stamp}.json" if attempt == 0 else f"{stamp}-{attempt}.json")
            try:
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(document, indent=2, ensure_ascii=False) + "\n")
            return str(target)
    except (OSError, RuntimeError) as exc:
        return f"not written ({exc})"
    return "not written (no free name)"


def legacy_string(entry: Mapping[str, Any]) -> str:
    """An issue as ``ValidationIssue.to_legacy_string`` writes it, from its JSON."""
    location = ".".join(str(part) for part in entry.get("field_path") or ())
    message = str(entry.get("message", ""))
    return f"{location}: {message}" if location else message


def default_checks_request(
    checks: Sequence[str] | None, default: Sequence[str], *, queries_as_warnings: bool
) -> tuple[str | None, str] | None:
    """``(check, queries)`` for a run of *checks*: ``--check`` and ``--queries``.

    ``None`` when no ``validate`` command line runs exactly *checks*: the
    defaults, the defaults without ``queries`` (``--queries off``), or one
    check.
    """
    queries = "warn" if queries_as_warnings else "error"
    if checks is None or set(checks) == set(default):
        return None, queries
    if set(checks) == set(default) - {"queries"}:
        return None, "off"
    if len(set(checks)) == 1:
        return next(iter(checks)), queries
    return None
