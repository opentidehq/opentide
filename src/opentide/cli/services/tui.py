"""What ``opentide tui`` shows and runs, without Textual.

The catalogue comes from the registry (:func:`collect_info` reloads it), the
coverage table from the same lookup as ``opentide info --technique … coverage``,
the language server's findings from the engine behind ``opentide lsp check``,
and the actions call the service functions behind ``validate``, ``generate``
and ``deploy --dry-run``, so the terminal UI cannot disagree with the CLI.
Textual is imported only by :mod:`opentide.cli.tui_app`.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal

from opentide.cli.output import CommandResult
from opentide.cli.ui.contract import Failure

if TYPE_CHECKING:
    from opentide.cli.context import CliContext

#: ``failure.code`` when ``opentide tui`` runs where nobody can use it.
USAGE_TUI_NEEDS_TTY = "usage_tui_needs_tty"

ObjectKind = Literal["threat", "objective", "rule"]

#: Index family → kind, in the order the tree nests them.
_FAMILIES: tuple[tuple[str, ObjectKind], ...] = (
    ("threats", "threat"),
    ("objectives", "objective"),
    ("rules", "rule"),
)


@dataclass(frozen=True)
class CatalogueEntry:
    """One object as the tree shows it."""

    uuid: str
    kind: ObjectKind
    name: str
    #: The YAML file the object was read from, when the index knows it.
    path: Path | None
    #: Threats an objective covers; the objective a rule implements.
    parents: tuple[str, ...] = ()


@dataclass(frozen=True)
class TechniqueCoverage:
    """One ATT&CK technique: the rules that detect it and the objects that name it."""

    technique: str
    rules: tuple[str, ...]
    #: Threats and objectives that list the technique.
    referenced_by: tuple[str, ...]


@dataclass(frozen=True)
class LoadError:
    """An object file the indexer could not read."""

    path: Path | None
    message: str


@dataclass(frozen=True)
class LanguageServerReport:
    """What the language server reports for each object file, as an editor shows it."""

    #: Resolved object file → its findings, in file order.
    findings: Mapping[Path, tuple[Diagnostic, ...]] = dataclasses.field(default_factory=dict)
    #: Why the engine did not load, when it did not: nothing was checked.
    unavailable: str | None = None
    #: What to do about it.
    advice: str | None = None

    def for_path(self, path: Path | None) -> tuple[Diagnostic, ...]:
        if path is None:
            return ()
        try:
            return self.findings.get(path.resolve(), ())
        except OSError:
            return ()


@dataclass(frozen=True)
class Catalogue:
    """A snapshot of the workspace. Built off the UI thread, read on it."""

    repo: Path
    entries: Mapping[str, CatalogueEntry]
    coverage: tuple[TechniqueCoverage, ...] = ()
    load_errors: tuple[LoadError, ...] = ()
    language_server: LanguageServerReport = dataclasses.field(default_factory=LanguageServerReport)

    def of_kind(self, kind: ObjectKind) -> list[CatalogueEntry]:
        return sorted(
            (entry for entry in self.entries.values() if entry.kind == kind),
            key=lambda entry: (entry.name.lower(), entry.uuid),
        )

    def children(self, uuid: str) -> list[CatalogueEntry]:
        """Objectives under a threat, rules under an objective."""
        return sorted(
            (entry for entry in self.entries.values() if uuid in entry.parents),
            key=lambda entry: (entry.name.lower(), entry.uuid),
        )

    def unlinked(self, kind: ObjectKind) -> list[CatalogueEntry]:
        """Objects of *kind* whose parent is missing from the catalogue (or that name none)."""
        return [
            entry
            for entry in self.of_kind(kind)
            if not any(parent in self.entries for parent in entry.parents)
        ]

    def count(self, kind: ObjectKind) -> int:
        return sum(1 for entry in self.entries.values() if entry.kind == kind)


def load_catalogue(ctx: CliContext) -> Catalogue:
    """Reload the registry for *ctx*'s workspace and snapshot what the UI shows."""
    from opentide.cli.services.info import _technique_coverage, collect_info
    from opentide.core.index_manager import IndexManager
    from opentide.core.object_fields import object_techniques
    from opentide.core.registry import Opentide

    collect_info(ctx)  # applies the context's environment and reloads the registry
    index = Opentide.Index
    file_paths: Mapping[str, str] = index.get("file_paths") or {}
    families = {family: dict(getattr(Opentide.Models, family)) for family, _ in _FAMILIES}
    signal_owner = _signal_owners(families["objectives"])

    entries: dict[str, CatalogueEntry] = {}
    for family, kind in _FAMILIES:
        for uuid, body in families[family].items():
            path = file_paths.get(uuid)
            entries[uuid] = CatalogueEntry(
                uuid=uuid,
                kind=kind,
                name=_name(body, uuid),
                path=Path(path) if path else None,
                parents=_parents(kind, body, signal_owner),
            )

    referenced: dict[str, set[str]] = {}
    techniques: set[str] = set()
    for family, _kind in _FAMILIES:
        for uuid, body in families[family].items():
            for technique in object_techniques(body):
                key = technique.strip().upper()
                techniques.add(key)
                if family != "rules":
                    referenced.setdefault(key, set()).add(uuid)
    coverage = tuple(
        TechniqueCoverage(
            technique=technique,
            # The lookup behind `opentide info --technique … coverage`: a
            # parent technique also counts the rules on its sub-techniques.
            rules=tuple(_technique_coverage(technique)["rules"]),
            referenced_by=tuple(sorted(referenced.get(technique, ()))),
        )
        for technique in sorted(techniques)
    )

    load_errors = tuple(
        LoadError(
            path=Path(entry["path"]) if entry.get("path") else None,
            message=str(entry.get("message") or entry.get("error") or "could not be read"),
        )
        for entry in IndexManager.load().get("parse_errors") or []
    )
    return Catalogue(
        repo=Path(ctx.repo).resolve(),
        entries=entries,
        coverage=coverage,
        load_errors=load_errors,
        language_server=_language_server_report(),
    )


def _language_server_report() -> LanguageServerReport:
    """:func:`language_server_report`, or why it failed: the tree does not depend on it."""
    try:
        return language_server_report()
    except Exception as exc:
        return LanguageServerReport(
            unavailable=f"The language server failed: {type(exc).__name__}: {exc}",
            advice="opentide lsp check shows the same failure on the command line",
        )


def language_server_report() -> LanguageServerReport:
    """What ``opentide lsp check`` reports for every object file of the workspace.

    The workspace's catalogs are used when ``opentide generate schemas``
    wrote them. A file that cannot be read has no findings here: the
    catalogue lists it under the files that failed to load.
    """
    from opentide.analysis import (
        EngineUnavailableError,
        check_file,
        install_workspace_catalog,
        object_files,
        workspace,
    )
    from opentide.cli.ui.diagnostics import diagnostic_from_engine
    from opentide.registry.discovery import discover_workspace

    root = discover_workspace()
    findings: dict[Path, tuple[Diagnostic, ...]] = {}
    try:
        install_workspace_catalog(root)
        objects = object_files(root)
        space = workspace(root, objects)
        for path in objects:
            try:
                text = path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            found = [
                diagnostic_from_engine(finding, file_path=path, workspace=root)
                for finding in check_file(space, path, text)
            ]
            findings[path.resolve()] = tuple(
                Diagnostic(
                    code=item.code,
                    severity=item.severity,
                    message=item.message,
                    path=path,
                    line=item.line,
                    column=item.column,
                    end_column=item.end_column,
                    field_path=tuple(item.field_path),
                    help=item.help,
                    source=LANGUAGE_SERVER,
                )
                for item in found
            )
    except EngineUnavailableError as exc:
        return LanguageServerReport(unavailable=str(exc), advice=exc.advice)
    return LanguageServerReport(findings=findings)


def _name(body: Mapping[str, Any], uuid: str) -> str:
    from opentide.core.object_refs import object_name

    try:
        return object_name(body)
    except KeyError:
        return uuid


def _uuids(value: Any) -> tuple[str, ...]:
    """A reference field as UUIDs: ``detection_model`` may be a string or a list."""
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str) and item)
    return ()


def _signal_owners(objectives: Mapping[str, Any]) -> dict[str, str]:
    """Signal UUID → the objective that declares it, so a rule on a signal nests under it."""
    owners: dict[str, str] = {}
    for uuid, body in objectives.items():
        for signal in (body.get("objective") or {}).get("signals") or []:
            if isinstance(signal, Mapping) and signal.get("uuid"):
                owners[str(signal["uuid"])] = uuid
    return owners


def _parents(
    kind: ObjectKind, body: Mapping[str, Any], signal_owner: Mapping[str, str]
) -> tuple[str, ...]:
    if kind == "objective":
        return _uuids((body.get("objective") or {}).get("threats"))
    if kind == "rule":
        return tuple(
            dict.fromkeys(signal_owner.get(ref, ref) for ref in _uuids(body.get("detection_model")))
        )
    return ()


#: Codes whose ``suggestion`` is the value to write instead: an object UUID or
#: a vocabulary entry. Every other code's suggestion is prose.
VALUE_SUGGESTION_CODES = frozenset({"invalid_ref", "vocab_unknown", "chaining_relation_unknown"})


#: :attr:`Diagnostic.source` of a finding from a validate run.
VALIDATE = "validate"
#: :attr:`Diagnostic.source` of a finding from the language server.
LANGUAGE_SERVER = "language server"
#: :attr:`Diagnostic.source` of a validate finding the engine made: ``validate
#: --deep``'s query findings, which the language server reports too.
ENGINE = "engine"


@dataclass(frozen=True)
class Diagnostic:
    """A finding as the detail pane shows it. ``line`` and ``column`` are 1-based."""

    code: str
    severity: str
    message: str
    object_uuid: str = ""
    path: Path | None = None
    line: int | None = None
    field_path: tuple[str, ...] = ()
    help: str | None = None
    column: int | None = None
    #: Exclusive, on ``line``.
    end_column: int | None = None
    #: Who reported it: :data:`VALIDATE`, :data:`ENGINE` or :data:`LANGUAGE_SERVER`.
    source: str = VALIDATE

    @classmethod
    def from_issue(cls, issue: Mapping[str, Any]) -> Diagnostic:
        """From one entry of ``report.issues`` or ``report.warnings`` in the validate payload."""
        yaml_line = issue.get("yaml_line")
        file_path = issue.get("file_path")
        context = issue.get("context") or {}
        position = context.get("position") or {}
        column = position.get("column")
        end_column = (
            position.get("end_column") if position.get("end_line") == position.get("line") else None
        )
        return cls(
            code=str(issue.get("code") or "invalid"),
            severity=str(issue.get("severity") or "error"),
            message=str(issue.get("message") or ""),
            object_uuid=str(issue.get("object_uuid") or ""),
            path=Path(file_path) if file_path else None,
            line=None if yaml_line is None else int(yaml_line) + 1,
            field_path=tuple(str(part) for part in issue.get("field_path") or ()),
            help=issue.get("suggestion") or None,
            column=None if column is None else int(column),
            end_column=None if end_column is None else int(end_column),
            source=ENGINE if context.get("source") == "engine" else VALIDATE,
        )

    def help_text(self) -> str | None:
        """``did you mean 'clear'?`` when the suggestion is a value, else the suggestion as written.

        Most codes suggest the value to write instead of the wrong one; others
        (``invalid_cve``, the external-id codes) carry a sentence of advice.
        """
        if not self.help:
            return None
        if self.source == VALIDATE and self.code in VALUE_SUGGESTION_CODES:
            return f"did you mean {self.help!r}?"
        return self.help

    def concerns(self, entry: CatalogueEntry) -> bool:
        """Whether this diagnostic is about *entry*: by UUID, else by file."""
        if self.object_uuid:
            return self.object_uuid == entry.uuid
        return _same_file(self.path, entry.path)


def _same_file(left: Path | None, right: Path | None) -> bool:
    if left is None or right is None:
        return False
    try:
        return left.resolve() == right.resolve()
    except OSError:
        return left == right


def diagnostics_from(payload: Mapping[str, Any]) -> tuple[Diagnostic, ...]:
    """The issues, then the warnings, of a ``validate`` payload."""
    report = payload.get("report") or {}
    items: Iterable[Mapping[str, Any]] = [
        *(report.get("issues") or ()),
        *(report.get("warnings") or ()),
    ]
    return tuple(Diagnostic.from_issue(item) for item in items)


@dataclass(frozen=True)
class Action:
    """A command the TUI runs in-process, through the service the CLI calls."""

    name: str
    #: What a person would type for the same result.
    command: str
    help: str
    run: Callable[[CliContext], dict[str, Any]]
    default_message: str = "Completed successfully"

    @property
    def validates(self) -> bool:
        """Whether it is a validate run, whose findings the detail pane shows."""
        return self.name in VALIDATE_ACTIONS


def _validate(ctx: CliContext) -> dict[str, Any]:
    from opentide.cli.services.validation import run_validate

    return dict(run_validate(ctx))


def _validate_deep(ctx: CliContext) -> dict[str, Any]:
    from opentide.cli.services.validation import run_validate

    return dict(run_validate(ctx, deep=True))


def _generate(ctx: CliContext) -> dict[str, Any]:
    from opentide.cli.services.generation import run_generate

    return dict(run_generate(ctx))


def _deploy_dry_run(strategy: str) -> Callable[[CliContext], dict[str, Any]]:
    def run(ctx: CliContext) -> dict[str, Any]:
        from opentide.cli.services.deploy import run_deploy

        return dict(run_deploy(ctx, strategies=(strategy,), all_files=True, dry_run=True))

    return run


#: The actions that are validate runs.
VALIDATE_ACTIONS = frozenset({"validate", "validate-deep"})

ACTIONS: tuple[Action, ...] = (
    Action(
        "validate",
        "opentide validate",
        "Validate every object: schema, UUIDs and uniqueness",
        _validate,
        default_message="Validation passed",
    ),
    Action(
        "validate-deep",
        "opentide validate --deep",
        "Validate every object, and check every rule's query offline with the analysis engine",
        _validate_deep,
        default_message="Validation passed",
    ),
    Action(
        "generate",
        "opentide generate",
        "Run the full generation pipeline: "
        "docs, exports, vocabularies, templates, schemas, snippets",
        _generate,
    ),
    Action(
        "deploy-preview",
        "opentide deploy --dry-run --strategy PREVIEW --all",
        "Show what a PREVIEW deploy of every rule file would send, without calling a platform",
        _deploy_dry_run("PREVIEW"),
        default_message="Deployment completed",
    ),
    Action(
        "deploy-release",
        "opentide deploy --dry-run --strategy RELEASE --all",
        "Show what a RELEASE deploy of every rule file would send, without calling a platform",
        _deploy_dry_run("RELEASE"),
        default_message="Deployment completed",
    ),
)

ACTIONS_BY_NAME: Mapping[str, Action] = {action.name: action for action in ACTIONS}


@dataclass(frozen=True)
class ActionOutcome:
    """What one action returned, ready for the renderers."""

    action: Action
    result: CommandResult
    diagnostics: tuple[Diagnostic, ...] = ()
    #: The findings as ``validate`` prints them (#641's code frames).
    frames: tuple[Any, ...] = ()
    #: A dry run's payload, for #643's plan view and compile diagnostics.
    plan: Mapping[str, Any] | None = None


def run_action(ctx: CliContext, action: Action) -> ActionOutcome:
    """Run *action* the way its command would, and never raise.

    The services see a context with ``json_output`` set, so they return their
    payload and print nothing: the TUI owns the terminal and renders the
    result itself. An unexpected exception becomes an ``internal`` failure,
    as the CLI reports it.
    """
    import time

    quiet = dataclasses.replace(ctx, json_output=True)
    started = time.monotonic()
    try:
        payload = action.run(quiet)
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"
        result = CommandResult(
            message=message,
            ok=False,
            status="failed",
            data={"error": message},
            exit_code=1,
            failure=Failure(code="internal", message=message),
        )
        return ActionOutcome(action=action, result=result)
    frames = tuple(payload.pop("_diagnostics", None) or ())
    plan = dict(payload) if action.name.startswith("deploy") else None
    result = CommandResult.from_payload(payload, default_message=action.default_message)
    # The services ran with json_output set, so their next steps read
    # ``opentide --json …``; a person at the UI is shown the human command.
    result = dataclasses.replace(
        result,
        next_actions=tuple(
            dataclasses.replace(item, command=_human_command(item.command))
            for item in result.next_actions
        ),
    )
    if not action.validates:
        return ActionOutcome(action=action, result=result, plan=plan)
    from opentide.cli.services.validation import validate_outcome_line

    # As ``opentide validate`` prints it: the counted line, and the frames
    # instead of a warning line per finding.
    line = result.message
    if not line.startswith("Validation passed, but"):
        seconds = time.monotonic() - started
        line = validate_outcome_line(result.summary, failed=not result.ok, seconds=seconds)
    return ActionOutcome(
        action=action,
        result=dataclasses.replace(result, outcome=line, warnings=()),
        diagnostics=diagnostics_from(payload),
        frames=frames,
    )


def _human_command(command: str) -> str:
    """``opentide --json validate`` → ``opentide validate``."""
    prefix = "opentide --json "
    return "opentide " + command[len(prefix) :] if command.startswith(prefix) else command


def relative(path: Path | None, root: Path) -> str:
    """*path* relative to *root* when inside it, for display."""
    if path is None:
        return ""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return str(path)


def plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def summary_line(catalogue: Catalogue) -> str:
    """``1 threat · 1 objective · 1 rule``, plus load errors when there are any."""
    parts: Sequence[str] = [
        plural(catalogue.count("threat"), "threat"),
        plural(catalogue.count("objective"), "objective"),
        plural(catalogue.count("rule"), "rule"),
    ]
    if catalogue.load_errors:
        parts = [*parts, plural(len(catalogue.load_errors), "load error")]
    return " · ".join(parts)
