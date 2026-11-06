"""What telemetry a repository declares, and which detections use it (#776, explorer#85).

``.opentide/configurations/visibility.toml`` declares each log source: its
``name`` is the dataset (a KQL table, a Splunk sourcetype, an Elastic index
pattern), with its ``system``, description and, when known, its columns. This
module joins it with the catalogue:

- **Signals:** an objective's signal names log sources in ``data.logsources``;
  the objective uses them, and so does each rule implementing that signal, or
  the objective as a whole.
- **Queries:** the datasets each rule's queries read, as the analysis engine
  reads them. Declaring is opt-in per system: once a system declares one log
  source, the engine reports every dataset a query of that system reads that
  none names (``kql_table_not_declared``, ``spl_dataset_not_declared``,
  ``elastic_dataset_not_declared``). Analysing each query with a visibility
  that declares only a placeholder for every system makes it name them all,
  so the datasets come from the engine's own parsing, never from a second
  parser here.

The TUI's Visibility tab and ``opentide generate explorer --include-visibility``
show the same report. A telemetry inventory says what an organisation cannot
see, so the explorer export is off unless asked for.
"""

from __future__ import annotations

import contextlib
import fnmatch
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from opentide.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "Column",
    "DatasetRead",
    "LogSource",
    "Undeclared",
    "VisibilityReport",
    "collect_visibility",
]

#: The engine's findings for a dataset a query reads that no log source names.
UNDECLARED_CODES = frozenset(
    {"kql_table_not_declared", "spl_dataset_not_declared", "elastic_dataset_not_declared"}
)
#: The systems whose log source names declare datasets to the query checks.
DATASET_SYSTEMS = ("sentinel", "defender_for_endpoint", "splunk", "elastic")
#: A dataset name no query reads: declaring it per system opts every system in.
_PROBE = "__opentide_visibility_probe__"
#: The dataset a finding names: quoted ``'X'`` for KQL, `` `X` `` for SPL and Elastic.
_QUOTED = re.compile(r"'([^']+)'|`([^`]+)`")


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    description: str = ""


@dataclass(frozen=True)
class DatasetRead:
    """One dataset a rule's query reads."""

    rule: str
    #: The ``configurations`` key the query is under (``sentinel``).
    system: str
    name: str
    #: The query's field path (``configurations.sentinel.query``).
    field_path: str


@dataclass(frozen=True)
class LogSource:
    """One declared log source, and what uses it."""

    name: str
    system: str
    description: str
    columns: tuple[Column, ...] = ()
    tenants: tuple[str, ...] = ()
    #: Rules whose queries read it (its name, or a dataset its pattern covers).
    read_by: tuple[str, ...] = ()
    #: Objectives one of whose signals names it.
    objectives: tuple[str, ...] = ()
    #: ``(objective, signal UUID, signal name)`` for each signal that names it.
    signals: tuple[tuple[str, str, str], ...] = ()
    #: Rules that implement such a signal, or its objective.
    signal_rules: tuple[str, ...] = ()

    @property
    def rules(self) -> tuple[str, ...]:
        """Every rule that uses it, by its query or through a signal."""
        return tuple(dict.fromkeys((*self.read_by, *self.signal_rules)))

    @property
    def used(self) -> bool:
        return bool(self.rules or self.objectives)


@dataclass(frozen=True)
class Undeclared:
    """A dataset rules read that no log source of its system declares."""

    system: str
    name: str
    rules: tuple[str, ...]
    #: Whether the workspace declares any log source for the system: only then
    #: does the engine warn about it (``kql_table_not_declared`` and the rest).
    system_declares: bool


@dataclass(frozen=True)
class VisibilityReport:
    """The whole picture: declared log sources, what uses them, and what is missing."""

    logsources: tuple[LogSource, ...] = ()
    undeclared: tuple[Undeclared, ...] = ()
    #: Signal ``data.logsources`` names no log source declares: ``(name, objectives)``.
    unknown_signal_sources: tuple[tuple[str, tuple[str, ...]], ...] = ()
    reads: tuple[DatasetRead, ...] = ()
    #: Why the datasets queries read are not known (the engine did not load).
    reads_unavailable: str | None = None
    #: Why ``visibility.toml`` could not be read, when it could not.
    problem: str | None = None
    #: Whether the workspace has a ``visibility.toml`` at all.
    present: bool = False
    systems: Mapping[str, Mapping[str, int]] = field(default_factory=dict)

    def find(self, system: str, name: str) -> LogSource | None:
        for source in self.logsources:
            if source.system == system and source.name == name:
                return source
        return None

    def to_dict(self) -> dict[str, Any]:
        """The report as JSON-ready data (the explorer export)."""
        return {
            "present": self.present,
            "problem": self.problem,
            "reads_unavailable": self.reads_unavailable,
            "systems": {name: dict(counts) for name, counts in self.systems.items()},
            "logsources": [
                {
                    "name": source.name,
                    "system": source.system,
                    "description": source.description,
                    "tenants": list(source.tenants),
                    "columns": [
                        {"name": c.name, "type": c.type, "description": c.description}
                        for c in source.columns
                    ],
                    "read_by": list(source.read_by),
                    "objectives": list(source.objectives),
                    "signals": [
                        {"objective": objective, "uuid": uuid, "name": name}
                        for objective, uuid, name in source.signals
                    ],
                    "signal_rules": list(source.signal_rules),
                    "rules": list(source.rules),
                }
                for source in self.logsources
            ],
            "undeclared": [
                {
                    "system": item.system,
                    "name": item.name,
                    "rules": list(item.rules),
                    "system_declares": item.system_declares,
                }
                for item in self.undeclared
            ],
            "unknown_signal_sources": [
                {"name": name, "objectives": list(objectives)}
                for name, objectives in self.unknown_signal_sources
            ],
            "reads": [
                {
                    "rule": read.rule,
                    "system": read.system,
                    "name": read.name,
                    "field_path": read.field_path,
                }
                for read in self.reads
            ],
        }


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _declared(raw: Any) -> list[LogSource]:
    sources: list[LogSource] = []
    for entry in raw or ():
        get = (
            entry.get if isinstance(entry, Mapping) else lambda key, e=entry: getattr(e, key, None)
        )
        columns = get("columns") or {}
        sources.append(
            LogSource(
                name=str(get("name") or ""),
                system=str(get("system") or ""),
                description=str(get("description") or ""),
                tenants=tuple(str(t) for t in get("tenants") or ()),
                columns=tuple(
                    Column(
                        name=str(name),
                        type=str(_field(column, "type") or ""),
                        description=str(_field(column, "description") or ""),
                    )
                    for name, column in (columns.items() if isinstance(columns, Mapping) else ())
                ),
            )
        )
    return sources


def _field(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else getattr(value, key, None)


def _covers(declared: str, read: str) -> bool:
    """Whether a log source named *declared* (``*`` a wildcard) holds the dataset *read*."""
    return declared == read or fnmatch.fnmatchcase(read, declared)


def dataset_reads(
    rules: Mapping[str, str], probe_files: Sequence[tuple[str, str]]
) -> list[DatasetRead]:
    """The datasets each rule's queries read, as the engine reads them.

    *rules* maps a rule's UUID to its file's text; *probe_files* are the
    engine workspace's files (the rules, and the Elastic configuration that
    sets the stack its ES|QL is checked against). Installs a placeholder
    visibility while it runs: the caller installs the workspace's again.
    Raises :class:`opentide.analysis.EngineUnavailableError`.
    """
    from opentide.analysis import engine

    module = engine()
    probe = "".join(
        f'[[logsources]]\nname = "{_PROBE}"\ndescription = "probe"\nsystem = "{system}"\n\n'
        for system in DATASET_SYSTEMS
    )
    module.install_visibility(probe)
    workspace = module.Workspace(list(probe_files))
    reads: list[DatasetRead] = []
    for uuid, text in rules.items():
        for report in workspace.analyze_queries(text):
            path = list(report.field_path)
            system = path[1] if len(path) > 1 and path[0] == "configurations" else ""
            for finding in report.diagnostics:
                if finding.code not in UNDECLARED_CODES:
                    continue
                match = _QUOTED.search(finding.message)
                name = (match.group(1) or match.group(2)) if match else ""
                if name and name != _PROBE:
                    reads.append(DatasetRead(uuid, system, name, ".".join(path)))
    return list(dict.fromkeys(reads))


def collect_visibility(
    root: Path | None,
    families: Mapping[str, Mapping[str, Any]],
    rule_files: Mapping[str, Path],
    logsources: Iterable[Any] | None,
    *,
    problem: str | None = None,
) -> VisibilityReport:
    """Join the declared log sources with the catalogue's signals and queries.

    *families* are the registry's ``objectives`` and ``rules`` bodies;
    *rule_files* each rule's file; *logsources* the parsed ``[[logsources]]``
    (``None`` when the workspace has no ``visibility.toml``). The workspace's
    declared datasets are installed again before this returns.
    """
    from opentide.core.object_fields import as_body

    declared = _declared(logsources)
    objectives = {uuid: as_body(body) for uuid, body in (families.get("objectives") or {}).items()}
    rules = {uuid: as_body(body) for uuid, body in (families.get("rules") or {}).items()}

    # Signals: objective → [(signal uuid, name, [log source names])].
    signal_sources: dict[str, list[tuple[str, str, list[str]]]] = {}
    for uuid, body in objectives.items():
        raw = body.get("objective")
        section: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        for signal in _as_list(section.get("signals")):
            if not isinstance(signal, Mapping):
                continue
            raw_data = signal.get("data")
            data: Mapping[str, Any] = raw_data if isinstance(raw_data, Mapping) else {}
            names = [str(n) for n in _as_list(data.get("logsources")) if isinstance(n, str)]
            signal_sources.setdefault(uuid, []).append(
                (str(signal.get("uuid") or ""), str(signal.get("name") or ""), names)
            )
    implementers: dict[str, list[str]] = {}
    for uuid, body in rules.items():
        target = body.get("detection_model")
        if isinstance(target, str):
            implementers.setdefault(target, []).append(uuid)

    reads: list[DatasetRead] = []
    reads_unavailable = None
    texts: dict[str, str] = {}
    for uuid, path in rule_files.items():
        try:
            texts[uuid] = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError):
            continue
    from opentide.analysis import EngineUnavailableError, install_workspace_visibility

    try:
        reads = dataset_reads(texts, [(str(rule_files[u]), t) for u, t in texts.items()])
    except EngineUnavailableError as exc:
        reads_unavailable = str(exc)
    finally:
        with contextlib.suppress(EngineUnavailableError):
            install_workspace_visibility(root)

    rows: list[LogSource] = []
    named = {(source.name.lower()) for source in declared}
    for source in declared:
        read_by = [
            r.rule for r in reads if r.system == source.system and _covers(source.name, r.name)
        ]
        objectives_using: list[str] = []
        signals: list[tuple[str, str, str]] = []
        signal_rules: list[str] = []
        for owner, owned in signal_sources.items():
            for signal, name, names in owned:
                if source.name not in names:
                    continue
                objectives_using.append(owner)
                signals.append((owner, signal, name))
                signal_rules.extend(implementers.get(signal, ()))
                signal_rules.extend(implementers.get(owner, ()))
        rows.append(
            LogSource(
                name=source.name,
                system=source.system,
                description=source.description,
                columns=source.columns,
                tenants=source.tenants,
                read_by=tuple(dict.fromkeys(read_by)),
                objectives=tuple(dict.fromkeys(objectives_using)),
                signals=tuple(signals),
                signal_rules=tuple(dict.fromkeys(signal_rules)),
            )
        )

    declaring = {source.system for source in declared}
    missing: dict[tuple[str, str], list[str]] = {}
    for read in reads:
        if not any(s.system == read.system and _covers(s.name, read.name) for s in declared):
            missing.setdefault((read.system, read.name), []).append(read.rule)
    undeclared = tuple(
        Undeclared(system, name, tuple(dict.fromkeys(found)), system in declaring)
        for (system, name), found in sorted(missing.items())
    )
    unknown: dict[str, list[str]] = {}
    for owner, owned in signal_sources.items():
        for _signal, _name, names in owned:
            for name in names:
                if name.lower() not in named:
                    unknown.setdefault(name, []).append(owner)
    systems: dict[str, dict[str, int]] = {}
    for row in rows:
        counts = systems.setdefault(row.system, {"logsources": 0, "with_columns": 0, "used": 0})
        counts["logsources"] += 1
        counts["with_columns"] += bool(row.columns)
        counts["used"] += row.used
    return VisibilityReport(
        logsources=tuple(sorted(rows, key=lambda r: (r.system, r.name.lower()))),
        undeclared=undeclared,
        unknown_signal_sources=tuple(
            (name, tuple(dict.fromkeys(owners))) for name, owners in sorted(unknown.items())
        ),
        reads=tuple(reads),
        reads_unavailable=reads_unavailable,
        problem=problem,
        present=logsources is not None,
        systems=dict(sorted(systems.items())),
    )


def load_visibility(root: Path | None) -> VisibilityReport:
    """:func:`collect_visibility` for the loaded registry: call after ``Opentide.reload()``."""
    from opentide.core.index_manager import IndexManager
    from opentide.core.registry import Opentide

    problem = None
    try:
        logsources = Opentide.Configurations.Visibility.logsources
        present = root is not None and (root / ".opentide/configurations/visibility.toml").is_file()
    except Exception as exc:  # a broken file: validate reports it; the tab says why
        logger.warning("visibility_unreadable", error=str(exc))
        logsources, present, problem = None, True, f"visibility.toml could not be read: {exc}"
    file_paths: Mapping[str, str] = IndexManager.load().get("file_paths") or {}
    rules = dict(Opentide.Models.rules)
    rule_files = {uuid: Path(file_paths[uuid]) for uuid in rules if file_paths.get(uuid)}
    report = collect_visibility(
        root,
        {"objectives": dict(Opentide.Models.objectives), "rules": rules},
        rule_files,
        logsources if present else None,
        problem=problem,
    )
    return report
