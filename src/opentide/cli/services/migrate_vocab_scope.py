"""Re-prefix authored vocabulary values for stage-scoped fields.

A field declared ``VocabField(..., scoped=True)`` authors ``<stage>::<key>``.
When a field *becomes* scoped, or a vocabulary's stage identifiers change,
every object already on disk carries the previous form and stops validating.
This service rewrites those values to the scoped form the current engine
accepts.

Three properties make it safe to run on a real corpus:

**Nothing is guessed.** A bare key name defined under several stages is not
recoverable -- ``Account`` could be ``Host::Account`` or ``Cloud::Account`` --
so it is reported for a human and left untouched. Only mechanical outcomes
(an implied single-stage prefix, a stage-casing fix) are applied.

**Only the declared field is touched.** Values are located by *path* through
the parsed document, not by leaf key name. That distinction is load-bearing:
a Sentinel platform block also carries a key called ``entities``, holding
entity *mappings* rather than vocabulary values, and a name-based rewrite
would corrupt it.

**Formatting survives.** Each value is replaced over the exact character span
its scalar node occupies, so comments, block scalars, key order, quoting
style and flow sequences are all preserved. Every file is re-parsed
afterwards and compared against the intended mapping; a mismatch aborts that
file rather than writing a corrupted object.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from opentide.core.logging import get_logger
from opentide.generation.vocabulary import VocabularyDefinition
from opentide.validation.vocab_scope import ScopeOutcome, VocabScopeIndex

logger = get_logger(__name__)

#: Wildcard path segment matching any index of a sequence.
ANY = "*"


@dataclass(frozen=True)
class ScopedField:
    """A field authored as ``<stage>::<key>``, and where it lives."""

    vocab: str
    path: tuple[str, ...]

    @property
    def leaf(self) -> str:
        return self.path[-1]


#: Every field declared ``scoped=True`` on a model, with the document path it
#: is authored at. Paths mirror the vocabulary pin keys in ``data/pins/``;
#: ``test_scoped_fields_match_the_pins`` holds the two in step.
SCOPED_FIELDS: dict[str, ScopedField] = {
    "surface": ScopedField(vocab="surface", path=("threat", "surface")),
    "entities": ScopedField(
        vocab="signal.entities", path=("objective", "signals", ANY, "entities")
    ),
}


@dataclass
class FieldReport:
    """What one scoped field needed across the corpus."""

    field_name: str
    vocab: str
    counts: Counter[str] = field(default_factory=Counter)
    rewrites: dict[str, str] = field(default_factory=dict)
    blocked: dict[str, ScopeOutcome] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())


@dataclass
class MigrationReport:
    """Outcome of a whole migration run."""

    applied: bool
    fields: dict[str, FieldReport] = field(default_factory=dict)
    changed_files: list[str] = field(default_factory=list)
    failed_files: dict[str, str] = field(default_factory=dict)
    scanned: int = 0

    @property
    def blocked_total(self) -> int:
        return sum(len(report.blocked) for report in self.fields.values())

    def to_dict(self) -> dict[str, Any]:
        return {
            "applied": self.applied,
            "scanned": self.scanned,
            "changed_files": sorted(self.changed_files),
            "failed_files": self.failed_files,
            "fields": {
                name: {
                    "vocab": report.vocab,
                    "values": report.total,
                    "by_status": dict(report.counts),
                    "rewrites": report.rewrites,
                    "blocked": {
                        value: outcome.detail for value, outcome in sorted(report.blocked.items())
                    },
                }
                for name, report in sorted(self.fields.items())
            },
        }


def load_scoped_vocabularies(
    fields: dict[str, ScopedField] | None = None,
) -> dict[str, VocabularyDefinition]:
    """Load the packaged vocabularies backing the scoped fields.

    The engine's own copies are canonical -- a scoped value has to match the
    enum *this* release generates, not whatever an instance has on disk.
    """
    from opentide.core.root import get_data_root
    from opentide.vocabulary.io import load_vocab_file

    root = get_data_root() / "vocabulary"
    wanted = sorted({spec.vocab for spec in (fields or SCOPED_FIELDS).values()})
    return {name: load_vocab_file(root / f"{name}.vocab.toml") for name in wanted}


@dataclass(frozen=True)
class _Scalar:
    """One authored scalar, with the exact span it occupies in the source."""

    value: str
    start: int
    end: int


def _collect_scalars(text: str, path: tuple[str, ...]) -> list[_Scalar]:
    """Collect every scalar authored at *path*, with its character span.

    Uses the composed node tree rather than the loaded data, because only
    nodes carry source marks. A scalar's span is taken verbatim, so quoting
    style and flow-vs-block layout are irrelevant to the caller.
    """
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return []
    if root is None:
        return []

    lines = text.splitlines(keepends=True)
    offsets: list[int] = []
    running = 0
    for line in lines:
        offsets.append(running)
        running += len(line)
    offsets.append(running)

    def absolute(mark: Any) -> int:
        if mark.line >= len(offsets):
            return running
        return offsets[mark.line] + mark.column

    found: list[_Scalar] = []

    def walk(node: Any, remaining: tuple[str, ...]) -> None:
        if not remaining:
            _emit(node)
            return
        head, tail = remaining[0], remaining[1:]
        if isinstance(node, yaml.MappingNode):
            for key_node, value_node in node.value:
                if isinstance(key_node, yaml.ScalarNode) and key_node.value == head:
                    walk(value_node, tail)
        elif isinstance(node, yaml.SequenceNode) and head == ANY:
            for item in node.value:
                walk(item, tail)

    def _emit(node: Any) -> None:
        """Record the terminal node, which may be a scalar or a sequence."""
        if isinstance(node, yaml.ScalarNode):
            found.append(
                _Scalar(
                    value=node.value,
                    start=absolute(node.start_mark),
                    end=absolute(node.end_mark),
                )
            )
        elif isinstance(node, yaml.SequenceNode):
            for item in node.value:
                _emit(item)

    walk(root, path)
    return found


def _collect_values(text: str, path: tuple[str, ...], into: Counter[str]) -> None:
    """Count every authored value at *path*."""
    for scalar in _collect_scalars(text, path):
        into[scalar.value] += 1


def _needs_quoting(value: str) -> bool:
    """Whether *value* must be quoted to survive a YAML round trip."""
    if not value or value != value.strip():
        return True
    if value[:1] in "!&*?|>%@`,[]{}#\"'-":
        return True
    return value.endswith(":") or ": " in value


def _rewrite_text(
    text: str, plans: dict[str, tuple[tuple[str, ...], dict[str, str]]]
) -> tuple[str, int]:
    """Apply *plans* to *text* by replacing exact scalar spans."""
    edits: list[tuple[int, int, str]] = []
    for path, mapping in plans.values():
        if not mapping:
            continue
        for scalar in _collect_scalars(text, path):
            replacement = mapping.get(scalar.value)
            if replacement is None:
                continue
            original = text[scalar.start : scalar.end]
            quoted = original[:1] in {'"', "'"} and original[-1:] == original[:1]
            if quoted:
                quote = original[0]
                rendered = f"{quote}{replacement}{quote}"
            elif _needs_quoting(replacement):
                rendered = f'"{replacement}"'
            else:
                rendered = replacement
            edits.append((scalar.start, scalar.end, rendered))

    if not edits:
        return text, 0
    # Apply right-to-left so earlier spans keep their offsets.
    edits.sort(key=lambda edit: edit[0], reverse=True)
    out = text
    for start, end, rendered in edits:
        out = out[:start] + rendered + out[end:]
    return out, len(edits)


def run_migrate_vocab_scope(
    repo: Path,
    vocab_index: dict[str, VocabularyDefinition],
    *,
    apply: bool = False,
    objects_dir: str = "objects",
    fields: dict[str, ScopedField] | None = None,
) -> dict[str, Any]:
    """Re-prefix scoped vocabulary values across the object corpus.

    Dry-run by default: the report names every rewrite it would make and
    every value it cannot resolve. Pass ``apply=True`` to write.
    """
    targets = dict(fields or SCOPED_FIELDS)
    indexes: dict[str, VocabScopeIndex] = {}
    for field_name, spec in targets.items():
        definition = vocab_index.get(spec.vocab)
        if definition is None:
            raise ValueError(f"vocabulary {spec.vocab!r} is not loaded")
        index = VocabScopeIndex(definition)
        if not index.is_staged:
            raise ValueError(
                f"vocabulary {spec.vocab!r} declares no stages, so it cannot be scoped"
            )
        indexes[field_name] = index

    report = MigrationReport(applied=apply)
    for field_name, spec in targets.items():
        report.fields[field_name] = FieldReport(field_name=field_name, vocab=spec.vocab)

    root = repo / objects_dir
    paths = sorted(path for path in root.rglob("*.yaml") if path.is_file())
    sources: dict[Path, str] = {}

    # Pass 1: resolve every authored value, so an ambiguity anywhere is
    # reported before a single file is written.
    for path in paths:
        relative = str(path.relative_to(repo))
        try:
            text = path.read_text(encoding="utf-8")
            yaml.compose(text)
        except (OSError, yaml.YAMLError) as exc:
            report.failed_files[relative] = f"unreadable: {exc}"
            continue
        sources[path] = text
        report.scanned += 1
        for field_name, index in indexes.items():
            seen: Counter[str] = Counter()
            _collect_values(text, targets[field_name].path, seen)
            field_report = report.fields[field_name]
            for value, count in seen.items():
                outcome = index.resolve(value)
                field_report.counts[outcome.status] += count
                if outcome.changed and outcome.resolved is not None:
                    field_report.rewrites[value] = outcome.resolved
                elif not outcome.is_resolved:
                    field_report.blocked[value] = outcome

    plans = {
        field_name: (targets[field_name].path, report.fields[field_name].rewrites)
        for field_name in indexes
        if report.fields[field_name].rewrites
    }
    if not plans:
        return report.to_dict()

    # Pass 2: rewrite, then verify by re-parsing. A file whose values do not
    # land exactly on the plan is left untouched and reported.
    for path, original in sources.items():
        relative = str(path.relative_to(repo))
        updated, changes = _rewrite_text(original, plans)
        if not changes:
            continue
        problem = _verify(original, updated, plans)
        if problem:
            report.failed_files[relative] = problem
            continue
        report.changed_files.append(relative)
        if apply:
            path.write_text(updated, encoding="utf-8")

    if report.changed_files:
        logger.info(
            "vocab_scope_migration",
            applied=apply,
            files=len(report.changed_files),
            blocked=report.blocked_total,
        )
    return report.to_dict()


def _verify(
    original: str, updated: str, plans: dict[str, tuple[tuple[str, ...], dict[str, str]]]
) -> str | None:
    """Return a reason the rewrite is unsafe, or ``None`` when it is sound."""
    try:
        before = yaml.safe_load(original)
        after = yaml.safe_load(updated)
    except yaml.YAMLError as exc:
        return f"rewrite produced unparseable YAML: {exc}"

    for field_name, (path, mapping) in plans.items():
        expected: Counter[str] = Counter()
        _collect_values(original, path, expected)
        actual: Counter[str] = Counter()
        _collect_values(updated, path, actual)
        projected: Counter[str] = Counter()
        for value, count in expected.items():
            projected[mapping.get(value, value)] += count
        if projected != actual:
            return (
                f"rewrite of {field_name!r} did not match the plan "
                f"(expected {sorted(projected.items())}, got {sorted(actual.items())})"
            )

    # Nothing outside the migrated paths may differ in meaning.
    if _blank_paths(before, [path for path, _ in plans.values()]) != _blank_paths(
        after, [path for path, _ in plans.values()]
    ):
        return "rewrite altered a value outside the migration plan"
    return None


def _blank_paths(payload: Any, paths: list[tuple[str, ...]]) -> Any:
    """Copy *payload* with each of *paths* emptied, for comparison."""
    import copy

    clone = copy.deepcopy(payload)

    def strip(node: Any, remaining: tuple[str, ...]) -> None:
        if not remaining:
            return
        head, tail = remaining[0], remaining[1:]
        if isinstance(node, dict):
            if not tail:
                node.pop(head, None)
                return
            if head in node:
                strip(node[head], tail)
        elif isinstance(node, list) and head == ANY:
            for item in node:
                strip(item, tail)

    for path in paths:
        strip(clone, path)
    return clone
