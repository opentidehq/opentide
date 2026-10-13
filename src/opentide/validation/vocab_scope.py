"""Resolve an authored vocabulary value to its stage-scoped form.

A *staged* vocabulary groups its keys under stages, and a ``scoped`` field
authors ``<stage>::<key>`` rather than the bare key name. The same key name
legitimately appears under more than one stage, so the bare form is lossy:
``signal.entities`` defines ``Account`` under both ``Host`` and ``Cloud``.

This module turns an authored value into the scoped form the enum resolver
will accept, or reports why it cannot. It is the only place that decides
that question, so a migration can never emit a value ``validate`` rejects.

Resolution is **raw-first**: the whole authored value is tried as a key name
before its leading token is read as a stage id. That order matters because
key names contain ``::`` themselves -- ``surface`` defines
``AWS::Compute::EC2`` and six ``Security::*`` keys whose leading token is
also a stage id. Reading the prefix first would resolve
``Security::Kerberos`` (a ``Protocol`` key) to the unrelated
``Authentication`` key ``Kerberos``. This is the same precedence
``VocabularyEnumResolver.is_valid`` applies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from opentide.generation.vocabulary import is_id_keyed, normalize_stages

if TYPE_CHECKING:  # pragma: no cover - typing only
    from opentide.generation.vocabulary import VocabularyDefinition

SCOPE_SEPARATOR = "::"

ScopeStatus = Literal[
    "scoped",
    "rescoped",
    "prefixed",
    "ambiguous",
    "invalid_stage",
    "unknown",
]
"""Why a value resolved the way it did.

``scoped``
    Already exactly a valid scoped value. No change.
``rescoped``
    A valid scoped value once casing is normalised (``host::Process`` ->
    ``Host::Process``). Mechanical, safe to apply.
``prefixed``
    A bare key name carrying exactly one stage, so the prefix is implied by
    the vocabulary. Mechanical, safe to apply.
``ambiguous``
    A bare key name carrying several stages. The authored intent is *not*
    recoverable -- ``Account`` could be ``Host::Account`` or
    ``Cloud::Account`` -- so this is reported for a human, never guessed.
``invalid_stage``
    The key exists but not under the named stage (``Cloud::Process`` where
    ``Process`` is host-only). Reported with the key's real scoped forms.
``unknown``
    Not a key and not a scoped form, under any casing.
"""

RESOLVED_STATUSES: frozenset[str] = frozenset({"scoped", "rescoped", "prefixed"})
"""Statuses that yield a value safe to write back without human review."""


@dataclass(frozen=True)
class ScopeOutcome:
    """The resolution of one authored value."""

    authored: str
    status: ScopeStatus
    resolved: str | None = None
    key: str | None = None
    candidates: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_resolved(self) -> bool:
        """Whether a value safe to write back was produced."""
        return self.status in RESOLVED_STATUSES and self.resolved is not None

    @property
    def changed(self) -> bool:
        """Whether applying this outcome would alter the authored text."""
        return self.is_resolved and self.resolved != self.authored

    @property
    def detail(self) -> str:
        """One-line, human-facing explanation."""
        if self.status == "scoped":
            return f"{self.authored!r} is already scoped"
        if self.status == "rescoped":
            return f"{self.authored!r} -> {self.resolved!r} (stage casing)"
        if self.status == "prefixed":
            return f"{self.authored!r} -> {self.resolved!r}"
        if self.status == "ambiguous":
            options = ", ".join(repr(candidate) for candidate in self.candidates)
            return f"{self.authored!r} is defined under several stages: {options}"
        if self.status == "invalid_stage":
            options = ", ".join(repr(candidate) for candidate in self.candidates)
            return f"{self.authored!r} names a stage the key is not defined under; valid: {options}"
        return f"{self.authored!r} is not a known vocabulary value"


class VocabScopeIndex:
    """Resolution index over one staged vocabulary.

    Scoped forms are built exactly the way
    :meth:`VocabularyEnumResolver._process` builds the generated enum, so a
    value this index returns is a value the generated schema accepts:

    * a name-keyed vocabulary emits one value per stage the key carries;
    * an id-keyed vocabulary emits a single value, prefixed with the key's
      first stage.
    """

    def __init__(self, definition: VocabularyDefinition) -> None:
        self._stages: tuple[str, ...] = tuple(
            str(stage.get("id", "")) for stage in definition.metadata.get("stages", []) or []
        )
        self._stage_by_lower: dict[str, str] = {
            stage.lower(): stage for stage in self._stages if stage
        }
        id_keyed = is_id_keyed(definition.metadata.to_dict())

        self._scoped_by_key: dict[str, tuple[str, ...]] = {}
        for key, entry in definition.entries.items():
            stages = [stage for stage in normalize_stages(list(entry.stages)) if stage]
            if not stages:
                continue
            emitted = stages[:1] if id_keyed else stages
            self._scoped_by_key[key] = tuple(f"{stage}{SCOPE_SEPARATOR}{key}" for stage in emitted)

        self._key_by_lower: dict[str, str] = {key.lower(): key for key in self._scoped_by_key}
        self._key_by_scoped: dict[str, str] = {
            scoped: key for key, forms in self._scoped_by_key.items() for scoped in forms
        }
        self._scoped_by_lower: dict[str, str] = {
            scoped.lower(): scoped for scoped in self._key_by_scoped
        }

    @property
    def stages(self) -> tuple[str, ...]:
        """Declared stage identifiers, in declaration order."""
        return self._stages

    @property
    def is_staged(self) -> bool:
        """Whether this vocabulary groups any key under a stage."""
        return bool(self._scoped_by_key)

    def scoped_values(self) -> tuple[str, ...]:
        """Every scoped value this vocabulary admits."""
        return tuple(self._key_by_scoped)

    def resolve(self, authored: str) -> ScopeOutcome:
        """Resolve *authored* to its scoped form, or explain why it cannot be."""
        value = authored.strip()
        if not value:
            return ScopeOutcome(authored=authored, status="unknown")

        # 1. Already exactly valid. Short-circuit so a correct value is never
        #    rewritten, whatever else it could also be read as.
        key = self._key_by_scoped.get(value)
        if key is not None:
            return ScopeOutcome(authored=authored, status="scoped", resolved=value, key=key)

        # 2. Raw-first: the whole value as a key name. Must precede any
        #    prefix reading, because key names contain `::` themselves.
        outcome = self._from_key(authored, value)
        if outcome is not None:
            return outcome

        # 3. The whole value as a key name, case-insensitively.
        canonical_key = self._key_by_lower.get(value.lower())
        if canonical_key is not None:
            outcome = self._from_key(authored, canonical_key)
            if outcome is not None:
                return outcome

        # 4. A scoped value whose casing drifted (`host::Process`).
        canonical_scoped = self._scoped_by_lower.get(value.lower())
        if canonical_scoped is not None:
            return ScopeOutcome(
                authored=authored,
                status="rescoped",
                resolved=canonical_scoped,
                key=self._key_by_scoped[canonical_scoped],
            )

        # 5. A stage-prefixed value whose key is real but not defined under
        #    that stage. Distinguished from `unknown` because the remedy is
        #    different: pick a valid stage rather than find a valid key.
        head, separator, tail = value.partition(SCOPE_SEPARATOR)
        if separator and head.lower() in self._stage_by_lower:
            stranded = self._key_by_lower.get(tail.lower())
            if stranded is not None:
                return ScopeOutcome(
                    authored=authored,
                    status="invalid_stage",
                    key=stranded,
                    candidates=self._scoped_by_key[stranded],
                )

        return ScopeOutcome(authored=authored, status="unknown")

    def _from_key(self, authored: str, key: str) -> ScopeOutcome | None:
        """Resolve *authored* as the vocabulary key *key*, if that key exists."""
        scoped_forms = self._scoped_by_key.get(key)
        if not scoped_forms:
            return None
        if len(scoped_forms) > 1:
            return ScopeOutcome(
                authored=authored,
                status="ambiguous",
                key=key,
                candidates=scoped_forms,
            )
        return ScopeOutcome(
            authored=authored,
            status="prefixed",
            resolved=scoped_forms[0],
            key=key,
        )
