"""Which ATT&CK techniques each rule covers: those it lists, and those it inherits.

A rule seldom lists techniques itself. It implements an objective (its
``detection_model``, an objective UUID or one of that objective's signals), and
the objective names its techniques, or else takes those of the threats it
covers. ``opentide info catalog``, ``opentide info coverage``, the MCP
``coverage`` tool and the TUI's Coverage tab all read coverage from here, so
they cannot disagree about what a rule covers.

*Own* techniques are the ones the rule's model tags with
:attr:`~opentide.models.base.FieldRole.TECHNIQUES` (``techniques``); *inherited*
ones come from its objective (through a signal's owner) or that objective's
threats, minus the rule's own. "This rule lists the technique" is the stronger
claim, so the two stay apart wherever coverage is reported.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from opentide.core.object_fields import as_body, object_role_values, technique_covers
from opentide.models.base import FieldRole

__all__ = [
    "RuleTechniques",
    "TechniqueMatch",
    "as_list",
    "inherited_techniques",
    "match_technique",
    "own_techniques",
    "rule_technique_index",
]


@dataclass(frozen=True)
class RuleTechniques:
    """The techniques one rule covers, kept apart by where they come from."""

    #: Listed by the rule itself, in authored order.
    own: tuple[str, ...]
    #: From its objective or that objective's threats, without the rule's own.
    inherited: tuple[str, ...]

    @property
    def all(self) -> tuple[str, ...]:
        return (*self.own, *self.inherited)


@dataclass(frozen=True)
class TechniqueMatch:
    """The rules that cover one requested technique."""

    technique: str
    #: Rules whose own list covers it.
    own: tuple[str, ...]
    #: Rules that cover it only through their objective or its threats.
    inherited: tuple[str, ...]
    #: The catalogue's technique IDs that satisfied the request (``T1059.001`` for ``T1059``).
    matched: tuple[str, ...]

    @property
    def rules(self) -> tuple[str, ...]:
        """Every covering rule: the ones that list it first."""
        return (*self.own, *self.inherited)

    def as_payload(self) -> dict[str, Any]:
        rules = list(self.rules)
        return {
            "technique": self.technique,
            "rules": rules,
            "count": len(rules),
            "own": list(self.own),
            "inherited": list(self.inherited),
            "matched_techniques": list(self.matched),
        }


def as_list(value: Any) -> list[Any]:
    """A field that holds a list, read as one: ``[value]`` for a lone string.

    An author who writes ``threats: <uuid>`` or ``logsources: Windows`` means one
    item; iterating the string would make one per character.
    """
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def own_techniques(body: Any) -> list[str]:
    """The techniques *body* lists itself, in authored order."""
    return [technique for _, technique in object_role_values(body, FieldRole.TECHNIQUES)]


def _objective_techniques(body: Any, threats: Mapping[str, Any]) -> list[str]:
    """An objective's techniques: its own, else those of each threat it covers that exists."""
    own = own_techniques(body)
    if own:
        return own
    section = body.get("objective") if isinstance(body, Mapping) else None
    covered = as_list(section.get("threats")) if isinstance(section, Mapping) else []
    found: list[str] = []
    for threat in covered:
        parent = threats.get(threat) if isinstance(threat, str) else None
        # A dangling threat: its covers edge says so (missing: true); the others still count.
        if isinstance(parent, Mapping):
            found.extend(own_techniques(parent))
    return list(dict.fromkeys(found))


def inherited_techniques(
    family: str,
    body: Mapping[str, Any],
    threats: Mapping[str, Any],
    objectives: Mapping[str, Any],
    signals: Mapping[str, Any],
) -> list[str]:
    """What an object gets from its parents, as ``techniques_resolver`` resolves it.

    A rule takes its objective's (through a signal's owner), an objective its
    threats'; a threat has no parent. Resolved here rather than by
    ``techniques_resolver``, which gives up on the first missing parent and
    iterates a lone string per character. The result may repeat the object's
    own techniques; :func:`rule_technique_index` removes them.
    """
    if family == "objective":
        return _objective_techniques(body, threats)
    if family != "rule":
        return []
    target = body.get("detection_model")
    if not isinstance(target, str):
        return []
    signal = signals.get(target)
    owner = signal.get("owner") if isinstance(signal, Mapping) else target
    objective = objectives.get(owner) if isinstance(owner, str) else None
    if not isinstance(objective, Mapping):
        return []
    return _objective_techniques(objective, threats)


def rule_technique_index(models: Any = None) -> dict[str, RuleTechniques]:
    """Every rule's :class:`RuleTechniques`, from the loaded registry.

    *models* is ``Opentide.Models`` unless given (anything with ``rules``,
    ``objectives``, ``threats`` and ``signals`` mappings).
    """
    if models is None:
        from opentide.core.registry import Opentide

        models = Opentide.Models
    threats = _bodies(models.threats)
    objectives = _bodies(models.objectives)
    signals: Mapping[str, Any] = getattr(models, "signals", None) or {}
    if not isinstance(signals, Mapping):
        signals = {}
    index: dict[str, RuleTechniques] = {}
    for uuid, rule in (models.rules or {}).items():
        body = as_body(rule)
        own = own_techniques(body)
        inherited = (
            inherited_techniques("rule", body, threats, objectives, signals)
            if isinstance(body, Mapping)
            else []
        )
        index[uuid] = RuleTechniques(
            own=tuple(own),
            inherited=tuple(t for t in dict.fromkeys(inherited) if t not in own),
        )
    return index


def match_technique(technique: str, index: Mapping[str, RuleTechniques]) -> TechniqueMatch:
    """The rules in *index* that cover *technique*, as :func:`technique_covers` matches.

    A parent technique counts its sub-techniques' rules. A rule that lists a
    matching technique is *own*, even when it also inherits one.
    """
    needle = technique.strip()
    own: list[str] = []
    inherited: list[str] = []
    matched: set[str] = set()
    for uuid, techniques in index.items():
        own_hits = [t for t in techniques.own if technique_covers(needle, t)]
        inherited_hits = [t for t in techniques.inherited if technique_covers(needle, t)]
        matched.update(own_hits, inherited_hits)
        if own_hits:
            own.append(uuid)
        elif inherited_hits:
            inherited.append(uuid)
    return TechniqueMatch(
        technique=needle,
        own=tuple(own),
        inherited=tuple(inherited),
        matched=tuple(sorted(matched)),
    )


def _bodies(bucket: Any) -> dict[str, Any]:
    """*bucket* with each object as its plain mapping (registry entries may be models)."""
    if not isinstance(bucket, Mapping):
        return {}
    return {uuid: as_body(body) for uuid, body in bucket.items()}
