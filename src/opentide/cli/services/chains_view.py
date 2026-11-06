"""Threat chaining as ``opentide tui`` draws it: a path you can read and follow (#776).

``threat.chaining`` links two threats with a relation from the
``chaining_relations`` vocabulary. Each stage has a pair of inverse relations
(``sequence::preceeds`` and ``sequence::succeeds``, ``atomicity::implemented``
and ``atomicity::implements``, ``support::enabled`` and ``support::enabling``)
and ``support::synergize`` goes both ways, so the same link can be written from
either end. :func:`chain_edges` reads every link once, as its ``from`` form
(``A preceeds B`` for ``B succeeds A``), with the description each end gives.

:func:`neighbourhood` is what the tab shows: the threats within some hops of the
focused one, sequence links laid out left to right as attack flow
(:func:`flow_layers`), supporting and atomicity links beside them, and per
threat the rules under its objectives and how many of its techniques some
rule covers (own or inherited, :mod:`opentide.core.technique_coverage`).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "STAGES",
    "ChainEdge",
    "ChainNode",
    "Neighbourhood",
    "chain_edges",
    "flow_layers",
    "neighbourhood",
]

#: The relation stages, in the order the filter cycles through them.
STAGES = ("sequence", "atomicity", "support")

#: A relation's ``from`` form: ``(stage, name)`` → how the edge reads, source to target.
_FROM = {
    ("sequence", "preceeds"): "then",
    ("atomicity", "implemented"): "implemented by",
    ("support", "enabled"): "enables",
}
#: A ``to`` form and the ``from`` form it is the inverse of.
_TO = {
    ("sequence", "succeeds"): ("sequence", "preceeds"),
    ("atomicity", "implements"): ("atomicity", "implemented"),
    ("support", "enabling"): ("support", "enabled"),
}
_BOTH = {("support", "synergize"): "synergizes with"}


@dataclass(frozen=True)
class ChainEdge:
    """One chaining link, read once whichever end wrote it."""

    source: str
    target: str
    stage: str
    #: How it reads from source to target: ``then``, ``enables``, ``implemented by``…
    label: str
    #: The relation each end wrote, as written (``sequence::preceeds``).
    relations: tuple[str, ...]
    #: Each end's ``description``, when it gives one.
    descriptions: tuple[str, ...] = ()
    #: Whether both ends wrote it (so it was merged).
    merged: bool = False
    #: A target no threat of the catalogue has.
    missing: bool = False
    directed: bool = True


@dataclass(frozen=True)
class ChainNode:
    uuid: str
    name: str
    #: Hops from the focused threat.
    distance: int
    #: Rules under the threat's objectives.
    rules: int
    #: ``(covered, total)`` of the threat's techniques that some rule covers.
    techniques: tuple[int, int] = (0, 0)
    missing: bool = False


@dataclass(frozen=True)
class Neighbourhood:
    focus: str
    nodes: Mapping[str, ChainNode]
    edges: tuple[ChainEdge, ...]
    #: Sequence links' threats in flow order: each layer comes after the one before it.
    layers: tuple[tuple[str, ...], ...] = ()
    stage: str | None = None
    hops: int = 1
    #: Threats the hop limit left out.
    hidden: int = 0
    totals: Mapping[str, int] = field(default_factory=dict)


def _relation(raw: str) -> tuple[str, str] | None:
    stage, _, name = raw.partition("::")
    if not name:
        return None
    # `support::*` is the vocabulary's stage id for "Supportive".
    stage = stage.strip().lower()
    return stage, name.strip().lower()


def chain_edges(threats: Mapping[str, Any]) -> tuple[ChainEdge, ...]:
    """Every chaining link of *threats* (bodies by UUID), each once, inverses merged."""
    from opentide.core.object_fields import as_body

    found: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for uuid, raw in threats.items():
        body = as_body(raw)
        section = body.get("threat")
        links = section.get("chaining") if isinstance(section, Mapping) else None
        for link in links or ():
            if not isinstance(link, Mapping):
                continue
            relation, vector = link.get("relation"), link.get("vector")
            if not isinstance(relation, str) or not isinstance(vector, str):
                continue
            parsed = _relation(relation)
            if parsed is None:
                continue
            if parsed in _FROM:
                key, source, target, label, directed = parsed, uuid, vector, _FROM[parsed], True
            elif parsed in _TO:
                key = _TO[parsed]
                source, target, label, directed = vector, uuid, _FROM[key], True
            elif parsed in _BOTH:
                key = parsed
                source, target = sorted((uuid, vector))
                label, directed = _BOTH[parsed], False
            else:
                continue
            entry = found.setdefault(
                (source, target, *key),
                {
                    "label": label,
                    "relations": [],
                    "descriptions": [],
                    "ends": set(),
                    "directed": directed,
                },
            )
            entry["relations"].append(relation)
            entry["ends"].add(uuid)
            description = link.get("description")
            if isinstance(description, str) and description.strip():
                entry["descriptions"].append(" ".join(description.split()))
    return tuple(
        ChainEdge(
            source=source,
            target=target,
            stage=stage,
            label=entry["label"],
            relations=tuple(entry["relations"]),
            descriptions=tuple(dict.fromkeys(entry["descriptions"])),
            merged=len(entry["ends"]) > 1,
            missing=source not in threats or target not in threats,
            directed=entry["directed"],
        )
        for (source, target, stage, _name), entry in sorted(found.items())
    )


def flow_layers(nodes: Iterable[str], edges: Iterable[ChainEdge]) -> tuple[tuple[str, ...], ...]:
    """The threats sequence links connect, in layers: each after the layer before it.

    A threat's layer is the longest run of ``then`` links that leads to it, so a
    chain reads left to right as the attack unfolds. A cycle (``A then B then
    A``) is cut where it closes. Threats no sequence link touches are left out.
    """
    sequence = [e for e in edges if e.stage == "sequence" and e.directed]
    members = set(nodes)
    after: dict[str, list[str]] = {}
    incoming: dict[str, int] = {}
    touched: set[str] = set()
    for edge in sequence:
        if edge.source in members and edge.target in members and edge.source != edge.target:
            after.setdefault(edge.source, []).append(edge.target)
            incoming[edge.target] = incoming.get(edge.target, 0) + 1
            touched |= {edge.source, edge.target}
    layer = dict.fromkeys(touched, 0)
    queue = deque(sorted(uuid for uuid in touched if not incoming.get(uuid)))
    seen: set[str] = set()
    remaining = dict(incoming)
    while queue or len(seen) < len(touched):
        if not queue:
            # A cycle: start again from the earliest threat not yet placed.
            queue.append(min(touched - seen))
        uuid = queue.popleft()
        if uuid in seen:
            continue
        seen.add(uuid)
        for target in after.get(uuid, ()):
            if target in seen:
                continue
            layer[target] = max(layer[target], layer[uuid] + 1)
            remaining[target] -= 1
            if remaining[target] <= 0:
                queue.append(target)
    depth = max(layer.values(), default=-1) + 1
    return tuple(
        tuple(sorted(uuid for uuid, n in layer.items() if n == index)) for index in range(depth)
    )


def neighbourhood(
    focus: str,
    edges: Iterable[ChainEdge],
    names: Mapping[str, str],
    rules: Mapping[str, int],
    techniques: Mapping[str, tuple[int, int]] | None = None,
    *,
    hops: int = 1,
    stage: str | None = None,
) -> Neighbourhood:
    """The threats within *hops* links of *focus*, by links of *stage* (all when ``None``)."""
    techniques = techniques or {}
    chosen = [e for e in edges if stage is None or e.stage == stage]
    adjacent: dict[str, set[str]] = {}
    for edge in chosen:
        adjacent.setdefault(edge.source, set()).add(edge.target)
        adjacent.setdefault(edge.target, set()).add(edge.source)
    distance = {focus: 0}
    queue = deque([focus])
    while queue:
        uuid = queue.popleft()
        for other in sorted(adjacent.get(uuid, ())):
            if other not in distance:
                distance[other] = distance[uuid] + 1
                queue.append(other)
    reachable = len(distance)
    within = {uuid: n for uuid, n in distance.items() if n <= hops}
    shown = tuple(e for e in chosen if e.source in within and e.target in within)
    nodes = {
        uuid: ChainNode(
            uuid=uuid,
            name=names.get(uuid, uuid),
            distance=n,
            rules=rules.get(uuid, 0),
            techniques=techniques.get(uuid, (0, 0)),
            missing=uuid not in names,
        )
        for uuid, n in within.items()
    }
    totals = {name: sum(1 for e in shown if e.stage == name) for name in STAGES}
    return Neighbourhood(
        focus=focus,
        nodes=nodes,
        edges=shown,
        layers=flow_layers(within, shown),
        stage=stage,
        hops=hops,
        hidden=reachable - len(within),
        totals=totals,
    )
