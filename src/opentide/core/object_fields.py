"""Field extraction helpers for object bodies.

ATT&CK techniques, threat actors, and platform configurations live in more than
one place depending on schema family and authoring era: rules carry top-level
``techniques``, threats carry ``threat.att&ck`` / ``threat.actors``, and legacy
content uses a ``tags`` mapping. Consumers that read a single location silently
miss content, so every reader goes through these helpers.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

_TECHNIQUE_KEYS = ("techniques", "attack", "att&ck")
_ACTOR_KEYS = ("actors",)
_CONFIGURATION_KEYS = ("configurations", "platforms")
_NESTED_SECTIONS = ("tags", "threat")


def as_body(obj: Any) -> dict[str, Any]:
    """Coerce a registry entry (plain dict or Pydantic model) to a dict."""
    if isinstance(obj, dict):
        return obj
    dump = getattr(obj, "model_dump", None)
    if callable(dump):
        try:
            dumped = dump(by_alias=True)
        except TypeError:
            dumped = dump()
        if isinstance(dumped, dict):
            return dumped
    if isinstance(obj, Mapping):
        return dict(obj)
    return {}


def _sections(body: dict[str, Any]) -> Iterator[Mapping[str, Any]]:
    yield body
    for name in _NESTED_SECTIONS:
        value = body.get(name)
        if isinstance(value, Mapping):
            yield value


def _names(value: Any) -> Iterator[str]:
    """Yield identifier strings from a scalar, mapping, or nested sequence."""
    if isinstance(value, str):
        text = value.strip()
        if text:
            yield text
    elif isinstance(value, Mapping):
        for key in ("name", "id", "value"):
            candidate = value.get(key)
            if isinstance(candidate, str) and candidate.strip():
                yield candidate.strip()
                break
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _names(item)


def _collect(body: Any, keys: tuple[str, ...]) -> set[str]:
    found: set[str] = set()
    for section in _sections(as_body(body)):
        for key in keys:
            found.update(_names(section.get(key)))
    return found


def object_techniques(body: Any) -> set[str]:
    """ATT&CK technique identifiers referenced anywhere in *body*."""
    return _collect(body, _TECHNIQUE_KEYS)


def object_actors(body: Any) -> set[str]:
    """Lowercased actor identifiers, plus the bare suffix of namespaced names.

    ``att&ck::G0006`` also matches a search for ``G0006``.
    """
    actors: set[str] = set()
    for name in _collect(body, _ACTOR_KEYS):
        lowered = name.lower()
        actors.add(lowered)
        if "::" in lowered:
            actors.add(lowered.rsplit("::", 1)[-1])
    return actors


def object_platforms(body: Any) -> set[str]:
    """Lowercased platform keys declared by the object's configurations."""
    resolved = as_body(body)
    platforms: set[str] = set()
    for key in _CONFIGURATION_KEYS:
        section = resolved.get(key)
        if isinstance(section, Mapping):
            platforms.update(str(name).lower() for name in section)
    return platforms


def technique_covers(requested: str, candidate: str) -> bool:
    """Whether *candidate* answers a query for *requested*.

    Case-insensitive, and a parent technique covers its sub-techniques:
    ``T1059`` matches ``T1059.001``, but ``T1059.001`` does not match ``T1059``
    and ``T105`` matches nothing. Asking "what do we detect for T1059?" and
    getting nothing because every rule is tagged at sub-technique level is the
    answer nobody wants.
    """
    needle = requested.strip().lower()
    value = candidate.strip().lower()
    return bool(needle) and (value == needle or value.startswith(f"{needle}."))


def matched_techniques(body: Any, technique: str) -> set[str]:
    """The technique identifiers on *body* that satisfy a query for *technique*."""
    return {item for item in object_techniques(body) if technique_covers(technique, item)}


def matches_technique(body: Any, technique: str) -> bool:
    if not technique.strip():
        return True
    return bool(matched_techniques(body, technique))


def matches_actor(body: Any, actor: str) -> bool:
    needle = actor.strip().lower()
    if not needle:
        return True
    return needle in object_actors(body)


def matches_platform(body: Any, platform: str) -> bool:
    """Exact platform-key match so ``sentinel`` never matches ``sentinel_one``."""
    needle = platform.strip().lower()
    if not needle:
        return True
    return needle in object_platforms(body)
