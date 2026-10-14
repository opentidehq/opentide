"""Field extraction helpers for object bodies, anchored to the Pydantic models.

ATT&CK techniques, threat actors, and platform configurations live at different
places depending on the object family: a rule carries top-level ``techniques``, a
threat carries ``threat.mitre_attack`` / ``threat.actors``, an objective carries
``objective.mitre_attack``. Consumers that read a single location silently miss
content, so every reader goes through these helpers.

The locations are **not** a hardcoded key list. They are DERIVED from the models:
each role-bearing field is tagged with a :class:`~opentide.models.base.FieldRole`
on the model that declares it, and the paths below are built by walking the
registered schema models (and their nested sub-models). A new or renamed
role-bearing field is picked up by tagging it on the model — no edit here. The
``metadata.schema`` identifier on a body selects which model's paths apply; a body
whose schema cannot be resolved falls back to the union of every registered
model's role paths (still model-derived — never a legacy key tuple).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from functools import cache
from typing import Any, get_args

from pydantic.fields import FieldInfo

from opentide.models.base import FieldRole, TideModel, field_role

#: Maximum model-nesting depth walked when deriving role paths. The deepest
#: role-bearing field today sits one level down (``threat.mitre_attack``); the
#: bound guards against a pathological or cyclic model graph.
_MAX_DEPTH = 6


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


def _nested_models(annotation: Any) -> Iterator[type[TideModel]]:
    """Yield every ``TideModel`` subclass reachable from a field annotation.

    Unwraps ``Optional``/``Union`` and the element type of ``list``/``set``/
    ``tuple`` so that ``list[ThreatActor] | None`` yields ``ThreatActor``.
    """
    if isinstance(annotation, type) and issubclass(annotation, TideModel):
        yield annotation
        return
    for arg in get_args(annotation):
        yield from _nested_models(arg)


def _role_paths_for_model(
    model: type[TideModel], role: FieldRole, *, _depth: int = 0
) -> frozenset[tuple[str, ...]]:
    """Dotted paths into *model* (and nested sub-models) tagged with *role*.

    Each path is a tuple of field names from the object root down to the
    role-bearing field, e.g. ``("threat", "mitre_attack")`` for a threat vector
    or ``("techniques",)`` for a rule.
    """
    if _depth > _MAX_DEPTH:
        return frozenset()
    paths: set[tuple[str, ...]] = set()
    for name, info in model.model_fields.items():
        info_role = field_role(info)
        if info_role is role:
            paths.add((name,))
        for nested in _nested_models(_field_annotation(info)):
            if nested is model:
                continue
            for sub in _role_paths_for_model(nested, role, _depth=_depth + 1):
                paths.add((name, *sub))
    return frozenset(paths)


def _field_annotation(info: FieldInfo) -> Any:
    return info.annotation


@cache
def _role_paths(schema_id: str | None, role: FieldRole) -> frozenset[tuple[str, ...]]:
    """Role paths for the model identified by *schema_id*.

    When *schema_id* is ``None`` or cannot be resolved to a registered model, the
    union of role paths across every registered model is returned, so an
    unidentified body is still read against the models rather than ignored.
    """
    from opentide.models.schema_registry import SCHEMA_MODELS, resolve_model

    if schema_id is not None:
        try:
            model = resolve_model(schema_id)
        except LookupError:
            model = None
        if model is not None:
            return _role_paths_for_model(model, role)
    paths: set[tuple[str, ...]] = set()
    for model in SCHEMA_MODELS.values():
        paths.update(_role_paths_for_model(model, role))
    return frozenset(paths)


def _schema_id(body: Mapping[str, Any]) -> str | None:
    """The ``metadata.schema`` identifier declared by *body*, if present."""
    metadata = body.get("metadata")
    if isinstance(metadata, Mapping):
        schema_id = metadata.get("schema")
        if isinstance(schema_id, str) and schema_id.strip():
            return schema_id.strip()
    return None


def _resolve_path(body: Mapping[str, Any], path: tuple[str, ...]) -> Iterator[Any]:
    """Yield the value(s) reached by following *path* through *body*.

    A mapping is descended; a list of mappings is descended element-wise so a
    path such as ``("actors", "name")`` reaches every actor's name.
    """
    head, *rest = path
    value = body.get(head)
    if not rest:
        if value is not None:
            yield value
        return
    if isinstance(value, Mapping):
        yield from _resolve_path(value, tuple(rest))
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            if isinstance(item, Mapping):
                yield from _resolve_path(item, tuple(rest))


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


def _collect(body: Any, role: FieldRole) -> set[str]:
    resolved = as_body(body)
    found: set[str] = set()
    for path in _role_paths(_schema_id(resolved), role):
        for value in _resolve_path(resolved, path):
            found.update(_names(value))
    return found


def object_techniques(body: Any) -> set[str]:
    """ATT&CK technique identifiers declared by *body*'s model."""
    return _collect(body, FieldRole.TECHNIQUES)


def object_actors(body: Any) -> set[str]:
    """Lowercased actor identifiers, plus the bare suffix of namespaced names.

    ``att&ck::G0006`` also matches a search for ``G0006``.
    """
    actors: set[str] = set()
    for name in _collect(body, FieldRole.ACTORS):
        lowered = name.lower()
        actors.add(lowered)
        if "::" in lowered:
            actors.add(lowered.rsplit("::", 1)[-1])
    return actors


def object_platforms(body: Any) -> set[str]:
    """Lowercased platform keys declared by the object's configuration fields."""
    resolved = as_body(body)
    platforms: set[str] = set()
    for path in _role_paths(_schema_id(resolved), FieldRole.CONFIGURATIONS):
        for value in _resolve_path(resolved, path):
            if isinstance(value, Mapping):
                platforms.update(str(name).lower() for name in value)
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
