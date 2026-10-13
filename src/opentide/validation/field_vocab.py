"""Metaschema-driven vocabulary field validation."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from opentide.generation.pydantic_metaschema import _deref_schema_node, _schema_branch_nodes
from opentide.validation.deprecated_fields import resolve_metaschema
from opentide.validation.errors import _leaf_field_name
from opentide.validation.issues import ValidationIssue
from opentide.validation.preflight import PreflightGraph


def _configured_responders() -> list[str]:
    """Read the configured alert-handling teams.

    Imported lazily: `opentide.core.responders` reaches the registry, which
    is not built at module import time.
    """
    from opentide.core.responders import configured_responders

    return configured_responders()


def walk_vocab_fields(
    payload: dict[str, Any],
    schema: dict[str, Any],
    graph: PreflightGraph,
    *,
    object_uuid: str = "",
    object_type: str = "",
    path: tuple[str, ...] = (),
    defs: dict[str, Any] | None = None,
) -> list[ValidationIssue]:
    """Validate ``tide.vocab`` fields in *payload* against the live enum resolver."""
    issues: list[ValidationIssue] = []
    if defs is None:
        raw_defs = schema.get("$defs")
        defs = raw_defs if isinstance(raw_defs, dict) else {}
    properties = schema.get("properties", schema)
    if not isinstance(properties, dict):
        return issues

    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_path = (*path, field_name)
        value = payload.get(field_name) if isinstance(payload, dict) else None
        resolved = _deref_schema_node(field_schema, defs)
        vocab_schema = field_schema if field_schema.get("tide.vocab") is not None else resolved
        if vocab_schema.get("tide.vocab") is not None:
            issues.extend(
                _validate_vocab_value(
                    value,
                    vocab_schema,
                    graph,
                    field_path=field_path,
                    object_uuid=object_uuid,
                    object_type=object_type,
                )
            )
        config_schema = field_schema if _config_enum_keyword(field_schema) else resolved
        if _config_enum_keyword(config_schema):
            issues.extend(
                _validate_config_enum_value(
                    value,
                    config_schema,
                    field_path=field_path,
                    object_uuid=object_uuid,
                    object_type=object_type,
                )
            )
        for branch in _schema_branch_nodes(field_schema, defs):
            nested_props = branch.get("properties")
            if isinstance(nested_props, dict) and isinstance(value, dict):
                issues.extend(
                    walk_vocab_fields(
                        value,
                        branch,
                        graph,
                        object_uuid=object_uuid,
                        object_type=object_type,
                        path=field_path,
                        defs=defs,
                    )
                )
            items = branch.get("items")
            if isinstance(items, dict) and isinstance(value, list):
                item_schema = _deref_schema_node(items, defs)
                item_props = item_schema.get("properties")
                if isinstance(item_props, dict):
                    for index, item in enumerate(value):
                        if isinstance(item, dict):
                            issues.extend(
                                walk_vocab_fields(
                                    cast(dict[str, Any], item),
                                    item_schema,
                                    graph,
                                    object_uuid=object_uuid,
                                    object_type=object_type,
                                    path=(*field_path, str(index)),
                                    defs=defs,
                                )
                            )
                item_vocab_schema = items if items.get("tide.vocab") is not None else item_schema
                if item_vocab_schema.get("tide.vocab") is not None:
                    for index, item in enumerate(value):
                        issues.extend(
                            _validate_vocab_value(
                                item,
                                item_vocab_schema,
                                graph,
                                field_path=(*field_path, str(index)),
                                object_uuid=object_uuid,
                                object_type=object_type,
                            )
                        )
    return issues


#: Metaschema keywords marking a field whose allowed values come from the
#: instance's own configuration rather than from a canonical vocabulary,
#: mapped to the ONE function that reads them.
#:
#: Validation walks the *un-enriched* metaschema, which carries the keyword
#: but no `enum` -- the enum is written later, during schema generation. So
#: the allowed set cannot be read off the node here. Both paths therefore
#: call the same resolver rather than each deriving the answer: `validate`
#: through this table, and the generation pipeline through
#: `VocabularyResolver.Responders`. One function, two call sites, no second
#: implementation to drift (the failure class #508 was about).
CONFIG_ENUM_RESOLVERS: dict[str, Callable[[], list[str]]] = {
    "tide.config.responders": _configured_responders,
}

CONFIG_ENUM_KEYWORDS: tuple[str, ...] = tuple(CONFIG_ENUM_RESOLVERS)


def _config_enum_keyword(field_schema: dict[str, Any]) -> str | None:
    """Return the configuration-enum keyword on *field_schema*, if any."""
    for keyword in CONFIG_ENUM_KEYWORDS:
        if field_schema.get(keyword):
            return keyword
    return None


def _config_enum_allowed(keyword: str, field_schema: dict[str, Any]) -> list[str]:
    """Return the allowed values for a configuration-enum field.

    Prefers an `enum` already present on the node, so a caller handing in an
    enriched schema is validated against exactly what that schema advertises;
    otherwise resolves from configuration.
    """
    for candidate in (field_schema, field_schema.get("items")):
        if isinstance(candidate, dict):
            allowed = candidate.get("enum")
            if isinstance(allowed, list) and allowed:
                return [str(value) for value in allowed]
    resolver = CONFIG_ENUM_RESOLVERS.get(keyword)
    return list(resolver()) if resolver else []


def _validate_config_enum_value(
    value: Any,
    field_schema: dict[str, Any],
    *,
    field_path: tuple[str, ...],
    object_uuid: str,
    object_type: str,
) -> list[ValidationIssue]:
    """Validate a configuration-enum field against the configured values.

    An instance that has declared nothing leaves the field unconstrained,
    which is how a shipped template avoids carrying a constraint nobody can
    satisfy (#507).
    """
    if value is None:
        return []
    keyword = _config_enum_keyword(field_schema)
    if keyword is None:
        return []
    allowed = _config_enum_allowed(keyword, field_schema)
    if not allowed:
        return []

    setting = keyword.rsplit(".", 1)[-1]
    issues: list[ValidationIssue] = []
    for item in value if isinstance(value, list) else [value]:
        if not isinstance(item, str) or item in allowed:
            continue
        issues.append(
            ValidationIssue(
                code="config_enum_unknown",
                severity="error",
                object_uuid=object_uuid,
                object_type=object_type,
                field_path=field_path,
                message=(
                    f"Value {item!r} is not a configured {setting} value. "
                    f"Declare it in the [[{setting}]] block of your deployment "
                    f"configuration, or use one of: {', '.join(allowed)}"
                ),
                context={"setting": setting, "value": item, "allowed": allowed},
            )
        )
    return issues


def _validate_vocab_value(
    value: Any,
    field_schema: dict[str, Any],
    graph: PreflightGraph,
    *,
    field_path: tuple[str, ...],
    object_uuid: str,
    object_type: str,
) -> list[ValidationIssue]:
    if value is None:
        return []
    vocab = field_schema.get("tide.vocab")
    if vocab is True:
        vocab = _leaf_field_name(field_path) or "unknown"
    if isinstance(vocab, list):
        vocab = vocab[0]
    if not isinstance(vocab, str):
        return []

    # Versioned contracts (``field::M.m``) are passed through to the enum resolver.

    scoped = bool(field_schema.get("tide.vocab.scoped"))
    stages = field_schema.get("tide.vocab.stages")
    no_wrap = bool(field_schema.get("tide.vocab.hints.no-wrap"))

    issues: list[ValidationIssue] = []
    values = value if isinstance(value, list) else [value]
    for item in values:
        if not isinstance(item, str):
            continue
        if graph.enum_resolver.is_valid(item, vocab, stages=stages, scoped=scoped, no_wrap=no_wrap):
            continue
        suggestion = graph.enum_resolver.suggest(
            item, vocab, stages=stages, scoped=scoped, no_wrap=no_wrap
        )
        issues.append(
            ValidationIssue(
                code="vocab_unknown",
                severity="error",
                object_uuid=object_uuid,
                object_type=object_type,
                field_path=field_path,
                message=f"Value {item!r} is not a valid {vocab!r} vocabulary entry",
                suggestion=suggestion,
                context={"vocab": vocab, "value": item},
            )
        )
    return issues


def validate_object_vocab_from_metaschema(
    payload: dict[str, Any],
    metaschemas: dict[str, Any],
    object_type: str,
    graph: PreflightGraph,
    *,
    object_uuid: str = "",
) -> list[ValidationIssue]:
    schema = resolve_metaschema(metaschemas, payload, object_type)
    if not schema:
        return []
    return walk_vocab_fields(
        payload,
        schema,
        graph,
        object_uuid=object_uuid,
        object_type=object_type,
    )
