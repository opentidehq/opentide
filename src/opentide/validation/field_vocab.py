"""Metaschema-driven vocabulary field validation."""

from __future__ import annotations

from typing import Any, cast

from opentide.validation.deprecated_fields import resolve_metaschema
from opentide.validation.issues import ValidationIssue
from opentide.validation.preflight import PreflightGraph


def walk_vocab_fields(
    payload: dict[str, Any],
    schema: dict[str, Any],
    graph: PreflightGraph,
    *,
    object_uuid: str = "",
    object_type: str = "",
    path: tuple[str, ...] = (),
) -> list[ValidationIssue]:
    """Validate ``tide.vocab`` fields in *payload* against the live enum resolver."""
    issues: list[ValidationIssue] = []
    properties = schema.get("properties", schema)
    if not isinstance(properties, dict):
        return issues

    for field_name, field_schema in properties.items():
        if not isinstance(field_schema, dict):
            continue
        field_path = (*path, field_name)
        value = _get_nested(payload, field_path)
        vocab = field_schema.get("tide.vocab")
        if vocab is not None:
            issues.extend(
                _validate_vocab_value(
                    value,
                    field_schema,
                    graph,
                    field_path=field_path,
                    object_uuid=object_uuid,
                    object_type=object_type,
                )
            )
        nested_props = field_schema.get("properties")
        if isinstance(nested_props, dict) and isinstance(value, dict):
            issues.extend(
                walk_vocab_fields(
                    value,
                    field_schema,
                    graph,
                    object_uuid=object_uuid,
                    object_type=object_type,
                    path=field_path,
                )
            )
        items = field_schema.get("items")
        if isinstance(items, dict) and isinstance(value, list):
            item_props = items.get("properties")
            if isinstance(item_props, dict):
                for index, item in enumerate(value):
                    if isinstance(item, dict):
                        issues.extend(
                            walk_vocab_fields(
                                cast(dict[str, Any], item),
                                items,
                                graph,
                                object_uuid=object_uuid,
                                object_type=object_type,
                                path=(*field_path, str(index)),
                            )
                        )
            item_vocab = items.get("tide.vocab")
            if item_vocab is not None and isinstance(value, list):
                for index, item in enumerate(value):
                    issues.extend(
                        _validate_vocab_value(
                            item,
                            items,
                            graph,
                            field_path=(*field_path, str(index)),
                            object_uuid=object_uuid,
                            object_type=object_type,
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
        vocab = field_path[-1] if field_path else "unknown"
    if isinstance(vocab, list):
        vocab = vocab[0]
    if not isinstance(vocab, str):
        return []

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


def _get_nested(data: dict[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = data
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node
