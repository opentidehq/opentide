"""Cross-object reference and chaining checks."""

from __future__ import annotations

from typing import Any

from opentide.validation.issues import ValidationIssue
from opentide.validation.preflight import PreflightGraph


def check_references_for_object(
    uuid: str,
    object_type: str,
    body: dict[str, Any],
    graph: PreflightGraph,
) -> list[ValidationIssue]:
    """Reference checks for a single indexed object."""
    if object_type not in ("rule", "objective", "threat"):
        return []

    issues: list[ValidationIssue] = []
    ref = graph.resolve(uuid)
    file_path = ref.file_path if ref else None

    if object_type == "rule":
        parent = body.get("detection_model")
        if parent and parent not in graph.enum_values("objective"):
            issues.append(
                ValidationIssue(
                    code="invalid_ref",
                    severity="error",
                    object_uuid=uuid,
                    object_type=object_type,
                    file_path=file_path,
                    field_path=("detection_model",),
                    message=graph.format_invalid_ref("objective", str(parent)),
                    suggestion=graph.suggest_ref("objective", str(parent)),
                )
            )
    if object_type == "objective":
        for threat_id in body.get("objective", {}).get("threats") or []:
            if threat_id not in graph.enum_values("threat"):
                issues.append(
                    ValidationIssue(
                        code="invalid_ref",
                        severity="error",
                        object_uuid=uuid,
                        object_type=object_type,
                        file_path=file_path,
                        field_path=("objective", "threats"),
                        message=graph.format_invalid_ref("threat", str(threat_id)),
                        suggestion=graph.suggest_ref("threat", str(threat_id)),
                    )
                )
    if object_type == "threat":
        chaining = body.get("threat", {}).get("chaining") or []
        for index, link in enumerate(chaining):
            if not isinstance(link, dict):
                continue
            vector = link.get("vector")
            if vector and vector not in graph.enum_values("threat"):
                issues.append(
                    ValidationIssue(
                        code="invalid_ref",
                        severity="error",
                        object_uuid=uuid,
                        object_type=object_type,
                        file_path=file_path,
                        field_path=("threat", "chaining", str(index), "vector"),
                        message=graph.format_invalid_ref("threat", str(vector)),
                        suggestion=graph.suggest_ref("threat", str(vector)),
                    )
                )
    return issues


def check_chaining_for_object(
    uuid: str,
    body: dict[str, Any],
    graph: PreflightGraph,
) -> list[ValidationIssue]:
    """Chaining relation checks for a single threat object."""
    issues: list[ValidationIssue] = []
    resolver = graph.enum_resolver
    relation_values = resolver.enum_values("chaining_relations", scoped=True)

    ref = graph.resolve(uuid)
    file_path = ref.file_path if ref else None
    chaining = body.get("threat", {}).get("chaining") or []
    for index, link in enumerate(chaining):
        if not isinstance(link, dict):
            continue
        relation = link.get("relation")
        if not relation:
            continue
        if relation not in relation_values and not resolver.is_valid(
            relation, "chaining_relations", scoped=True
        ):
            suggestion = resolver.suggest(relation, "chaining_relations", scoped=True)
            issues.append(
                ValidationIssue(
                    code="chaining_relation_unknown",
                    severity="error",
                    object_uuid=uuid,
                    object_type="threat",
                    file_path=file_path,
                    field_path=("threat", "chaining", str(index), "relation"),
                    message=f"Unknown chaining relation {relation!r}",
                    suggestion=suggestion,
                )
            )
    return issues


def check_references(
    objects_index: dict[str, dict[str, dict[str, Any]]],
    graph: PreflightGraph,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for object_type, registry in objects_index.items():
        for uuid, body in registry.items():
            issues.extend(check_references_for_object(uuid, object_type, body, graph))
    return issues


def check_chaining(
    objects_index: dict[str, dict[str, dict[str, Any]]],
    graph: PreflightGraph,
) -> list[ValidationIssue]:
    issues: list[ValidationIssue] = []
    for uuid, body in objects_index.get("threat", {}).items():
        issues.extend(check_chaining_for_object(uuid, body, graph))
    return issues
