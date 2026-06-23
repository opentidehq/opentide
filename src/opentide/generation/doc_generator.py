"""Schema documentation generator — model introspection for wiki export."""

from __future__ import annotations

from opentide.models.base import TideModel


def generate_model_doc(model: type[TideModel]) -> str:
    """Return markdown documentation for a TideModel schema identifier and fields."""
    lines = [f"# Schema `{model.schema_identifier()}`", ""]
    for name, field in model.model_fields.items():
        annotation = getattr(field.annotation, "__name__", str(field.annotation))
        lines.append(f"- **{name}**(`{annotation}`)")
    return "\n".join(lines)


def schema_doc_for_identifier(identifier: str) -> str:
    """Resolve a schema identifier to documentation text."""
    from opentide.models.objective import DetectionObjective
    from opentide.models.rule import DetectionRule
    from opentide.models.threat import ThreatVector

    mapping: dict[str, type[TideModel]] = {
        DetectionRule.schema_identifier(): DetectionRule,
        DetectionObjective.schema_identifier(): DetectionObjective,
        ThreatVector.schema_identifier(): ThreatVector,
    }
    model = mapping.get(identifier)
    if model is None:
        return f"# Unknown schema `{identifier}`"
    return generate_model_doc(model)


def export_schema_docs() -> dict[str, str]:
    """Export documentation for all core object schemas."""
    from opentide.models.objective import DetectionObjective
    from opentide.models.rule import DetectionRule
    from opentide.models.threat import ThreatVector

    models: list[type[TideModel]] = [DetectionRule, DetectionObjective, ThreatVector]
    return {model.schema_identifier(): generate_model_doc(model) for model in models}
