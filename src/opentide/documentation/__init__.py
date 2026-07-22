"""Public API for OpenTide documentation rendering."""

from opentide.documentation.api import (
    render_objective,
    render_rule,
    render_threat,
    write_all,
    write_objectives,
    write_rules,
    write_threats,
)
from opentide.documentation.cli import run
from opentide.documentation.context import DocumentationContext
from opentide.documentation.types import DocumentFlavor
from opentide.documentation.vocabulary import (
    EnrichedEntry,
    chaining_relation_label,
    enrich,
    enrich_technique,
)

__all__ = [
    "DocumentationContext",
    "DocumentFlavor",
    "EnrichedEntry",
    "chaining_relation_label",
    "enrich",
    "enrich_technique",
    "render_objective",
    "render_rule",
    "render_threat",
    "run",
    "write_all",
    "write_objectives",
    "write_rules",
    "write_threats",
]
