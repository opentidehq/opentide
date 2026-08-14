"""Public API for OpenTide documentation rendering.

Exports are resolved lazily so importing ``DocumentScope`` / ``DocumentFlavor``
(for the CLI) does not build the detection registry or pull the full render stack.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
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

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "DocumentationContext": ("opentide.documentation.context", "DocumentationContext"),
    "DocumentFlavor": ("opentide.documentation.types", "DocumentFlavor"),
    "EnrichedEntry": ("opentide.documentation.vocabulary", "EnrichedEntry"),
    "chaining_relation_label": ("opentide.documentation.vocabulary", "chaining_relation_label"),
    "enrich": ("opentide.documentation.vocabulary", "enrich"),
    "enrich_technique": ("opentide.documentation.vocabulary", "enrich_technique"),
    "render_objective": ("opentide.documentation.api", "render_objective"),
    "render_rule": ("opentide.documentation.api", "render_rule"),
    "render_threat": ("opentide.documentation.api", "render_threat"),
    "run": ("opentide.documentation.cli", "run"),
    "write_all": ("opentide.documentation.api", "write_all"),
    "write_objectives": ("opentide.documentation.api", "write_objectives"),
    "write_rules": ("opentide.documentation.api", "write_rules"),
    "write_threats": ("opentide.documentation.api", "write_threats"),
}


def __getattr__(name: str) -> Any:
    try:
        module_name, attr = _LAZY_EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    module = __import__(module_name, fromlist=[attr])
    value = getattr(module, attr)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
