"""Generation package — Pydantic-backed schema and template emission.

``generate_schemas`` / ``generate_templates`` resolve lazily so importing a
sibling submodule (for example ``framework``) does not run schema generation
imports or touch the detection registry.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from opentide.generation.schema import run as generate_schemas
    from opentide.generation.template import run as generate_templates

__all__ = ["generate_schemas", "generate_templates"]


def __getattr__(name: str) -> Any:
    if name == "generate_schemas":
        from opentide.generation.schema import run as generate_schemas

        globals()[name] = generate_schemas
        return generate_schemas
    if name == "generate_templates":
        from opentide.generation.template import run as generate_templates

        globals()[name] = generate_templates
        return generate_templates
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
