"""Generation package — Pydantic-backed schema and template emission."""

from opentide.generation.schema import run as generate_schemas
from opentide.generation.template import run as generate_templates

__all__ = ["generate_schemas", "generate_templates"]
