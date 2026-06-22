"""JSON Schema generation — TideSchemaGenerator entry point."""

from __future__ import annotations

from pydantic.json_schema import GenerateJsonSchema

from opentide.models.base import TideModel


class TideSchemaGenerator(GenerateJsonSchema):
    """Custom Pydantic JSON Schema generator preserving Tide metadata."""

    def field_title_should_be_set(self, field) -> bool:  # type: ignore[no-untyped-def]
        return True


def model_json_schema(model: type[TideModel]) -> dict:
    """Generate JSON Schema for a TideModel subclass."""
    return model.model_json_schema(schema_generator=TideSchemaGenerator)


def run() -> None:
    """Generate JSON schemas via the legacy pipeline (migration in progress)."""
    import sys

    from opentide.core.root import repository_root

    root = str(repository_root())
    if root not in sys.path:
        sys.path.append(root)
    from Engines.framework import json_schemas

    json_schemas.run()
